package proxy

import (
	"log/slog"
	"sync"
	"time"

	"algoryn.io/relay/internal/config"
)

type clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type outlierOutcome struct {
	at      time.Time
	failure bool
}

// outlierState is owned by one instance and has its own lock, keeping passive
// accounting off the proxy-wide load-balancer lock.
type outlierState struct {
	mu           sync.Mutex
	cfg          config.OutlierDetectionConfig
	outcomes     []outlierOutcome
	consecutive  int
	ejectedUntil time.Time
	ejections    int
	reason       string
}

func newOutlierState(cfg config.OutlierDetectionConfig) *outlierState {
	if cfg.Window <= 0 {
		cfg.Window = 30 * time.Second
	}
	if cfg.BaseEjectionDuration <= 0 {
		cfg.BaseEjectionDuration = 30 * time.Second
	}
	if cfg.MaxEjectionDuration <= 0 {
		cfg.MaxEjectionDuration = 5 * time.Minute
	}
	if cfg.MaxEjectionPercent == 0 {
		cfg.MaxEjectionPercent = 100
	}
	return &outlierState{cfg: cfg}
}

func outlierEnabled(cfg config.OutlierDetectionConfig) bool {
	return cfg.ConsecutiveFailures > 0 || cfg.FailureRatePercent > 0
}

func newInstanceOutlier(cfg config.OutlierDetectionConfig) *outlierState {
	if !outlierEnabled(cfg) {
		return nil
	}
	return newOutlierState(cfg)
}

// record adds one upstream outcome and returns a bounded trigger reason.
func (s *outlierState) record(now time.Time, failure bool) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := now.Add(-s.cfg.Window)
	first := 0
	for first < len(s.outcomes) && s.outcomes[first].at.Before(cutoff) {
		first++
	}
	if first > 0 {
		copy(s.outcomes, s.outcomes[first:])
		s.outcomes = s.outcomes[:len(s.outcomes)-first]
	}
	s.outcomes = append(s.outcomes, outlierOutcome{at: now, failure: failure})
	if failure {
		s.consecutive++
	} else {
		s.consecutive = 0
		return ""
	}
	if !s.ejectedUntil.IsZero() && now.Before(s.ejectedUntil) {
		return ""
	}
	if s.cfg.ConsecutiveFailures > 0 && s.consecutive >= s.cfg.ConsecutiveFailures {
		return "consecutive_failures"
	}
	if s.cfg.FailureRatePercent > 0 && len(s.outcomes) >= s.cfg.MinimumVolume {
		failures := 0
		for _, outcome := range s.outcomes {
			if outcome.failure {
				failures++
			}
		}
		if float64(failures)*100/float64(len(s.outcomes)) >= s.cfg.FailureRatePercent {
			return "failure_rate"
		}
	}
	return ""
}

func (s *outlierState) eject(now time.Time, reason string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	duration := s.cfg.BaseEjectionDuration
	for i := 0; i < s.ejections && duration < s.cfg.MaxEjectionDuration; i++ {
		if duration > s.cfg.MaxEjectionDuration/2 {
			duration = s.cfg.MaxEjectionDuration
			break
		}
		duration *= 2
	}
	if duration > s.cfg.MaxEjectionDuration {
		duration = s.cfg.MaxEjectionDuration
	}
	s.ejections++
	s.reason = reason
	s.ejectedUntil = now.Add(duration)
	s.consecutive = 0
	return s.ejectedUntil
}

// ejectionStatus lazily expires an ejection. recovered is true exactly once.
func (s *outlierState) ejectionStatus(now time.Time) (ejected, recovered bool) {
	if s == nil {
		return false, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ejectedUntil.IsZero() {
		return false, false
	}
	if now.Before(s.ejectedUntil) {
		return true, false
	}
	s.ejectedUntil = time.Time{}
	s.reason = ""
	s.outcomes = nil
	s.consecutive = 0
	return false, true
}

func (s *outlierState) recover() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ejectedUntil.IsZero() {
		return false
	}
	s.ejectedUntil = time.Time{}
	s.reason = ""
	s.outcomes = nil
	s.consecutive = 0
	return true
}

func (s *outlierState) snapshot(now time.Time) (bool, time.Time, string, int) {
	if s == nil {
		return false, time.Time{}, "", 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ejectedUntil.IsZero() || !now.Before(s.ejectedUntil) {
		return false, time.Time{}, "", s.ejections
	}
	return true, s.ejectedUntil, s.reason, s.ejections
}

func (p *Proxy) recordOutlierOutcome(backend string, state *instanceState, failure bool, active bool) {
	if state == nil || state.outlier == nil {
		return
	}
	now := p.clock.Now()
	if !failure && active && state.outlier.cfg.SuccessRecovery && state.outlier.recover() {
		p.emitOutlierRecovery(backend, state, "active_success")
	}
	reason := state.outlier.record(now, failure)
	if reason == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	ejected, _, _, _ := state.outlier.snapshot(now)
	if ejected {
		return
	}
	states := p.instances[backend]
	limitPercent := state.outlier.cfg.MaxEjectionPercent
	limit := len(states) * limitPercent / 100
	ejectedCount := 0
	for _, candidate := range states {
		if candidate == nil || candidate.outlier == nil {
			continue
		}
		if active, _, _, _ := candidate.outlier.snapshot(now); active {
			ejectedCount++
		}
	}
	if limit == 0 || ejectedCount >= limit {
		return
	}
	until := state.outlier.eject(now, reason)
	instance := instanceURL(state)
	p.metricsSink().RecordOutlierEjection(backend, instance, reason)
	p.metricsSink().SetOutlierEjected(backend, instance, true)
	logOutlier(p.logger, "upstream instance ejected", backend, instance, reason, until)
}

func (p *Proxy) emitOutlierRecovery(backend string, state *instanceState, reason string) {
	instance := instanceURL(state)
	p.metricsSink().RecordOutlierRecovery(backend, instance, reason)
	p.metricsSink().SetOutlierEjected(backend, instance, false)
	logOutlier(p.logger, "upstream instance recovered", backend, instance, reason, time.Time{})
}

func instanceURL(state *instanceState) string {
	if state == nil || state.URL == nil {
		return ""
	}
	return state.URL.String()
}

func logOutlier(logger *slog.Logger, message, backend, instance, reason string, until time.Time) {
	if logger == nil {
		return
	}
	args := []any{"backend", backend, "instance", instance, "reason", reason}
	if !until.IsZero() {
		args = append(args, "ejected_until", until)
	}
	logger.Warn(message, args...)
}
