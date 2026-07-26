package observability

import (
	"log/slog"
	"sync"
	"time"

	fabricv1 "algoryn.io/fabric/gen/go/fabric/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	EventCodeConfigReloadFailed     = "relay.config_reload.failed"
	EventCodeConfigReloadSucceeded  = "relay.config_reload.succeeded"
	EventCodeRedisDegraded          = "relay.rate_limit.redis.degraded"
	EventCodeRedisUnavailable       = "relay.rate_limit.redis.unavailable"
	EventCodeRedisRecovered         = "relay.rate_limit.redis.recovered"
	EventCodeFailOpenBypass         = "relay.rate_limit.fail_open_bypass"
	EventCodeMemoryEvictionPressure = "relay.rate_limit.memory_eviction_pressure"
)

// OperationalEvents emits bounded, non-sensitive process events. Counters are
// updated for every occurrence, while logs and Fabric events are transition-only.
type OperationalEvents struct {
	mu                sync.Mutex
	logger            *slog.Logger
	metrics           *PrometheusCollector
	dispatcher        *EventDispatcher
	service           string
	states            map[string]string
	redisStates       map[string]string
	redisSources      map[string]struct{}
	sourcesConfigured bool
}

func NewOperationalEvents(logger *slog.Logger, metrics *PrometheusCollector) *OperationalEvents {
	if logger == nil {
		logger = slog.Default()
	}
	return &OperationalEvents{
		logger:       logger,
		metrics:      metrics,
		service:      "relay",
		states:       make(map[string]string),
		redisStates:  make(map[string]string),
		redisSources: make(map[string]struct{}),
	}
}

// SetFabric updates the hot-reloadable Fabric destination.
func (o *OperationalEvents) SetFabric(dispatcher *EventDispatcher, service string) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.dispatcher = dispatcher
	if service != "" {
		o.service = service
	}
}

func (o *OperationalEvents) RecordConfigReload(result, stage string) {
	if o == nil {
		return
	}
	if o.metrics != nil {
		o.metrics.RecordConfigReload(result, stage)
	}
	if result == "success" {
		o.transition("config_reload", "healthy", EventCodeConfigReloadSucceeded, "info", stage)
		return
	}
	o.transition("config_reload", "failed", EventCodeConfigReloadFailed, "error", stage)
}

// RecordRateLimitRedisResult counts every Redis check and emits only outage and
// recovery transitions. failOpen selects degraded versus unavailable semantics.
func (o *OperationalEvents) RecordRateLimitRedisResult(source string, success, failOpen bool) {
	if o == nil {
		return
	}
	if o.metrics != nil {
		o.metrics.RecordRateLimitRedisCheck(success)
	}
	if source == "" {
		source = "default"
	}
	state := "healthy"
	if !success && failOpen {
		state = "degraded"
	} else if !success {
		state = "unavailable"
	}
	o.mu.Lock()
	if o.sourcesConfigured {
		if _, active := o.redisSources[source]; !active {
			o.mu.Unlock()
			return
		}
	}
	o.redisStates[source] = state
	aggregate := aggregateRedisState(o.redisStates)
	if aggregate == "healthy" {
		o.states["rate_limit_fail_open"] = "healthy"
	}
	o.mu.Unlock()
	if o.metrics != nil {
		o.metrics.SetRateLimitRedisAvailable(aggregate == "healthy")
		o.metrics.SetRateLimitRedisState(aggregate)
	}
	switch aggregate {
	case "degraded":
		o.transition("rate_limit_redis", "degraded", EventCodeRedisDegraded, "warn", "")
	case "unavailable":
		o.transition("rate_limit_redis", "unavailable", EventCodeRedisUnavailable, "error", "")
	default:
		o.mu.Lock()
		previous := o.states["rate_limit_redis"]
		if previous == "" {
			o.states["rate_limit_redis"] = "healthy"
		}
		o.mu.Unlock()
		if previous == "degraded" || previous == "unavailable" {
			o.transition("rate_limit_redis", "healthy", EventCodeRedisRecovered, "info", "")
		}
	}
}

// ConfigureRateLimitRedisSources removes state for middleware no longer present
// after a hot reload. Source names remain process-local and are never emitted.
func (o *OperationalEvents) ConfigureRateLimitRedisSources(sources []string) {
	if o == nil {
		return
	}
	keep := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		keep[source] = struct{}{}
	}
	o.mu.Lock()
	o.sourcesConfigured = true
	o.redisSources = keep
	for source := range o.redisStates {
		if _, ok := keep[source]; !ok {
			delete(o.redisStates, source)
		}
	}
	aggregate := aggregateRedisState(o.redisStates)
	previous := o.states["rate_limit_redis"]
	o.mu.Unlock()
	if o.metrics != nil {
		o.metrics.SetRateLimitRedisAvailable(aggregate == "healthy")
		o.metrics.SetRateLimitRedisState(aggregate)
	}
	if aggregate == "healthy" && (previous == "degraded" || previous == "unavailable") {
		o.transition("rate_limit_redis", "healthy", EventCodeRedisRecovered, "info", "")
	}
}

func (o *OperationalEvents) RecordRateLimitFailOpenBypass() {
	if o == nil {
		return
	}
	if o.metrics != nil {
		o.metrics.RecordRateLimitFailOpenBypass()
	}
	o.transition("rate_limit_fail_open", "bypassing", EventCodeFailOpenBypass, "warn", "")
}

func (o *OperationalEvents) AddRateLimitMemoryBuckets(delta int) {
	if o != nil && o.metrics != nil {
		o.metrics.AddRateLimitMemoryBuckets(delta)
	}
}

func (o *OperationalEvents) RecordRateLimitMemoryEviction() {
	if o == nil {
		return
	}
	if o.metrics != nil {
		o.metrics.RecordRateLimitMemoryEviction()
	}
	o.transition("rate_limit_memory", "pressure", EventCodeMemoryEvictionPressure, "warn", "")
}

func (o *OperationalEvents) transition(component, state, code, level, stage string) {
	o.mu.Lock()
	if o.states[component] == state {
		o.mu.Unlock()
		return
	}
	o.states[component] = state
	dispatcher := o.dispatcher
	service := o.service
	o.mu.Unlock()

	if o.metrics != nil {
		o.metrics.RecordOperationalEvent(code)
	}
	attrs := []any{"event_type", "operational", "event_code", code, "component", component, "state", state}
	if stage != "" {
		attrs = append(attrs, "stage", stage)
	}
	switch level {
	case "error":
		o.logger.Error("operational event", attrs...)
	case "warn":
		o.logger.Warn("operational event", attrs...)
	default:
		o.logger.Info("operational event", attrs...)
	}
	if dispatcher != nil {
		dispatcher.TryEnqueue(FabricDispatchItem{Event: BuildOperationalFabricEvent(service, code, state)})
	}
}

// BuildOperationalFabricEvent maps operational transitions to Fabric's stable
// threshold envelope. Only bounded codes and state are included.
func BuildOperationalFabricEvent(service, code, state string) *fabricv1.Event {
	if service == "" {
		service = "relay"
	}
	now := timestamppb.Now()
	return &fabricv1.Event{
		Id:        "relay-op-" + code + "-" + time.Now().UTC().Format("20060102T150405.000000000"),
		Type:      fabricv1.EventType_EVENT_TYPE_THRESHOLD_VIOLATED,
		Source:    service,
		Timestamp: now,
		Payload: &fabricv1.Event_ThresholdViolated{
			ThresholdViolated: &fabricv1.ThresholdViolatedPayload{
				Service:     service,
				Source:      "relay",
				Description: code,
				Actual:      operationalStateValue(state),
				Limit:       0,
			},
		},
	}
}

func operationalStateValue(state string) float64 {
	if state == "healthy" {
		return 0
	}
	return 1
}

func aggregateRedisState(states map[string]string) string {
	aggregate := "healthy"
	for _, state := range states {
		if state == "unavailable" {
			return state
		}
		if state == "degraded" {
			aggregate = state
		}
	}
	return aggregate
}
