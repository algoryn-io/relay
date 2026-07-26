package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"algoryn.io/relay/internal/config"
)

func (p *Proxy) healthLoop(backendName string, health config.HealthCheckConfig) {
	defer p.healthWG.Done()
	// Health probes must use the same base transport as normal upstream traffic.
	// In particular, this preserves custom roots and client certificates for
	// backends protected with TLS or mTLS. Do not use transportFor here: health
	// checks must still run while a circuit is open so a recovered backend can
	// become selectable again.
	client := &http.Client{
		Timeout:   health.Timeout,
		Transport: p.backendTransports[backendName],
	}
	p.checkBackendHealth(client, backendName, health)

	ticker := time.NewTicker(health.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.checkBackendHealth(client, backendName, health)
		}
	}
}

func (p *Proxy) checkBackendHealth(client *http.Client, backendName string, health config.HealthCheckConfig) {
	p.mu.RLock()
	states := append([]*instanceState(nil), p.instances[backendName]...)
	p.mu.RUnlock()

	for _, state := range states {
		if state == nil || state.URL == nil {
			p.updateInstanceHealth(backendName, state, false)
			continue
		}

		target := state.URL.ResolveReference(&url.URL{Path: health.Path})
		// Tie the probe to the proxy context so it aborts promptly on shutdown
		// instead of blocking Close for the full health timeout.
		method := strings.ToUpper(strings.TrimSpace(health.Method))
		if method == "" {
			method = http.MethodGet
		}
		req, err := http.NewRequestWithContext(p.ctx, method, target.String(), nil)
		if err != nil {
			p.updateInstanceHealth(backendName, state, false)
			p.recordOutlierOutcome(backendName, state, true, true)
			continue
		}
		for name, value := range health.Headers {
			req.Header.Set(name, value)
		}

		resp, err := client.Do(req)
		healthy := err == nil && expectedHealthStatus(resp.StatusCode, health.ExpectedStatus)
		if resp != nil && resp.Body != nil {
			if healthy && hasBodyMatcher(health.Body) {
				maxBytes := health.MaxBodyBytes
				if maxBytes <= 0 {
					maxBytes = 64 << 10
				}
				limited := &io.LimitedReader{R: resp.Body, N: maxBytes + 1}
				body, readErr := io.ReadAll(limited)
				healthy = readErr == nil && limited.N > 0 && matchHealthBody(body, health.Body)
			} else {
				// Drain before closing so the keep-alive connection can be reused.
				_, _ = io.Copy(io.Discard, resp.Body)
			}
			_ = resp.Body.Close()
		}

		p.updateInstanceHealth(backendName, state, healthy)
		p.recordOutlierOutcome(backendName, state, !healthy, true)
	}
}

func (p *Proxy) updateInstanceHealth(backendName string, target *instanceState, healthy bool) {
	p.mu.Lock()
	var instanceURL string
	for _, state := range p.instances[backendName] {
		if state == target {
			state.Healthy = healthy
			state.LastChecked = p.clock.Now()
			if state.URL != nil {
				instanceURL = state.URL.String()
			}
			break
		}
	}
	notifier := p.healthNotifier
	p.mu.Unlock()

	if instanceURL != "" && notifier != nil {
		notifier.NotifyBackendHealth(backendName, instanceURL, healthy)
	}
}

func expectedHealthStatus(status int, expected config.ExpectedStatusConfig) bool {
	switch {
	case expected.Exact != 0:
		return status == expected.Exact
	case len(expected.Range) == 2:
		return status >= expected.Range[0] && status <= expected.Range[1]
	case len(expected.List) > 0:
		for _, candidate := range expected.List {
			if status == candidate {
				return true
			}
		}
		return false
	default:
		return status >= 200 && status < 300
	}
}

func hasBodyMatcher(m config.BodyMatcherConfig) bool {
	return m.Exact != "" || m.Contains != "" || m.Regex != ""
}

func matchHealthBody(body []byte, matcher config.BodyMatcherConfig) bool {
	switch {
	case matcher.Exact != "":
		return bytes.Equal(body, []byte(matcher.Exact))
	case matcher.Contains != "":
		return bytes.Contains(body, []byte(matcher.Contains))
	case matcher.Regex != "":
		re, err := regexp.Compile(matcher.Regex)
		return err == nil && re.Match(body)
	default:
		return true
	}
}
