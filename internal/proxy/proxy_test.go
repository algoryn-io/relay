package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestProxySuccessfulRequest(t *testing.T) {
	t.Parallel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service": "orders",
			"path":    r.URL.Path,
			"method":  r.Method,
		})
	}))
	defer backend.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"orders-backend": {
			Name:     "orders-backend",
			Strategy: "round_robin",
			Instances: []config.InstanceRuntime{
				{URL: backend.URL},
			},
		},
	})

	resp := performProxyRequest(t, p, &config.RouteRuntime{BackendName: "orders-backend"}, http.MethodGet, "/api/orders")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["service"] != "orders" {
		t.Fatalf("service = %q, want orders", body["service"])
	}
	if body["path"] != "/api/orders" {
		t.Fatalf("path = %q, want /api/orders", body["path"])
	}
	if body["method"] != http.MethodGet {
		t.Fatalf("method = %q, want %s", body["method"], http.MethodGet)
	}
}

func TestProxySetsForwardedHeaders(t *testing.T) {
	t.Parallel()

	received := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"orders-backend": {
			Name:     "orders-backend",
			Strategy: "round_robin",
			Instances: []config.InstanceRuntime{
				{URL: backend.URL},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.Host = "relay.local"
	req.RemoteAddr = "203.0.113.10:4321"
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req, &config.RouteRuntime{BackendName: "orders-backend"})

	headers := <-received
	if got := headers.Get("X-Forwarded-Host"); got != "relay.local" {
		t.Fatalf("X-Forwarded-Host = %q, want relay.local", got)
	}
	if got := headers.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("X-Forwarded-Proto = %q, want http", got)
	}
	if got := headers.Get("X-Forwarded-For"); got != "203.0.113.10" {
		t.Fatalf("X-Forwarded-For = %q, want 203.0.113.10", got)
	}
}

func TestProxyRoundRobin(t *testing.T) {
	t.Parallel()

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"instance": "first"})
	}))
	defer first.Close()

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"instance": "second"})
	}))
	defer second.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"orders-backend": {
			Name:     "orders-backend",
			Strategy: "round_robin",
			Instances: []config.InstanceRuntime{
				{URL: first.URL},
				{URL: second.URL},
			},
		},
	})

	got := make([]string, 0, 4)
	for range 4 {
		resp := performProxyRequest(t, p, &config.RouteRuntime{BackendName: "orders-backend"}, http.MethodGet, "/api/orders")
		var body map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		_ = resp.Body.Close()
		got = append(got, body["instance"])
	}

	want := []string{"first", "second", "first", "second"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("round robin sequence = %v, want %v", got, want)
		}
	}
}

func TestProxyLeastConnections(t *testing.T) {
	t.Parallel()

	slowStarted := make(chan struct{}, 1)
	releaseSlow := make(chan struct{})

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slowStarted <- struct{}{}
		<-releaseSlow
		_ = json.NewEncoder(w).Encode(map[string]string{"instance": "slow"})
	}))
	defer slow.Close()

	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"instance": "fast"})
	}))
	defer fast.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"orders-backend": {
			Name:     "orders-backend",
			Strategy: "least_connections",
			Instances: []config.InstanceRuntime{
				{URL: slow.URL},
				{URL: fast.URL},
			},
		},
	})

	var wg sync.WaitGroup
	wg.Add(1)

	firstRespCh := make(chan *http.Response, 1)
	go func() {
		defer wg.Done()
		firstRespCh <- performProxyRequest(t, p, &config.RouteRuntime{BackendName: "orders-backend"}, http.MethodGet, "/api/orders")
	}()

	<-slowStarted

	secondResp := performProxyRequest(t, p, &config.RouteRuntime{BackendName: "orders-backend"}, http.MethodGet, "/api/orders")
	defer secondResp.Body.Close()

	var secondBody map[string]string
	if err := json.NewDecoder(secondResp.Body).Decode(&secondBody); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if secondBody["instance"] != "fast" {
		t.Fatalf("least connections picked %q, want fast", secondBody["instance"])
	}

	close(releaseSlow)

	firstResp := <-firstRespCh
	defer firstResp.Body.Close()
	var firstBody map[string]string
	if err := json.NewDecoder(firstResp.Body).Decode(&firstBody); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if firstBody["instance"] != "slow" {
		t.Fatalf("first request hit %q, want slow", firstBody["instance"])
	}

	wg.Wait()
}

func TestProxySkipsUnhealthyInstance(t *testing.T) {
	t.Parallel()

	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"instance": "unhealthy"})
	}))
	defer unhealthy.Close()

	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"instance": "healthy"})
	}))
	defer healthy.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"orders-backend": {
			Name:     "orders-backend",
			Strategy: "round_robin",
			HealthCheck: config.HealthCheckConfig{
				Path:     "/health",
				Interval: 25 * time.Millisecond,
				Timeout:  100 * time.Millisecond,
			},
			Instances: []config.InstanceRuntime{
				{URL: unhealthy.URL},
				{URL: healthy.URL},
			},
		},
	})

	waitForHealthState(t, p, "orders-backend", []bool{false, true})

	resp := performProxyRequest(t, p, &config.RouteRuntime{BackendName: "orders-backend"}, http.MethodGet, "/api/orders")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["instance"] != "healthy" {
		t.Fatalf("instance = %q, want healthy", body["instance"])
	}
}

func TestProxyAllUnhealthyReturns502(t *testing.T) {
	t.Parallel()

	downA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer downA.Close()

	downB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer downB.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"orders-backend": {
			Name:     "orders-backend",
			Strategy: "round_robin",
			HealthCheck: config.HealthCheckConfig{
				Path:     "/health",
				Interval: 25 * time.Millisecond,
				Timeout:  100 * time.Millisecond,
			},
			Instances: []config.InstanceRuntime{
				{URL: downA.URL},
				{URL: downB.URL},
			},
		},
	})

	waitForHealthState(t, p, "orders-backend", []bool{false, false})

	resp := performProxyRequest(t, p, &config.RouteRuntime{BackendName: "orders-backend"}, http.MethodGet, "/api/orders")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["error"] != "bad_gateway" {
		t.Fatalf("error = %q, want bad_gateway", body["error"])
	}
	if body["status"] != "error" {
		t.Fatalf("status = %q, want error", body["status"])
	}
}

func TestProxyBackendDownReturns502(t *testing.T) {
	t.Parallel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	backendURL := backend.URL
	backend.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"orders-backend": {
			Name:     "orders-backend",
			Strategy: "round_robin",
			Instances: []config.InstanceRuntime{
				{URL: backendURL},
			},
		},
	})

	resp := performProxyRequest(t, p, &config.RouteRuntime{BackendName: "orders-backend"}, http.MethodGet, "/api/orders")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["error"] != "bad_gateway" {
		t.Fatalf("error = %q, want bad_gateway", body["error"])
	}
	if body["status"] != "error" {
		t.Fatalf("status = %q, want error", body["status"])
	}
}

func TestProxyNoInstancesReturns502(t *testing.T) {
	t.Parallel()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"orders-backend": {
			Name:     "orders-backend",
			Strategy: "round_robin",
		},
	})

	resp := performProxyRequest(t, p, &config.RouteRuntime{BackendName: "orders-backend"}, http.MethodGet, "/api/orders")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["error"] != "bad_gateway" {
		t.Fatalf("error = %q, want bad_gateway", body["error"])
	}
	if body["status"] != "error" {
		t.Fatalf("status = %q, want error", body["status"])
	}
}

func newTestProxy(t *testing.T, backends map[string]config.BackendRuntime) *Proxy {
	t.Helper()

	p, err := New(&config.RuntimeConfig{Backends: backends})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(p.Close)

	return p
}

func performProxyRequest(t *testing.T, p *Proxy, route *config.RouteRuntime, method, path string) *http.Response {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "203.0.113.10:1234"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req, route)
	return rec.Result()
}

func waitForHealthState(t *testing.T, p *Proxy, backendName string, want []bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.RLock()
		states := p.instances[backendName]
		match := len(states) == len(want)
		if match {
			for i := range want {
				if states[i].Healthy != want[i] {
					match = false
					break
				}
			}
		}
		p.mu.RUnlock()

		if match {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	t.Fatalf("health state for %s did not converge, got %#v want %v", backendName, p.instances[backendName], want)
}
