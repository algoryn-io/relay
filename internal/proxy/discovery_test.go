package proxy

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/discovery"
)

func TestDNSDiscoveryPopulatesAndUpdatesPoolAtomically(t *testing.T) {
	t.Parallel()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"node": "a"})
	}))
	defer primary.Close()
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"node": "b"})
	}))
	defer secondary.Close()

	hostA, portA := mustHostPort(t, primary.URL)
	hostB, portB := mustHostPort(t, secondary.URL)
	if portA != portB {
		// httptest picks ephemeral ports; discovery uses a single configured port,
		// so bind both servers through one listener isn't needed — use two
		// discovery configs via sequential updates with each server's own port.
		_ = hostB
	}

	fake := &discovery.FakeResolver{}
	fake.Set("orders.svc.local", "A", discovery.Result{
		TTL:       50 * time.Millisecond,
		Endpoints: []discovery.Endpoint{{Host: hostA, Weight: 1}},
	})

	p, err := NewWithResolver(&config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"orders": {
				Name:     "orders",
				Strategy: "round_robin",
				Discovery: &config.DNSDiscoveryConfig{
					Name:            "orders.svc.local",
					RecordType:      "A",
					Port:            portA,
					Scheme:          "http",
					RefreshInterval: 50 * time.Millisecond,
					TTLMin:          10 * time.Millisecond,
					Weight:          1,
				},
			},
		},
	}, nil, fake)
	if err != nil {
		t.Fatalf("NewWithResolver: %v", err)
	}
	t.Cleanup(p.Close)

	waitForInstanceURLs(t, p, "orders", []string{primary.URL})

	resp := performProxyRequest(t, p, &config.RouteRuntime{BackendName: "orders"}, http.MethodGet, "/x")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	// Swap the discovered port/host by updating runtime discovery port under lock
	// and pushing a new DNS answer. applyDiscoveredInstances reads Port from config.
	p.mu.Lock()
	p.backends["orders"].Discovery.Port = portB
	p.mu.Unlock()
	fake.Set("orders.svc.local", "A", discovery.Result{
		TTL:       50 * time.Millisecond,
		Endpoints: []discovery.Endpoint{{Host: hostB, Weight: 1}},
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.RLock()
		states := p.instances["orders"]
		ok := len(states) == 1 && states[0].URL != nil && states[0].URL.String() == secondary.URL
		p.mu.RUnlock()
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for atomic DNS pool update")
}

func TestRouteFailoverToSecondaryBackend(t *testing.T) {
	t.Parallel()

	var primaryHits, secondaryHits atomic.Int64
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondaryHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer secondary.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"primary": {
			Name:     "primary",
			Strategy: "round_robin",
			Instances: []config.InstanceRuntime{
				{URL: primary.URL, Weight: 1},
			},
		},
		"secondary": {
			Name:     "secondary",
			Strategy: "round_robin",
			Instances: []config.InstanceRuntime{
				{URL: secondary.URL, Weight: 1},
			},
		},
	})

	p.mu.Lock()
	p.instances["primary"][0].Healthy = false
	p.mu.Unlock()

	route := &config.RouteRuntime{
		Name:             "api",
		BackendName:      "primary",
		FailoverBackends: []string{"secondary"},
	}
	resp := performProxyRequest(t, p, route, http.MethodGet, "/api")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if primaryHits.Load() != 0 {
		t.Fatalf("primary hits = %d, want 0", primaryHits.Load())
	}
	if secondaryHits.Load() != 1 {
		t.Fatalf("secondary hits = %d, want 1", secondaryHits.Load())
	}
}

func TestRouteFailoverPrefersHealthyPrimary(t *testing.T) {
	t.Parallel()

	var primaryHits, secondaryHits atomic.Int64
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondaryHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer secondary.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"primary": {
			Name:     "primary",
			Strategy: "round_robin",
			Instances: []config.InstanceRuntime{
				{URL: primary.URL, Weight: 1},
			},
		},
		"secondary": {
			Name:     "secondary",
			Strategy: "round_robin",
			Instances: []config.InstanceRuntime{
				{URL: secondary.URL, Weight: 1},
			},
		},
	})

	route := &config.RouteRuntime{
		BackendName:      "primary",
		FailoverBackends: []string{"secondary"},
	}
	resp := performProxyRequest(t, p, route, http.MethodGet, "/api")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if primaryHits.Load() != 1 || secondaryHits.Load() != 0 {
		t.Fatalf("hits primary=%d secondary=%d", primaryHits.Load(), secondaryHits.Load())
	}
}

func TestDNSDiscoveryPreservesInstanceStateAcrossUpdates(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host, port := mustHostPort(t, srv.URL)

	fake := &discovery.FakeResolver{}
	fake.Set("keep.svc.local", "A", discovery.Result{
		TTL:       time.Hour,
		Endpoints: []discovery.Endpoint{{Host: host, Weight: 1}},
	})

	p, err := NewWithResolver(&config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"keep": {
				Name:     "keep",
				Strategy: "round_robin",
				Discovery: &config.DNSDiscoveryConfig{
					Name:            "keep.svc.local",
					RecordType:      "A",
					Port:            port,
					Scheme:          "http",
					RefreshInterval: time.Hour,
					TTLMin:          time.Second,
					Weight:          1,
				},
			},
		},
	}, nil, fake)
	if err != nil {
		t.Fatalf("NewWithResolver: %v", err)
	}
	t.Cleanup(p.Close)

	waitForInstanceURLs(t, p, "keep", []string{srv.URL})

	p.mu.Lock()
	original := p.instances["keep"][0]
	original.Healthy = false
	p.mu.Unlock()

	p.refreshDiscoveredBackend("keep", p.backends["keep"].Discovery)

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.instances["keep"]) != 1 || p.instances["keep"][0] != original {
		t.Fatal("expected same instanceState pointer after rediscovery")
	}
	if p.instances["keep"][0].Healthy {
		t.Fatal("preserved instance should keep unhealthy state")
	}
}

func waitForInstanceURLs(t *testing.T, p *Proxy, backend string, want []string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.RLock()
		states := p.instances[backend]
		match := len(states) == len(want)
		if match {
			for i := range want {
				if states[i] == nil || states[i].URL == nil || states[i].URL.String() != want[i] {
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
	t.Fatalf("timed out waiting for instances %v", want)
}

func mustHostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
