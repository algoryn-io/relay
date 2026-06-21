package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"algoryn.io/relay/internal/config"
)

// TestWeightedRandomDistribution verifies that traffic is split roughly in
// proportion to the configured weights. We use a 9:1 split over 1000 requests
// and allow a 5% tolerance.
func TestWeightedRandomDistribution(t *testing.T) {
	t.Parallel()

	counts := map[string]int{}
	handlers := map[string]*httptest.Server{}

	for _, name := range []string{"heavy", "light"} {
		n := name
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = n // capture
		}))
		defer srv.Close()
		handlers[name] = srv
	}

	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"b": {
				Name:     "b",
				Strategy: "weighted_random",
				Instances: []config.InstanceRuntime{
					{URL: handlers["heavy"].URL, Weight: 9},
					{URL: handlers["light"].URL, Weight: 1},
				},
			},
		},
		Routes: map[string]config.RouteRuntime{
			"r": {Name: "r", BackendName: "b"},
		},
	}

	p, err := New(rt, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer p.Close()

	heavyURL := handlers["heavy"].URL
	lightURL := handlers["light"].URL

	const total = 1000
	for i := 0; i < total; i++ {
		selected, selErr := p.selectInstance("b", "weighted_random")
		if selErr != nil {
			t.Fatalf("selectInstance() error = %v", selErr)
		}
		if selected.URL.String() == heavyURL {
			counts["heavy"]++
		} else if selected.URL.String() == lightURL {
			counts["light"]++
		}
		p.releaseInstance("b", selected)
	}

	heavyRatio := float64(counts["heavy"]) / total
	// Expected ~0.90; allow ±5% tolerance.
	if heavyRatio < 0.85 || heavyRatio > 0.95 {
		t.Errorf("heavy instance ratio = %.2f, want 0.85–0.95 (counts: heavy=%d light=%d)",
			heavyRatio, counts["heavy"], counts["light"])
	}
}

// TestWeightDefaultsToOne ensures instances without an explicit weight
// are treated equally (weight=1 each).
func TestWeightDefaultsToOne(t *testing.T) {
	t.Parallel()

	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv1.Close()
	defer srv2.Close()

	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"b": {
				Name:     "b",
				Strategy: "weighted_random",
				// Weight=0 in config → normalised to 1 each.
				Instances: []config.InstanceRuntime{
					{URL: srv1.URL, Weight: 0},
					{URL: srv2.URL, Weight: 0},
				},
			},
		},
		Routes: map[string]config.RouteRuntime{"r": {Name: "r", BackendName: "b"}},
	}
	p, err := New(rt, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer p.Close()

	counts := map[string]int{}
	const total = 500
	for i := 0; i < total; i++ {
		s, err := p.selectInstance("b", "weighted_random")
		if err != nil {
			t.Fatalf("selectInstance: %v", err)
		}
		counts[s.URL.String()]++
		p.releaseInstance("b", s)
	}

	// Each instance should receive roughly half the traffic (within 10%).
	for url, c := range counts {
		ratio := float64(c) / total
		if ratio < 0.40 || ratio > 0.60 {
			t.Errorf("instance %s ratio = %.2f, want ~0.50", url, ratio)
		}
	}
}

// TestWeightedRandomExcludesUnhealthyInstances confirms that unhealthy
// instances are never selected, even when they have a high weight.
func TestWeightedRandomExcludesUnhealthyInstances(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()

	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"b": {
				Name:     "b",
				Strategy: "weighted_random",
				Instances: []config.InstanceRuntime{
					{URL: "http://127.0.0.1:1", Weight: 100}, // will be marked unhealthy
					{URL: srv.URL, Weight: 1},
				},
			},
		},
		Routes: map[string]config.RouteRuntime{"r": {Name: "r", BackendName: "b"}},
	}
	p, err := New(rt, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer p.Close()

	// Mark the high-weight instance unhealthy.
	p.mu.Lock()
	p.instances["b"][0].Healthy = false
	p.mu.Unlock()

	for i := 0; i < 50; i++ {
		s, err := p.selectInstance("b", "weighted_random")
		if err != nil {
			t.Fatalf("selectInstance: %v", err)
		}
		if s.URL.String() != srv.URL {
			t.Errorf("selected unhealthy instance %s", s.URL)
		}
		p.releaseInstance("b", s)
	}
}

// TestWeightZeroNormalisedToOne verifies that weight=0 in RuntimeConfig is
// stored as weight=1 inside the proxy's instanceState.
func TestWeightZeroNormalisedToOne(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()

	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"b": {
				Name:      "b",
				Strategy:  "weighted_random",
				Instances: []config.InstanceRuntime{{URL: srv.URL, Weight: 0}},
			},
		},
		Routes: map[string]config.RouteRuntime{"r": {Name: "r", BackendName: "b"}},
	}
	p, err := New(rt, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer p.Close()

	p.mu.RLock()
	w := p.instances["b"][0].weight
	p.mu.RUnlock()

	if w != 1 {
		t.Errorf("instanceState.weight = %d, want 1 after normalisation", w)
	}
}

// TestWeightedRandomSingleInstance ensures a single instance always wins.
func TestWeightedRandomSingleInstance(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()

	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"b": {
				Name:      "b",
				Strategy:  "weighted_random",
				Instances: []config.InstanceRuntime{{URL: srv.URL, Weight: 5}},
			},
		},
		Routes: map[string]config.RouteRuntime{"r": {Name: "r", BackendName: "b"}},
	}
	p, err := New(rt, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer p.Close()

	for i := 0; i < 20; i++ {
		s, err := p.selectInstance("b", "weighted_random")
		if err != nil {
			t.Fatalf("selectInstance: %v", err)
		}
		if s.URL.String() != srv.URL {
			t.Errorf("unexpected instance: %s", s.URL)
		}
		p.releaseInstance("b", s)
	}
}

// TestWeightedProxyEndToEnd verifies the full proxy path with weighted_random.
func TestWeightedProxyEndToEnd(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"b": {
				Name:      "b",
				Strategy:  "weighted_random",
				Instances: []config.InstanceRuntime{{URL: srv.URL, Weight: 3}},
			},
		},
		Routes: map[string]config.RouteRuntime{
			"r": {Name: "r", BackendName: "b"},
		},
	}
	p, err := New(rt, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer p.Close()

	route := rt.Routes["r"]
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req, &route)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}
