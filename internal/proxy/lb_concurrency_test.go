package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"algoryn.io/relay/internal/config"
)

// Under concurrent load, lock-free select/release must not race and the
// per-instance in-flight counters must return to zero afterward.
func TestSelectReleaseBalancedUnderConcurrency(t *testing.T) {
	t.Parallel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"svc": {
			Name:     "svc",
			Strategy: "least_connections",
			Instances: []config.InstanceRuntime{
				{URL: backend.URL},
				{URL: backend.URL},
			},
		},
	})
	route := &config.RouteRuntime{BackendName: "svc"}

	var wg sync.WaitGroup
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := performProxyRequest(t, p, route, "GET", "/")
			resp.Body.Close()
		}()
	}
	wg.Wait()

	for _, inst := range p.instances["svc"] {
		if got := inst.activeRequests.Load(); got != 0 {
			t.Errorf("instance %v activeRequests = %d, want 0", inst.URL, got)
		}
	}
}
