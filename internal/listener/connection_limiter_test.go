package listener

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/observability"
)

func TestConnectionLimiterLifecycle(t *testing.T) {
	t.Parallel()

	limiter := newConnectionLimiter(1)
	first := newFakeConn("192.0.2.10:1001")
	second := newFakeConn("192.0.2.10:1002")

	limiter.connState(first, http.StateNew)
	limiter.connState(second, http.StateNew)
	if second.closed.Load() != 1 {
		t.Fatal("connection above limit was not closed")
	}
	assertLimiterSize(t, limiter, 1, 1)

	limiter.connState(first, http.StateHijacked)
	// A duplicate terminal notification must not decrement twice.
	limiter.connState(first, http.StateClosed)
	assertLimiterSize(t, limiter, 0, 0)

	replacement := newFakeConn("192.0.2.10:1003")
	limiter.connState(replacement, http.StateNew)
	if replacement.closed.Load() != 0 {
		t.Fatal("connection was rejected after the previous slot was released")
	}
	limiter.connState(replacement, http.StateClosed)
	assertLimiterSize(t, limiter, 0, 0)
}

func TestConnectionLimiterSeparatesRealPeerIPs(t *testing.T) {
	t.Parallel()

	limiter := newConnectionLimiter(1)
	first := newFakeConn("192.0.2.10:1001")
	second := newFakeConn("198.51.100.20:1002")

	limiter.connState(first, http.StateNew)
	limiter.connState(second, http.StateNew)

	if first.closed.Load() != 0 || second.closed.Load() != 0 {
		t.Fatal("different TCP peers incorrectly shared a limit")
	}
	assertLimiterSize(t, limiter, 2, 2)
}

func TestConnectionLimiterConcurrentLifecycleIsBounded(t *testing.T) {
	t.Parallel()

	const (
		limit = 16
		total = 256
	)
	limiter := newConnectionLimiter(limit)
	conns := make([]*fakeConn, total)

	var wg sync.WaitGroup
	for i := range conns {
		conns[i] = newFakeConn("203.0.113.9:4321")
		wg.Add(1)
		go func(conn *fakeConn) {
			defer wg.Done()
			limiter.connState(conn, http.StateNew)
		}(conns[i])
	}
	wg.Wait()

	assertLimiterSize(t, limiter, limit, 1)

	for _, conn := range conns {
		wg.Add(1)
		go func(conn *fakeConn) {
			defer wg.Done()
			limiter.connState(conn, http.StateClosed)
		}(conn)
	}
	wg.Wait()

	assertLimiterSize(t, limiter, 0, 0)
}

func TestConnectionLimiterReloadAndMetrics(t *testing.T) {
	t.Parallel()

	limiter := newConnectionLimiter(0)
	collector := observability.NewPrometheusCollector()
	limiter.setMetrics(collector)

	first := newFakeConn("192.0.2.44:1001")
	limiter.connState(first, http.StateNew)
	limiter.setLimit(1)

	rejected := newFakeConn("192.0.2.44:1002")
	limiter.connState(rejected, http.StateNew)
	if rejected.closed.Load() != 1 {
		t.Fatal("reloaded limit did not apply to a new connection")
	}

	rec := httptest.NewRecorder()
	collector.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		"relay_listener_connections_active 1",
		"relay_listener_peer_ips_active 1",
		"relay_listener_connections_rejected_total 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
}

func TestServerReloadUpdatesPerIPConnectionLimit(t *testing.T) {
	t.Parallel()

	cfg := testServerConfig(config.ListenerConfig{
		HTTP: config.HTTPConfig{Port: 8080},
		Timeouts: config.TimeoutsConfig{
			Read:  time.Second,
			Write: time.Second,
			Idle:  time.Second,
		},
	})
	rt := &config.RuntimeConfig{
		Routes:   map[string]config.RouteRuntime{},
		Backends: map[string]config.BackendRuntime{},
	}
	server, err := New(cfg, rt, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { server.state.Load().close() })

	first := newFakeConn("192.0.2.55:1001")
	server.connectionLimiter.connState(first, http.StateNew)

	reloaded := *cfg
	reloaded.Listener.MaxConnectionsPerIP = 1
	if err := server.Reload(&reloaded, rt); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	second := newFakeConn("192.0.2.55:1002")
	server.connectionLimiter.connState(second, http.StateNew)
	if second.closed.Load() != 1 {
		t.Fatal("server reload did not apply the per-IP connection limit")
	}
	server.connectionLimiter.connState(first, http.StateClosed)
}

func assertLimiterSize(t *testing.T, limiter *connectionLimiter, connections, ips int) {
	t.Helper()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if got := len(limiter.connections); got != connections {
		t.Fatalf("tracked connections = %d, want %d", got, connections)
	}
	if got := len(limiter.byIP); got != ips {
		t.Fatalf("tracked IPs = %d, want %d", got, ips)
	}
}

type fakeConn struct {
	remote net.Addr
	closed atomic.Int32
}

func newFakeConn(remote string) *fakeConn {
	addr, err := net.ResolveTCPAddr("tcp", remote)
	if err != nil {
		panic(err)
	}
	return &fakeConn{remote: addr}
}

func (c *fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *fakeConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fakeConn) Close() error                     { c.closed.Add(1); return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr             { return c.remote }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }
