package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

// wsTransportFor must wrap the upstream dial in an idleConn when a WS idle
// timeout is configured, so the backend side of the tunnel also times out.
func TestWSTransportForWrapsUpstreamDial(t *testing.T) {
	t.Parallel()

	backend := newTCPEcho(t)

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"svc": {Name: "svc", Strategy: "round_robin", Instances: []config.InstanceRuntime{{URL: "http://" + backend}}},
	})
	p.SetWebSocketIdleTimeout(50 * time.Millisecond)

	rt := p.wsTransportFor("svc", nil)
	tr, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("wsTransportFor returned %T, want *http.Transport", rt)
	}
	conn, err := tr.DialContext(context.Background(), "tcp", backend)
	if err != nil {
		t.Fatalf("DialContext error = %v", err)
	}
	defer conn.Close()
	if _, ok := conn.(*idleConn); !ok {
		t.Fatalf("dialed conn is %T, want *idleConn (idle deadline not applied upstream)", conn)
	}
}

// With no WS idle timeout, wsTransportFor falls back to the plain transport.
func TestWSTransportForNoIdleFallsBack(t *testing.T) {
	t.Parallel()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"svc": {Name: "svc", Strategy: "round_robin", Instances: []config.InstanceRuntime{{URL: "http://127.0.0.1:1"}}},
	})
	// wsIdleTimeout left at 0.
	if got := p.wsTransportFor("svc", nil); got != p.backendTransports["svc"] {
		t.Fatal("expected fallback to the backend transport when no WS idle timeout")
	}
}

func newTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

// idleConn must close out a read when the peer is silent past the idle window,
// so a dead/NATed client cannot hold a tunnel open forever.
func TestIdleConnTimesOutSilentRead(t *testing.T) {
	t.Parallel()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ic := &idleConn{Conn: c1, idle: 20 * time.Millisecond}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_, err := ic.Read(buf) // no writer on c2 → must hit the idle deadline
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read returned nil error, want idle timeout")
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("err = %v, want a timeout error", err)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not time out within 1s")
	}
}
