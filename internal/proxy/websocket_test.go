package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"algoryn.io/relay/internal/config"
)

// ── isWebSocketUpgrade ────────────────────────────────────────────────────────

func TestIsWebSocketUpgradeTrue(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	if !isWebSocketUpgrade(r) {
		t.Error("expected true for canonical WebSocket headers")
	}
}

func TestIsWebSocketUpgradeCaseInsensitive(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Upgrade", "WebSocket")
	r.Header.Set("Connection", "keep-alive, Upgrade")
	if !isWebSocketUpgrade(r) {
		t.Error("expected true for mixed-case WebSocket headers")
	}
}

func TestIsWebSocketUpgradeFalseNoUpgrade(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if isWebSocketUpgrade(r) {
		t.Error("expected false for plain HTTP request")
	}
}

func TestIsWebSocketUpgradeFalseMissingConnection(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Upgrade", "websocket")
	// No Connection: Upgrade
	if isWebSocketUpgrade(r) {
		t.Error("expected false when Connection: Upgrade is absent")
	}
}

func TestIsWebSocketUpgradeFalseOtherProtocol(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Upgrade", "h2c")
	r.Header.Set("Connection", "Upgrade")
	if isWebSocketUpgrade(r) {
		t.Error("expected false for non-websocket upgrade")
	}
}

// ── integration: WebSocket proxying ──────────────────────────────────────────

// wsBackend returns an httptest.Server whose handler completes a minimal
// WebSocket handshake (sends 101) and then echoes the first raw message back.
func wsBackend(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("backend ResponseWriter does not implement http.Hijacker")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()

		// Minimal 101 handshake — real servers would compute Sec-WebSocket-Accept.
		_, _ = fmt.Fprint(bufrw,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"\r\n",
		)
		_ = bufrw.Flush()

		// Echo one message so the test can verify bidirectional I/O.
		msg := make([]byte, 32)
		n, _ := bufrw.Read(msg)
		_, _ = conn.Write(msg[:n])
	}))
}

// proxyServer wraps the proxy in an httptest.Server so we can dial it directly.
func proxyServer(t *testing.T, backendURL string) *httptest.Server {
	t.Helper()
	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"ws": {
				Name:      "ws",
				Strategy:  "round_robin",
				Instances: []config.InstanceRuntime{{URL: backendURL}},
			},
		},
		Routes: map[string]config.RouteRuntime{
			"ws": {Name: "ws", BackendName: "ws"},
		},
	}
	p, err := New(rt, nil)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	route := rt.Routes["ws"]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(w, r, &route)
	}))
	t.Cleanup(func() {
		srv.Close()
		p.Close()
	})
	return srv
}

// dialProxy dials the proxy server and sends a raw WebSocket upgrade request.
// Returns the raw connection and a buffered reader for reading the response.
func dialProxy(t *testing.T, proxyURL string) (net.Conn, *bufio.Reader) {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	req := "GET /ws HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := fmt.Fprint(conn, req); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}
	return conn, bufio.NewReader(conn)
}

func TestWebSocketUpgradeReturns101(t *testing.T) {
	backend := wsBackend(t)
	defer backend.Close()

	proxy := proxyServer(t, backend.URL)

	conn, br := dialProxy(t, proxy.URL)
	_ = conn

	// Read the status line from the proxy response.
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(statusLine), "HTTP/1.1 101") {
		t.Errorf("expected 101 Switching Protocols, got: %q", statusLine)
	}
}

func TestWebSocketBidirectionalEcho(t *testing.T) {
	backend := wsBackend(t)
	defer backend.Close()

	proxy := proxyServer(t, backend.URL)

	conn, br := dialProxy(t, proxy.URL)

	// Drain the 101 response headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read response header: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// Send a raw message and expect it echoed back.
	msg := "hello relay"
	if _, err := fmt.Fprint(conn, msg); err != nil {
		t.Fatalf("write message: %v", err)
	}
	buf := make([]byte, len(msg))
	n, err := br.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if got := string(buf[:n]); got != msg {
		t.Errorf("echo = %q, want %q", got, msg)
	}
}

func TestRegularRequestStillWorksAfterWebSocketDetection(t *testing.T) {
	t.Parallel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"b": {Name: "b", Strategy: "round_robin", Instances: []config.InstanceRuntime{{URL: backend.URL}}},
		},
		Routes: map[string]config.RouteRuntime{
			"r": {Name: "r", BackendName: "b"},
		},
	}
	p, err := New(rt, nil)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	route := rt.Routes["r"]
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req, &route)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}
