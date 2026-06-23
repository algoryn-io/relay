package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
)

// isWebSocketUpgrade reports whether r is a WebSocket upgrade request.
// Both the Upgrade and Connection headers must be present and correct.
func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	// Connection header may contain multiple tokens; check for "upgrade".
	for _, v := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}

// serveWebSocket handles an HTTP upgrade request (WebSocket or other protocols).
// It bypasses the retry loop and responseBuffer because the underlying
// http.ResponseWriter must implement http.Hijacker for the protocol switch.
// No retry is performed: once the handshake starts, replaying is not possible.
func (p *Proxy) serveWebSocket(
	w http.ResponseWriter,
	r *http.Request,
	backend config.BackendRuntime,
	clientIP, proto, originalHost string,
) {
	selected, selErr := p.selectInstance(backend.Name, backend.Strategy)
	if selErr != nil {
		if errors.Is(selErr, errAllCircuitsOpen) {
			if p.logger != nil {
				p.logger.Warn("websocket: all circuits open", "backend", backend.Name)
			}
			httpx.WriteError(w, http.StatusServiceUnavailable, "circuit_open")
		} else {
			httpx.WriteError(w, http.StatusBadGateway, "bad_gateway")
		}
		return
	}
	defer p.releaseInstance(backend.Name, selected)

	if selected.circuit != nil && !selected.circuit.Allow() {
		if p.logger != nil {
			p.logger.Warn("websocket: circuit open",
				"backend", backend.Name,
				"instance", selected.URL.String(),
			)
		}
		httpx.WriteError(w, http.StatusServiceUnavailable, "circuit_open")
		return
	}

	target := selected.URL
	backendName := backend.Name
	transport := p.transportFor(backendName, selected.circuit)

	rp := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Header.Del("X-Internal-Auth")
			pr.Out.Header.Del("X-Real-IP")
			pr.Out.Header.Del("X-Admin")
			pr.Out.Header.Set("X-Forwarded-Host", originalHost)
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
			if clientIP != "" {
				pr.Out.Header.Set("X-Forwarded-For", clientIP)
				pr.Out.Header.Set("X-Real-IP", clientIP)
			}
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			if errors.Is(err, context.DeadlineExceeded) {
				if p.logger != nil {
					p.logger.Warn("websocket backend timeout",
						"error", err,
						"path", req.URL.Path,
						"backend", backendName,
					)
				}
				httpx.WriteError(rw, http.StatusGatewayTimeout, "gateway_timeout")
				return
			}
			if p.logger != nil {
				p.logger.Error("websocket backend error",
					"error", err,
					"path", req.URL.Path,
					"backend", backendName,
				)
			}
			httpx.WriteError(rw, http.StatusBadGateway, "bad_gateway")
		},
	}

	// Write directly to w so that http.Hijacker remains accessible for the
	// protocol switch. The ReverseProxy propagates the Upgrade/Connection
	// headers and tunnels the bidirectional stream after the 101 response.
	//
	// When a WebSocket idle timeout is configured, wrap the writer so the
	// hijacked client connection gets a read/write deadline that resets on every
	// byte. A silent (e.g. dead/NATed) client then times out instead of holding
	// the tunnel, goroutine, FD and bulkhead slot forever.
	dst := w
	if p.wsIdleTimeout > 0 {
		dst = &idleHijackWriter{ResponseWriter: w, idle: p.wsIdleTimeout}
	}
	rp.ServeHTTP(dst, r)
}

// idleHijackWriter wraps a ResponseWriter so the hijacked connection enforces an
// idle deadline. ReverseProxy hijacks the connection for the protocol switch and
// tunnels through it, so the deadline transparently bounds tunnel inactivity.
type idleHijackWriter struct {
	http.ResponseWriter
	idle time.Duration
}

func (w *idleHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	return &idleConn{Conn: conn, idle: w.idle}, brw, nil
}

// idleConn resets the connection deadline on every Read/Write so the tunnel is
// closed only after `idle` elapses with no traffic in either direction.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(b)
}
