package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"algoryn.io/relay/internal/config"
)

// newBaseTransport returns an http.Transport tuned for a gateway forwarding to
// backends under load. Go's http.DefaultTransport caps idle connections per host
// at 2, which forces a new TCP (and TLS) handshake for almost every concurrent
// request — collapsing throughput and exhausting ephemeral ports. These settings
// keep a healthy pool of reusable keep-alive connections per backend instead.
func newBaseTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// buildBackendTransport constructs a tuned *http.Transport for the given backend.
// A custom TLS config is applied only when one of the TLS fields is set; otherwise
// the transport uses system roots (for https backends) and plain HTTP as usual.
func buildBackendTransport(cfg config.BackendTLSConfig) (*http.Transport, error) {
	tr := newBaseTransport()

	if !hasTLSConfig(cfg) {
		return tr, nil
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec — user-explicit opt-in
	}

	if cfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid certificates found in CA file %q", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	tr.TLSClientConfig = tlsCfg
	return tr, nil
}

// hasTLSConfig reports whether any backend TLS field is set.
func hasTLSConfig(cfg config.BackendTLSConfig) bool {
	return cfg.CertFile != "" || cfg.KeyFile != "" || cfg.CAFile != "" || cfg.InsecureSkipVerify
}

// transportFor returns the RoundTripper that should be used for a request to
// the named backend. The circuit breaker, when non-nil, wraps the base transport.
// Every backend has a tuned transport built at startup; the shared fallback is a
// defensive default that should not normally be reached.
func (p *Proxy) transportFor(backendName string, cb *CircuitBreaker) http.RoundTripper {
	base, ok := p.backendTransports[backendName]
	if !ok || base == nil {
		base = p.defaultTransport
	}
	if cb != nil {
		return &circuitTransport{base: base, circuit: cb}
	}
	return base
}

// wsTransportFor returns the RoundTripper for a WebSocket upgrade. When a
// WebSocket idle timeout is configured it clones the backend transport and wraps
// its DialContext so the upstream (backend) connection also enforces the idle
// deadline — the downstream/client side is handled by idleHijackWriter. The
// clone preserves the backend's TLS settings (mTLS, custom CA). Falls back to the
// regular transport when no idle timeout is set.
func (p *Proxy) wsTransportFor(backendName string, cb *CircuitBreaker) http.RoundTripper {
	if p.wsIdleTimeout <= 0 {
		return p.transportFor(backendName, cb)
	}
	base, ok := p.backendTransports[backendName]
	tr, isTransport := base.(*http.Transport)
	if !ok || !isTransport || tr == nil {
		return p.transportFor(backendName, cb)
	}

	clone := tr.Clone()
	idle := p.wsIdleTimeout
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	clone.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &idleConn{Conn: conn, idle: idle}, nil
	}

	var rt http.RoundTripper = clone
	if cb != nil {
		rt = &circuitTransport{base: clone, circuit: cb}
	}
	return rt
}
