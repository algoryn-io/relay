package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
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

// newH2CTransport returns a transport that speaks cleartext HTTP/2 (h2c) to the
// backend using prior knowledge. It relies on the stdlib net/http support for
// unencrypted HTTP/2 (Go 1.24+): enabling only UnencryptedHTTP2 makes http://
// requests use h2c, which is what lets Relay proxy gRPC and other HTTP/2 traffic
// to non-TLS upstreams.
func newH2CTransport() *http.Transport {
	tr := newBaseTransport()
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	tr.Protocols = protocols
	return tr
}

// buildBackendTransport constructs the RoundTripper for the given backend. For
// h2c backends it returns a cleartext HTTP/2 transport. Otherwise it returns a
// tuned *http.Transport; a custom TLS config is applied only when one of the TLS
// fields is set (system roots are used for https backends by default).
func buildBackendTransport(protocol string, cfg config.BackendTLSConfig) (http.RoundTripper, error) {
	if isH2C(protocol) {
		return newH2CTransport(), nil
	}

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

// isH2C reports whether the protocol string selects cleartext HTTP/2.
func isH2C(protocol string) bool {
	return strings.EqualFold(strings.TrimSpace(protocol), "h2c")
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
