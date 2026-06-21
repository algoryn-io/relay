package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"algoryn.io/relay/internal/config"
)

// buildBackendTransport constructs an http.RoundTripper for the given backend
// TLS settings. Returns a transport with a custom TLS config when any field is
// set; callers that receive nil must fall back to http.DefaultTransport.
func buildBackendTransport(cfg config.BackendTLSConfig) (http.RoundTripper, error) {
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

	return &http.Transport{
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}, nil
}

// transportFor returns the RoundTripper that should be used for a request to
// the named backend. The circuit breaker, when non-nil, wraps the base transport.
// Falls back to http.DefaultTransport when no custom transport was configured.
func (p *Proxy) transportFor(backendName string, cb *CircuitBreaker) http.RoundTripper {
	base, ok := p.backendTransports[backendName]
	if !ok || base == nil {
		base = http.DefaultTransport
	}
	if cb != nil {
		return &circuitTransport{base: base, circuit: cb}
	}
	return base
}
