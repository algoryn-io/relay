package listener

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"sync/atomic"

	"algoryn.io/relay/internal/config"
)

// TLSConfigHandle publishes complete, immutable TLS configurations atomically.
// The listener keeps a stable GetConfigForClient callback while every new
// handshake obtains the latest successfully prepared configuration.
type TLSConfigHandle struct {
	current atomic.Pointer[tls.Config]
}

func newTLSConfigHandle(initial *tls.Config) *TLSConfigHandle {
	h := &TLSConfigHandle{}
	h.current.Store(initial)
	return h
}

func (h *TLSConfigHandle) GetConfigForClient(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	cfg := h.current.Load()
	if cfg == nil {
		return nil, fmt.Errorf("TLS configuration is unavailable")
	}
	return cfg, nil
}

func (h *TLSConfigHandle) Store(cfg *tls.Config) {
	h.current.Store(cfg)
}

type sniCertificateStore struct {
	defaultCert *tls.Certificate
	exact       map[string]*tls.Certificate
	wildcards   map[string]*tls.Certificate // suffix includes the leading dot
}

func loadSNICertificates(cfg config.TLSConfig) (*sniCertificateStore, error) {
	defaultCert, err := loadCertificate(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load default cert/key: %w", err)
	}
	store := &sniCertificateStore{
		defaultCert: defaultCert,
		exact:       make(map[string]*tls.Certificate),
		wildcards:   make(map[string]*tls.Certificate),
	}
	for i, entry := range cfg.Certificates {
		cert, loadErr := loadCertificate(entry.CertFile, entry.KeyFile)
		if loadErr != nil {
			return nil, fmt.Errorf("load certificates[%d] cert/key: %w", i, loadErr)
		}
		for _, rawHost := range entry.Hosts {
			host := normalizeSNIName(rawHost)
			if coverageErr := certificateCoversHost(cert.Leaf, host); coverageErr != nil {
				return nil, fmt.Errorf("certificates[%d] host %q: %w", i, rawHost, coverageErr)
			}
			if strings.HasPrefix(host, "*.") {
				store.wildcards[strings.TrimPrefix(host, "*")] = cert
			} else {
				store.exact[host] = cert
			}
		}
	}
	return store, nil
}

func loadCertificate(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	cert.Leaf = leaf
	return &cert, nil
}

func certificateCoversHost(leaf *x509.Certificate, host string) error {
	if strings.HasPrefix(host, "*.") {
		for _, san := range leaf.DNSNames {
			if normalizeSNIName(san) == host {
				return nil
			}
		}
		return fmt.Errorf("certificate SAN does not cover wildcard")
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return fmt.Errorf("certificate SAN does not cover hostname: %w", err)
	}
	return nil
}

func (s *sniCertificateStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := ""
	if hello != nil {
		name = normalizeSNIName(hello.ServerName)
	}
	if name == "" {
		return s.defaultCert, nil
	}
	if cert := s.exact[name]; cert != nil {
		return cert, nil
	}
	if firstDot := strings.IndexByte(name, '.'); firstDot > 0 {
		if cert := s.wildcards[name[firstDot:]]; cert != nil {
			return cert, nil
		}
	}
	// The legacy/default certificate is eligible only when its SAN covers the
	// requested SNI. This prevents an unknown host from receiving another
	// tenant's certificate.
	if err := s.defaultCert.Leaf.VerifyHostname(name); err == nil {
		return s.defaultCert, nil
	}
	return nil, fmt.Errorf("no certificate configured for SNI %q", name)
}

func normalizeSNIName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
