package listener

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestBuildTLSConfigManualLoadsKeyPair(t *testing.T) {
	t.Parallel()

	certFile, keyFile := selfSignedCert(t)
	tlsCfg, err := buildTLSConfig(config.TLSConfig{
		Mode:     "manual",
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		t.Fatalf("buildTLSConfig() error = %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("certificates = %d, want 1", len(tlsCfg.Certificates))
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want TLS 1.2", tlsCfg.MinVersion)
	}
}

func TestBuildTLSConfigManualMissingFileErrors(t *testing.T) {
	t.Parallel()

	_, err := buildTLSConfig(config.TLSConfig{
		Mode:     "manual",
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("expected error for missing cert/key files, got nil")
	}
}

func TestBuildTLSConfigAutoReturnsTLSConfig(t *testing.T) {
	t.Parallel()

	tlsCfg, err := buildTLSConfig(config.TLSConfig{
		Mode:    "auto",
		Domains: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("buildTLSConfig(auto) error = %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil TLS config for auto mode")
	}
}

func TestBuildTLSConfigUnknownModeErrors(t *testing.T) {
	t.Parallel()

	_, err := buildTLSConfig(config.TLSConfig{Mode: "invalid"})
	if err == nil {
		t.Fatal("expected error for unknown mode, got nil")
	}
}

func TestHTTPSRedirectHandlerRedirectsToHTTPS(t *testing.T) {
	t.Parallel()

	handler := httpsRedirectHandler(8443)
	req := httptest.NewRequest(http.MethodGet, "/api/test?q=1", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", rec.Code)
	}
	loc := rec.Header().Get("Location")
	want := "https://example.com:8443/api/test?q=1"
	if loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

func TestHTTPSRedirectHandlerOmitsPortFor443(t *testing.T) {
	t.Parallel()

	handler := httpsRedirectHandler(443)
	req := httptest.NewRequest(http.MethodGet, "/path", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	loc := rec.Header().Get("Location")
	want := "https://example.com/path"
	if loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

func TestHTTPSRedirectHandlerStripsHostPort(t *testing.T) {
	t.Parallel()

	handler := httpsRedirectHandler(8443)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Host = "example.com:8080"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	loc := rec.Header().Get("Location")
	want := "https://example.com:8443/x"
	if loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

func TestValidateTLSManualRequiresCertAndKey(t *testing.T) {
	t.Parallel()

	cfg := testServerConfig(config.ListenerConfig{
		HTTP:  config.HTTPConfig{Port: 8080},
		HTTPS: config.HTTPSConfig{Port: 8443, TLS: config.TLSConfig{Mode: "manual"}},
	})

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for missing cert/key, got nil")
	}
}

func TestValidateTLSAutoRequiresDomains(t *testing.T) {
	t.Parallel()

	cfg := testServerConfig(config.ListenerConfig{
		HTTP:  config.HTTPConfig{Port: 8080},
		HTTPS: config.HTTPSConfig{Port: 8443, TLS: config.TLSConfig{Mode: "auto"}},
	})

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for missing domains in auto mode, got nil")
	}
}

func TestNewServerHTTPSManual(t *testing.T) {
	t.Parallel()

	certFile, keyFile := selfSignedCert(t)
	cfg := testServerConfig(config.ListenerConfig{
		HTTP: config.HTTPConfig{Port: 8080},
		HTTPS: config.HTTPSConfig{
			Port: freePort(t),
			TLS: config.TLSConfig{
				Mode:     "manual",
				CertFile: certFile,
				KeyFile:  keyFile,
			},
		},
	})

	rt := &config.RuntimeConfig{
		Routes:   map[string]config.RouteRuntime{},
		Backends: map[string]config.BackendRuntime{},
	}
	srv, err := New(cfg, rt, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if srv.httpsServer == nil {
		t.Fatal("expected httpsServer to be non-nil")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// selfSignedCert generates an ECDSA self-signed certificate and writes the
// PEM files to a temp directory. Returns paths to cert and key files.
func selfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certOut, _ := os.Create(certFile)
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyOut, _ := os.Create(keyFile)
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyOut.Close()

	return certFile, keyFile
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
