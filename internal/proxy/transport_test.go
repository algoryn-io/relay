package proxy

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

// generateCA creates a self-signed CA certificate and returns
// (certPEM, keyPEM, *x509.Certificate, *ecdsa.PrivateKey).
func generateCA(t *testing.T) ([]byte, []byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	return certPEM, keyPEM, cert, priv
}

// generateLeafCert creates a TLS leaf cert signed by the given CA.
func generateLeafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, isClient bool) ([]byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	extUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if isClient {
		extUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Test Leaf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  extUsage,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	return certPEM, keyPEM
}

func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	_ = f.Close()
	return f.Name()
}

// TestBuildBackendTransportEmpty verifies that an empty TLS config still
// returns a usable transport (plain HTTP/HTTPS with system CAs).
func TestBuildBackendTransportEmpty(t *testing.T) {
	t.Parallel()

	tr, err := buildBackendTransport(config.BackendTLSConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr == nil {
		t.Fatal("want non-nil transport, got nil")
	}
}

// TestBuildBackendTransportInsecureSkipVerify verifies that a transport with
// InsecureSkipVerify=true successfully connects to a TLS server with a
// self-signed certificate that is NOT in the system CA store.
func TestBuildBackendTransportInsecureSkipVerify(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr, err := buildBackendTransport(config.BackendTLSConfig{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestBuildBackendTransportCustomCA verifies that a backend's server cert
// signed by a private CA is accepted when that CA is provided via ca_file.
func TestBuildBackendTransportCustomCA(t *testing.T) {
	t.Parallel()

	caPEM, _, caCert, caKey := generateCA(t)
	serverCertPEM, serverKeyPEM := generateLeafCert(t, caCert, caKey, false)

	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverTLSCert}}
	srv.StartTLS()
	defer srv.Close()

	caFile := writeTempFile(t, caPEM)

	tr, err := buildBackendTransport(config.BackendTLSConfig{CAFile: caFile})
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET with custom CA: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestBuildBackendTransportMTLS verifies that the relay authenticates to a
// backend that requires a client certificate.
func TestBuildBackendTransportMTLS(t *testing.T) {
	t.Parallel()

	caPEM, _, caCert, caKey := generateCA(t)
	serverCertPEM, serverKeyPEM := generateLeafCert(t, caCert, caKey, false)
	clientCertPEM, clientKeyPEM := generateLeafCert(t, caCert, caKey, true)

	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequireAnyClientCert,
		ClientCAs:    caPool,
	}
	srv.StartTLS()
	defer srv.Close()

	certFile := writeTempFile(t, clientCertPEM)
	keyFile := writeTempFile(t, clientKeyPEM)
	caFile := writeTempFile(t, caPEM)

	tr, err := buildBackendTransport(config.BackendTLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("mTLS GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestBuildBackendTransportMTLSRejectedWithoutCert verifies that a backend
// requiring a client cert rejects a connection that does not provide one.
func TestBuildBackendTransportMTLSRejectedWithoutCert(t *testing.T) {
	t.Parallel()

	caPEM, _, caCert, caKey := generateCA(t)
	serverCertPEM, serverKeyPEM := generateLeafCert(t, caCert, caKey, false)

	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequireAnyClientCert,
		ClientCAs:    caPool,
	}
	srv.StartTLS()
	defer srv.Close()

	caFile := writeTempFile(t, caPEM)

	// No cert_file / key_file — request must be rejected by the server.
	tr, err := buildBackendTransport(config.BackendTLSConfig{CAFile: caFile})
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}

	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	resp, err := client.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Error("expected TLS error for missing client cert, got nil")
	}
}

// TestBuildBackendTransportMissingCAFile verifies that a non-existent ca_file
// returns an error from buildBackendTransport.
func TestBuildBackendTransportMissingCAFile(t *testing.T) {
	t.Parallel()

	_, err := buildBackendTransport(config.BackendTLSConfig{
		CAFile: filepath.Join(t.TempDir(), "nonexistent-ca.pem"),
	})
	if err == nil {
		t.Error("expected error for missing CA file, got nil")
	}
}

// TestBuildBackendTransportEmptyCAFile verifies that a CA file with no valid
// PEM certificates returns an error.
func TestBuildBackendTransportEmptyCAFile(t *testing.T) {
	t.Parallel()

	caFile := writeTempFile(t, []byte("not a cert\n"))
	_, err := buildBackendTransport(config.BackendTLSConfig{CAFile: caFile})
	if err == nil {
		t.Error("expected error for empty CA file, got nil")
	}
}

// TestBuildBackendTransportInvalidKeyPair verifies that a mismatched cert/key
// returns an error.
func TestBuildBackendTransportInvalidKeyPair(t *testing.T) {
	t.Parallel()

	_, _, ca1, key1 := generateCA(t)
	_, _, ca2, key2 := generateCA(t)
	certPEM, _ := generateLeafCert(t, ca1, key1, true) // cert from CA1
	_, keyPEM := generateLeafCert(t, ca2, key2, true)  // key from CA2 (mismatch)

	certFile := writeTempFile(t, certPEM)
	keyFile := writeTempFile(t, keyPEM)

	_, err := buildBackendTransport(config.BackendTLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err == nil {
		t.Error("expected error for mismatched cert/key pair, got nil")
	}
}

// TestTransportForFallback verifies that transportFor returns the proxy's tuned
// default transport when no custom transport is registered for a backend.
func TestTransportForFallback(t *testing.T) {
	t.Parallel()

	def := newBaseTransport()
	p := &Proxy{
		backendTransports: map[string]http.RoundTripper{},
		defaultTransport:  def,
	}
	tr := p.transportFor("unknown-backend", nil)
	if tr != def {
		t.Errorf("want proxy default transport, got %T", tr)
	}
}

// TestTransportForCircuitBreaker verifies that a circuit breaker wraps the base
// transport when provided.
func TestTransportForCircuitBreaker(t *testing.T) {
	t.Parallel()

	def := newBaseTransport()
	cb := newCircuitBreaker(5, 30*time.Second)
	p := &Proxy{
		backendTransports: map[string]http.RoundTripper{},
		defaultTransport:  def,
	}
	tr := p.transportFor("b", cb)
	ct, ok := tr.(*circuitTransport)
	if !ok {
		t.Fatalf("want *circuitTransport, got %T", tr)
	}
	if ct.base != def {
		t.Errorf("circuitTransport.base = %T, want proxy default transport", ct.base)
	}
	if ct.circuit != cb {
		t.Error("circuitTransport.circuit does not match provided circuit breaker")
	}
}

// TestTransportForCustomBase verifies that a registered custom transport is
// used as the base for the circuit breaker wrapper.
func TestTransportForCustomBase(t *testing.T) {
	t.Parallel()

	customBase, err := buildBackendTransport(config.BackendTLSConfig{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}

	cb := newCircuitBreaker(5, 30*time.Second)
	p := &Proxy{
		backendTransports: map[string]http.RoundTripper{"b": customBase},
	}
	tr := p.transportFor("b", cb)
	ct, ok := tr.(*circuitTransport)
	if !ok {
		t.Fatalf("want *circuitTransport, got %T", tr)
	}
	if ct.base != customBase {
		t.Errorf("circuitTransport.base = %T, want custom transport", ct.base)
	}
}

// TestProxyNewWithInvalidCertFile verifies that proxy.New returns an error when
// a backend's cert_file is invalid.
func TestProxyNewWithInvalidCertFile(t *testing.T) {
	t.Parallel()

	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"b": {
				Name:     "b",
				Strategy: "round_robin",
				TLS: config.BackendTLSConfig{
					CertFile: filepath.Join(t.TempDir(), "missing.crt"),
					KeyFile:  filepath.Join(t.TempDir(), "missing.key"),
				},
				Instances: []config.InstanceRuntime{{URL: "https://127.0.0.1:9443", Weight: 1}},
			},
		},
		Routes: map[string]config.RouteRuntime{"r": {Name: "r", BackendName: "b"}},
	}

	_, err := New(rt, nil)
	if err == nil {
		t.Error("expected error for missing cert file, got nil")
	}
}
