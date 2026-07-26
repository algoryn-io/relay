package listener

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestSNICertificateSelectionAndNoLeak(t *testing.T) {
	t.Parallel()
	defaultCert, defaultKey := writeNamedCertificate(t, 1, "default.example.com")
	exactCert, exactKey := writeNamedCertificate(t, 2, "api.example.com")
	wildcardCert, wildcardKey := writeNamedCertificate(t, 3, "*.tenant.example.com")

	store, err := loadSNICertificates(config.TLSConfig{
		CertFile: defaultCert,
		KeyFile:  defaultKey,
		Certificates: []config.TLSCertificateConfig{
			{Hosts: []string{"api.example.com"}, CertFile: exactCert, KeyFile: exactKey},
			{Hosts: []string{"*.tenant.example.com"}, CertFile: wildcardCert, KeyFile: wildcardKey},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSelectedSerial(t, store, "", 1)
	assertSelectedSerial(t, store, "API.EXAMPLE.COM.", 2)
	assertSelectedSerial(t, store, "one.tenant.example.com", 3)

	for _, name := range []string{"unknown.example.com", "deep.one.tenant.example.com"} {
		if cert, selectErr := store.GetCertificate(&tls.ClientHelloInfo{ServerName: name}); selectErr == nil || cert != nil {
			t.Fatalf("GetCertificate(%q) = (%v, %v), want no certificate and error", name, cert, selectErr)
		}
	}
}

func TestSNICertificateMustCoverConfiguredHost(t *testing.T) {
	t.Parallel()
	defaultCert, defaultKey := writeNamedCertificate(t, 1, "default.example.com")
	wrongCert, wrongKey := writeNamedCertificate(t, 2, "other.example.com")
	_, err := loadSNICertificates(config.TLSConfig{
		CertFile: defaultCert,
		KeyFile:  defaultKey,
		Certificates: []config.TLSCertificateConfig{{
			Hosts: []string{"api.example.com"}, CertFile: wrongCert, KeyFile: wrongKey,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "does not cover hostname") {
		t.Fatalf("error = %v, want SAN coverage error", err)
	}
}

func TestTLSConfigHandleUsesSNIAndReloadOnNewHandshakes(t *testing.T) {
	t.Parallel()
	defaultCert, defaultKey := writeNamedCertificate(t, 1, "default.example.com")
	apiCert1, apiKey1 := writeNamedCertificate(t, 2, "api.example.com")
	apiCert2, apiKey2 := writeNamedCertificate(t, 3, "api.example.com")
	initial := config.TLSConfig{
		CertFile: defaultCert,
		KeyFile:  defaultKey,
		Certificates: []config.TLSCertificateConfig{{
			Hosts: []string{"api.example.com"}, CertFile: apiCert1, KeyFile: apiKey1,
		}},
	}
	listenerConfig, handle, err := buildTLSConfig(initial)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := tls.Listen("tcp", "127.0.0.1:0", listenerConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	go acceptTLSConnections(socket)

	if got := dialCertificateSerial(t, socket.Addr().String(), "api.example.com"); got != 2 {
		t.Fatalf("initial API certificate serial = %d, want 2", got)
	}
	reloaded := initial
	reloaded.Certificates = []config.TLSCertificateConfig{{
		Hosts: []string{"api.example.com"}, CertFile: apiCert2, KeyFile: apiKey2,
	}}
	prepared, err := prepareTLSConfig(reloaded)
	if err != nil {
		t.Fatal(err)
	}
	handle.Store(prepared)
	if got := dialCertificateSerial(t, socket.Addr().String(), "api.example.com"); got != 3 {
		t.Fatalf("reloaded API certificate serial = %d, want 3", got)
	}
	if conn, dialErr := tls.Dial("tcp", socket.Addr().String(), &tls.Config{
		ServerName:         "unknown.example.com",
		InsecureSkipVerify: true, //nolint:gosec -- generated test certificates
	}); dialErr == nil {
		_ = conn.Close()
		t.Fatal("unknown SNI handshake succeeded")
	}
}

func TestReloadPublishesCompleteTLSConfigTransactionally(t *testing.T) {
	t.Parallel()
	cert1, key1 := writeNamedCertificate(t, 10, "relay.example.com")
	cert2, key2 := writeNamedCertificate(t, 20, "relay.example.com")
	cfg := tlsRuntimeConfig(t, cert1, key1)
	cfg.Listener.HTTPS.TLS.MinVersion = "1.3"
	srv, err := New(cfg, emptyRuntime(), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	before := srv.tlsHandle.current.Load()
	if before.MinVersion != tls.VersionTLS13 {
		t.Fatalf("initial minimum TLS version = %d, want TLS 1.3", before.MinVersion)
	}
	reloaded := *cfg
	reloaded.Listener = cfg.Listener
	reloaded.Listener.HTTPS.TLS.CertFile = cert2
	reloaded.Listener.HTTPS.TLS.KeyFile = key2
	reloaded.Listener.HTTPS.TLS.MinVersion = "1.2"
	reloaded.Listener.HTTPS.TLS.CipherSuites = []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}
	reloaded.Listener.HTTPS.TLS.ClientCAFile = cert1
	reloaded.Listener.HTTPS.TLS.ClientAuth = "verify_if_given"

	if err := srv.Reload(&reloaded, emptyRuntime()); err != nil {
		t.Fatal(err)
	}
	after := srv.tlsHandle.current.Load()
	if after == before {
		t.Fatal("TLS config pointer was not atomically replaced")
	}
	if after.ClientAuth != tls.VerifyClientCertIfGiven || after.ClientCAs == nil {
		t.Fatalf("reloaded client auth/CA not applied: auth=%v pool=%v", after.ClientAuth, after.ClientCAs)
	}
	if after.MinVersion != tls.VersionTLS12 {
		t.Fatalf("reloaded minimum TLS version = %d, want TLS 1.2", after.MinVersion)
	}
	if len(after.CipherSuites) != 1 || after.CipherSuites[0] != tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("reloaded cipher suites = %v", after.CipherSuites)
	}
	assertSelectedSerialFromConfig(t, after, "relay.example.com", 20)

	stateBeforeFailure := srv.state.Load()
	tlsBeforeFailure := srv.tlsHandle.current.Load()
	failed := reloaded
	failed.Listener = reloaded.Listener
	failed.Listener.HTTPS.TLS.ClientCAFile = filepath.Join(t.TempDir(), "missing-ca.pem")
	if err := srv.Reload(&failed, emptyRuntime()); err == nil {
		t.Fatal("Reload succeeded with an unreadable client CA")
	}
	if srv.state.Load() != stateBeforeFailure || srv.tlsHandle.current.Load() != tlsBeforeFailure {
		t.Fatal("failed reload changed HTTP or TLS runtime state")
	}

	failedBuild := reloaded
	failedBuild.Listener = reloaded.Listener
	failedBuild.Listener.HTTPS.TLS.CertFile = cert1
	failedBuild.Listener.HTTPS.TLS.KeyFile = key1
	badRuntime := emptyRuntime()
	badRuntime.Routes["broken"] = config.RouteRuntime{
		Name: "broken", Path: "/", Methods: []string{"GET"}, MiddlewareRefs: []string{"missing"},
	}
	if err := srv.Reload(&failedBuild, badRuntime); err == nil {
		t.Fatal("Reload succeeded with an invalid request runtime")
	}
	if srv.state.Load() != stateBeforeFailure || srv.tlsHandle.current.Load() != tlsBeforeFailure {
		t.Fatal("request-state build failure published prepared HTTP or TLS state")
	}
}

func TestReloadRejectsListenerTopologyChanges(t *testing.T) {
	t.Parallel()
	certFile, keyFile := writeNamedCertificate(t, 1, "relay.example.com")
	cfg := tlsRuntimeConfig(t, certFile, keyFile)
	srv, err := New(cfg, emptyRuntime(), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	changedPort := *cfg
	changedPort.Listener = cfg.Listener
	changedPort.Listener.HTTPS.Port++
	if err := srv.Reload(&changedPort, emptyRuntime()); err == nil || !strings.Contains(err.Error(), "cannot change listener ports") {
		t.Fatalf("port reload error = %v", err)
	}

	changedMode := *cfg
	changedMode.Listener = cfg.Listener
	changedMode.Listener.HTTPS.TLS.Mode = "auto"
	if err := srv.Reload(&changedMode, emptyRuntime()); err == nil || !strings.Contains(err.Error(), "cannot change TLS mode") {
		t.Fatalf("mode reload error = %v", err)
	}
}

func assertSelectedSerial(t *testing.T, store *sniCertificateStore, name string, want int64) {
	t.Helper()
	cert, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
	if err != nil {
		t.Fatal(err)
	}
	if got := cert.Leaf.SerialNumber.Int64(); got != want {
		t.Fatalf("certificate serial for %q = %d, want %d", name, got, want)
	}
}

func acceptTLSConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}()
	}
}

func dialCertificateSerial(t *testing.T, address, serverName string) int64 {
	t.Helper()
	conn, err := tls.Dial("tcp", address, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec -- generated test certificates
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

func assertSelectedSerialFromConfig(t *testing.T, cfg *tls.Config, name string, want int64) {
	t.Helper()
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
	if err != nil {
		t.Fatal(err)
	}
	if got := cert.Leaf.SerialNumber.Int64(); got != want {
		t.Fatalf("certificate serial = %d, want %d", got, want)
	}
}

func tlsRuntimeConfig(t *testing.T, certFile, keyFile string) *config.Config {
	t.Helper()
	return testServerConfig(config.ListenerConfig{
		HTTPS: config.HTTPSConfig{
			Port: freePort(t),
			TLS: config.TLSConfig{
				Mode:     "manual",
				CertFile: certFile,
				KeyFile:  keyFile,
			},
		},
		Timeouts: config.TimeoutsConfig{Read: time.Second, Write: time.Second, Idle: time.Second},
	})
}

func emptyRuntime() *config.RuntimeConfig {
	return &config.RuntimeConfig{
		Routes:     map[string]config.RouteRuntime{},
		Backends:   map[string]config.BackendRuntime{},
		Middleware: map[string]config.MiddlewareRuntime{},
	}
}

func writeNamedCertificate(t *testing.T, serial int64, dnsNames ...string) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
