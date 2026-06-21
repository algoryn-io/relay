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
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

// writeSelfSignedCert generates a self-signed TLS certificate with the given
// serial number, writes it to a temp dir, and returns (certFile, keyFile).
func writeSelfSignedCert(t *testing.T, serial int64) (string, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{Organization: []string{"Relay Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	cf, _ := os.Create(certFile)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	_ = cf.Close()

	privDER, _ := x509.MarshalECPrivateKey(priv)
	kf, _ := os.Create(keyFile)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	_ = kf.Close()

	return certFile, keyFile
}

func certSerial(t *testing.T, c *tls.Certificate) int64 {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return leaf.SerialNumber.Int64()
}

// ──────────────────────────────────────────────────────────────────────────────
// CertReloader unit tests
// ──────────────────────────────────────────────────────────────────────────────

func TestCertReloaderLoadsInitialCert(t *testing.T) {
	t.Parallel()

	certFile, keyFile := writeSelfSignedCert(t, 1)
	r, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil")
	}
}

func TestCertReloaderSwapsToCert(t *testing.T) {
	t.Parallel()

	certFile1, keyFile1 := writeSelfSignedCert(t, 1)
	certFile2, keyFile2 := writeSelfSignedCert(t, 2)

	r, err := NewCertReloader(certFile1, keyFile1)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	cert1, _ := r.GetCertificate(nil)
	if certSerial(t, cert1) != 1 {
		t.Fatalf("initial serial = %d, want 1", certSerial(t, cert1))
	}

	if err := r.Reload(certFile2, keyFile2); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	cert2, _ := r.GetCertificate(nil)
	if certSerial(t, cert2) != 2 {
		t.Errorf("serial after reload = %d, want 2", certSerial(t, cert2))
	}
}

func TestCertReloaderKeepsOldCertOnFailure(t *testing.T) {
	t.Parallel()

	certFile, keyFile := writeSelfSignedCert(t, 42)
	r, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	reloadErr := r.Reload(
		filepath.Join(t.TempDir(), "missing.crt"),
		filepath.Join(t.TempDir(), "missing.key"),
	)
	if reloadErr == nil {
		t.Fatal("expected error for missing files, got nil")
	}

	cert, _ := r.GetCertificate(nil)
	if certSerial(t, cert) != 42 {
		t.Errorf("serial after failed reload = %d, want 42", certSerial(t, cert))
	}
}

func TestCertReloaderMissingFilesError(t *testing.T) {
	t.Parallel()

	_, err := NewCertReloader(
		filepath.Join(t.TempDir(), "no-cert.pem"),
		filepath.Join(t.TempDir(), "no-key.pem"),
	)
	if err == nil {
		t.Error("expected error for missing files, got nil")
	}
}

func TestCertReloaderConcurrentAccess(t *testing.T) {
	t.Parallel()

	certFile1, keyFile1 := writeSelfSignedCert(t, 10)
	certFile2, keyFile2 := writeSelfSignedCert(t, 11)

	r, err := NewCertReloader(certFile1, keyFile1)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			if id%2 == 0 {
				_ = r.Reload(certFile2, keyFile2)
			} else {
				cert, cerr := r.GetCertificate(nil)
				if cerr != nil || cert == nil {
					t.Errorf("GetCertificate: cert=%v err=%v", cert, cerr)
				}
			}
		}(i)
	}
	wg.Wait()
}

// ──────────────────────────────────────────────────────────────────────────────
// buildTLSConfig tests
// ──────────────────────────────────────────────────────────────────────────────

func TestBuildTLSConfigManualReturnsReloader(t *testing.T) {
	t.Parallel()

	certFile, keyFile := writeSelfSignedCert(t, 99)

	tlsCfg, reloader, err := buildTLSConfig(config.TLSConfig{
		Mode:     "manual",
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if reloader == nil {
		t.Fatal("reloader = nil for manual mode")
	}
	if tlsCfg.GetCertificate == nil {
		t.Error("tls.Config.GetCertificate is nil in manual mode")
	}
	if len(tlsCfg.Certificates) != 0 {
		t.Error("tls.Config.Certificates should be empty; rotation uses GetCertificate")
	}
}

func TestBuildTLSConfigAutoReturnsNilReloader(t *testing.T) {
	t.Parallel()

	_, reloader, err := buildTLSConfig(config.TLSConfig{
		Mode:    "auto",
		Domains: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("buildTLSConfig auto: %v", err)
	}
	if reloader != nil {
		t.Error("reloader should be nil for auto mode (autocert handles rotation)")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// End-to-end: TLS handshake picks up rotated certificate
// ──────────────────────────────────────────────────────────────────────────────

// TestCertReloaderHandshakeUsesNewCert starts a TLS listener backed by a
// CertReloader, verifies the initial certificate serial, rotates it, and
// confirms that the next handshake presents the new certificate.
func TestCertReloaderHandshakeUsesNewCert(t *testing.T) {
	t.Parallel()

	certFile1, keyFile1 := writeSelfSignedCert(t, 100)
	certFile2, keyFile2 := writeSelfSignedCert(t, 200)

	reloader, err := NewCertReloader(certFile1, keyFile1)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: reloader.GetCertificate,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	// Accept and complete handshakes in the background.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()

	dialSerial := func() int64 {
		t.Helper()
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec — test only, self-signed cert
		})
		if err != nil {
			t.Fatalf("tls.Dial: %v", err)
		}
		defer conn.Close()
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			t.Fatal("no peer certificates")
		}
		return certs[0].SerialNumber.Int64()
	}

	if got := dialSerial(); got != 100 {
		t.Errorf("serial before rotation = %d, want 100", got)
	}

	if err := reloader.Reload(certFile2, keyFile2); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if got := dialSerial(); got != 200 {
		t.Errorf("serial after rotation = %d, want 200", got)
	}
}
