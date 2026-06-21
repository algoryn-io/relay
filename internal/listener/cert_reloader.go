package listener

import (
	"crypto/tls"
	"fmt"
	"sync/atomic"
)

// CertReloader holds a TLS certificate that can be atomically replaced while
// the server is running. Plug GetCertificate into tls.Config.GetCertificate so
// every new TLS handshake picks up the latest certificate automatically.
type CertReloader struct {
	cert atomic.Pointer[tls.Certificate]
}

// NewCertReloader loads the initial certificate from certFile and keyFile.
// Returns an error if the files cannot be parsed.
func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	r := &CertReloader{}
	if err := r.Reload(certFile, keyFile); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload reads certFile and keyFile from disk and atomically swaps the
// certificate served by GetCertificate. If loading fails the current
// certificate is left unchanged and the error is returned.
func (r *CertReloader) Reload(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("reload certificate: %w", err)
	}
	r.cert.Store(&cert)
	return nil
}

// GetCertificate implements the tls.Config.GetCertificate callback. It returns
// the most recently loaded certificate. The ClientHelloInfo argument is ignored
// because the relay serves a single certificate.
func (r *CertReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cert.Load(), nil
}
