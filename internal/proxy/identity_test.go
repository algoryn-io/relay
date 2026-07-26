package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
)

func TestApplyRelayOwnedHeadersPropagatesVerifiedIdentity(t *testing.T) {
	t.Parallel()

	uri, _ := url.Parse("spiffe://example.test/workload")
	cert := &x509.Certificate{
		Raw:            []byte("leaf-der"),
		Subject:        pkix.Name{CommonName: "client"},
		DNSNames:       []string{"client.example.test"},
		EmailAddresses: []string{"client@example.test"},
		IPAddresses:    []net.IP{net.ParseIP("2001:db8::7")},
		URIs:           []*url.URL{uri},
	}
	req := httptest.NewRequest(http.MethodGet, "https://relay.test/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
	req = httpx.WithForwarding(req, httpx.ParseTrustedNets([]string{"10.0.0.0/8"}), true)

	headers := make(http.Header)
	for _, name := range clientIdentityHeaders {
		headers.Set(name, "spoofed")
	}
	policy := config.ClientIdentityPropagationConfig{
		Enabled:                  true,
		Fields:                   []string{"subject", "san_dns", "san_email", "san_ip", "san_uri", "fingerprint_sha256"},
		AcknowledgeVerifiedHTTPS: true,
	}
	route := &config.RouteRuntime{PropagateClientIdentity: policy}
	backend := config.BackendRuntime{PropagateClientIdentity: policy}
	target, _ := url.Parse("https://backend.test")

	applyRelayOwnedHeaders(headers, req, route, backend, target, "10.0.0.1", "https", "relay.test")

	if got := headers.Get("X-Relay-Client-Cert-Subject"); got != "CN=client" {
		t.Fatalf("subject = %q", got)
	}
	if got := headers.Get("X-Relay-Client-Cert-San-Dns"); got != "client.example.test" {
		t.Fatalf("DNS SAN = %q", got)
	}
	if got := headers.Get("X-Relay-Client-Cert-San-Ip"); got != "2001:db8::7" {
		t.Fatalf("IP SAN = %q", got)
	}
	if got := headers.Get("X-Relay-Client-Cert-Fingerprint-Sha256"); len(got) != 64 || strings.Contains(got, "spoofed") {
		t.Fatalf("fingerprint = %q", got)
	}
	if got := headers.Get("Forwarded"); got != `for=10.0.0.1;proto=https;host="relay.test"` {
		t.Fatalf("Forwarded = %q", got)
	}
}

func TestApplyRelayOwnedHeadersRejectsSpoofAndUnverifiedIdentity(t *testing.T) {
	t.Parallel()

	cert := &x509.Certificate{Raw: []byte("unverified"), Subject: pkix.Name{CommonName: "attacker"}}
	req := httptest.NewRequest(http.MethodGet, "https://relay.test/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	headers := make(http.Header)
	headers.Set("X-Relay-Client-Cert-Subject", "spoofed")
	policy := config.ClientIdentityPropagationConfig{
		Enabled: true, Fields: []string{"subject"}, AcknowledgeVerifiedHTTPS: true,
	}
	target, _ := url.Parse("https://backend.test")

	applyRelayOwnedHeaders(headers, req, &config.RouteRuntime{PropagateClientIdentity: policy},
		config.BackendRuntime{}, target, "192.0.2.1", "https", "relay.test")

	if got := headers.Get("X-Relay-Client-Cert-Subject"); got != "" {
		t.Fatalf("unverified/spoofed subject propagated: %q", got)
	}
}

func TestIdentityPropagationRequiresVerifiedHTTPSUpstream(t *testing.T) {
	t.Parallel()

	policy := config.ClientIdentityPropagationConfig{
		Enabled: true, Fields: []string{"subject"}, AcknowledgeVerifiedHTTPS: true,
	}
	httpTarget, _ := url.Parse("http://backend.test")
	httpsTarget, _ := url.Parse("https://backend.test")
	if identityPropagationSafe(policy, config.BackendRuntime{}, httpTarget) {
		t.Fatal("identity propagation allowed over HTTP")
	}
	if identityPropagationSafe(policy, config.BackendRuntime{TLS: config.BackendTLSConfig{InsecureSkipVerify: true}}, httpsTarget) {
		t.Fatal("identity propagation allowed with insecure TLS verification")
	}
}
