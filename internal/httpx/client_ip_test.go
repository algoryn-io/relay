package httpx

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPUsesRemoteAddrOnly(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:4321"
	req.Header.Set("X-Forwarded-For", "198.51.100.50")

	if got := ClientIP(req); got != "203.0.113.10" {
		t.Fatalf("ClientIP() = %q, want 203.0.113.10", got)
	}
}

func TestClientIPFallsBackToRawRemoteAddr(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10"

	if got := ClientIP(req); got != "203.0.113.10" {
		t.Fatalf("ClientIP() = %q, want 203.0.113.10", got)
	}
}

func TestClientIPFromContextViaTrustedProxy(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")

	trustedNets := ParseTrustedNets([]string{"10.0.0.0/8"})
	req = WithResolvedClientIP(req, trustedNets)

	if got := ClientIP(req); got != "203.0.113.10" {
		t.Fatalf("ClientIP() = %q, want 203.0.113.10 (from XFF via trusted proxy)", got)
	}
}

func TestClientIPIgnoresXFFFromUntrustedRemote(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:4321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	trustedNets := ParseTrustedNets([]string{"10.0.0.0/8"})
	req = WithResolvedClientIP(req, trustedNets)

	if got := ClientIP(req); got != "203.0.113.10" {
		t.Fatalf("ClientIP() = %q, want 203.0.113.10 (untrusted remote, ignore XFF)", got)
	}
}

func TestClientIPNoTrustedNetsIgnoresXFF(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")

	req = WithResolvedClientIP(req, nil)

	if got := ClientIP(req); got != "10.0.0.1" {
		t.Fatalf("ClientIP() = %q, want 10.0.0.1 (no trusted nets, ignore XFF)", got)
	}
}

func TestParseTrustedNets(t *testing.T) {
	t.Parallel()

	nets := ParseTrustedNets([]string{"10.0.0.0/8", "172.16.0.1", ""})
	if len(nets) != 2 {
		t.Fatalf("ParseTrustedNets() returned %d nets, want 2", len(nets))
	}

	if !nets[0].Contains(net.ParseIP("10.1.2.3")) {
		t.Fatalf("expected 10.0.0.0/8 to contain 10.1.2.3")
	}
	if !nets[1].Contains(net.ParseIP("172.16.0.1")) {
		t.Fatalf("expected single IP 172.16.0.1 to be contained")
	}
	if nets[1].Contains(net.ParseIP("172.16.0.2")) {
		t.Fatalf("expected 172.16.0.1/32 to NOT contain 172.16.0.2")
	}
}
