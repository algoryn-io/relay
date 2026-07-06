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

// A client that pre-seeds X-Forwarded-For must not be able to spoof its IP: the
// real client is the right-most untrusted entry (proxies append), never the
// left-most attacker-controlled value.
func TestClientIPIgnoresSpoofedLeftmostXFF(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234" // trusted proxy peer
	// Attacker sent "1.1.1.1"; the trusted proxy appended the real client.
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 203.0.113.10")

	trustedNets := ParseTrustedNets([]string{"10.0.0.0/8"})
	req = WithResolvedClientIP(req, trustedNets)

	if got := ClientIP(req); got != "203.0.113.10" {
		t.Fatalf("ClientIP() = %q, want 203.0.113.10 (spoofed leftmost must be ignored)", got)
	}
}

// Multiple trusted proxy hops are skipped from the right; the first untrusted
// address is the real client.
func TestClientIPSkipsTrustedHops(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	// spoofed, real-client, internal-proxy (appended last by 10.0.0.1).
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 203.0.113.10, 10.0.0.2")

	trustedNets := ParseTrustedNets([]string{"10.0.0.0/8"})
	req = WithResolvedClientIP(req, trustedNets)

	if got := ClientIP(req); got != "203.0.113.10" {
		t.Fatalf("ClientIP() = %q, want 203.0.113.10 (skip trusted hops)", got)
	}
}

// If every forwarded entry is a trusted proxy, fall back to the real TCP peer
// rather than trusting any forwarded value.
func TestClientIPAllTrustedFallsBackToPeer(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.2, 10.0.0.3")

	trustedNets := ParseTrustedNets([]string{"10.0.0.0/8"})
	req = WithResolvedClientIP(req, trustedNets)

	if got := ClientIP(req); got != "10.0.0.1" {
		t.Fatalf("ClientIP() = %q, want 10.0.0.1 (all forwarded entries trusted)", got)
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
