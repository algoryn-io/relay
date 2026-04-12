package httpx

import (
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
