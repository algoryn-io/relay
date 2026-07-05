package listener

import (
	"io"
	"net"
	"net/http"
	"testing"
)

// TestServerAcceptsInboundH2C verifies that the plaintext listener accepts a
// cleartext HTTP/2 (h2c) client — the transport gRPC uses without TLS — and
// still serves HTTP/1.1 clients transparently through the same wrapper.
func TestServerAcceptsInboundH2C(t *testing.T) {
	t.Parallel()

	server := newTestServer(t) // HTTP-only listener => handler wrapped for h2c
	if server.httpServer == nil {
		t.Fatal("expected a plaintext HTTP server")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = server.httpServer.Serve(ln) }()
	t.Cleanup(func() { _ = server.httpServer.Close() })

	base := "http://" + ln.Addr().String()

	// h2c client: stdlib transport with unencrypted HTTP/2 (prior knowledge).
	h2cProtocols := new(http.Protocols)
	h2cProtocols.SetUnencryptedHTTP2(true)
	h2cClient := &http.Client{Transport: &http.Transport{Protocols: h2cProtocols}}
	resp, err := h2cClient.Get(base + "/api/orders")
	if err != nil {
		t.Fatalf("h2c GET: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.ProtoMajor != 2 {
		t.Fatalf("h2c client negotiated HTTP/%d, want HTTP/2", resp.ProtoMajor)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("h2c status = %d, want 200", resp.StatusCode)
	}

	// HTTP/1.1 clients must keep working through the same wrapped handler.
	resp1, err := http.Get(base + "/api/orders")
	if err != nil {
		t.Fatalf("http/1.1 GET: %v", err)
	}
	defer resp1.Body.Close()
	if resp1.ProtoMajor != 1 {
		t.Fatalf("plain client negotiated HTTP/%d, want HTTP/1", resp1.ProtoMajor)
	}
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("http/1.1 status = %d, want 200", resp1.StatusCode)
	}
}
