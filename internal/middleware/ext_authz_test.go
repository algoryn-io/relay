package middleware

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
)

func newExtAuthz(t *testing.T, server *httptest.Server, copyHeaders []string, failOpen bool) Middleware {
	t.Helper()
	mw, err := NewExtAuthz(ExtAuthzConfig{
		URL:         server.URL,
		CopyHeaders: copyHeaders,
		FailOpen:    failOpen,
		Client:      server.Client(),
	})
	if err != nil {
		t.Fatalf("NewExtAuthz() error = %v", err)
	}
	return mw
}

func TestExtAuthzRequiresHTTPSByDefault(t *testing.T) {
	t.Parallel()

	if _, err := NewExtAuthz(ExtAuthzConfig{URL: "http://authz.internal/check"}); err == nil {
		t.Fatal("NewExtAuthz() error = nil, want HTTP endpoint rejection")
	}
	if _, err := NewExtAuthz(ExtAuthzConfig{
		URL:               "http://authz.internal/check",
		AllowInsecureHTTP: true,
	}); err != nil {
		t.Fatalf("NewExtAuthz() explicit HTTP opt-in error = %v", err)
	}
}

func TestExtAuthzAllowsOn2xx(t *testing.T) {
	t.Parallel()

	var gotMethod, gotURI string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Header.Get("X-Forwarded-Method")
		gotURI = r.Header.Get("X-Forwarded-Uri")
		w.Header().Set("X-User-Id", "alice")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	mw := newExtAuthz(t, server, []string{"X-User-Id"}, false)

	var injected string
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		injected = r.Header.Get("X-User-Id")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/orders?x=1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if injected != "alice" {
		t.Fatalf("copied header X-User-Id = %q, want alice", injected)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("forwarded method = %q, want POST", gotMethod)
	}
	if gotURI != "/orders?x=1" {
		t.Fatalf("forwarded uri = %q, want /orders?x=1", gotURI)
	}
}

func TestExtAuthzPublishesOnlyAuthorizerIdentity(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(extAuthzSubjectHeader, "verified-user")
		w.Header().Set(extAuthzTenantHeader, "verified-tenant")
		w.Header().Set(extAuthzKeyIDHeader, "decision-key")
		w.Header().Set(extAuthzClaimHeaderPrefix+"Account-Id", "verified-account")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	mw := newExtAuthz(t, server, nil, false)

	var identity AuthIdentity
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _ = authIdentityFromRequest(r)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(extAuthzSubjectHeader, "client-spoof")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if identity.Subject != "verified-user" || identity.Tenant != "verified-tenant" ||
		identity.KeyID != "decision-key" || identity.Claims["account-id"] != "verified-account" {
		t.Fatalf("identity = %+v", identity)
	}
}

// A client must not be able to spoof a copy_header: when the authorizer allows
// the request but does not set the header, the inbound (client) value must be
// stripped, not forwarded to the backend.
func TestExtAuthzStripsSpoofedCopyHeader(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // allow, but do NOT set X-User-Id
	}))
	t.Cleanup(server.Close)

	mw := newExtAuthz(t, server, []string{"X-User-Id"}, false)

	var forwarded string
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get("X-User-Id")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User-Id", "admin") // attacker-supplied
	h.ServeHTTP(httptest.NewRecorder(), req)

	if forwarded != "" {
		t.Fatalf("backend received spoofed X-User-Id = %q, want empty (stripped)", forwarded)
	}
}

func TestExtAuthzDeniesOn403(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	var backendCalled atomic.Bool
	mw := newExtAuthz(t, server, nil, false)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if backendCalled.Load() {
		t.Fatal("backend must not be called when authz denies")
	}
}

func TestExtAuthzDeniesOn401(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	mw := newExtAuthz(t, server, nil, false)
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestExtAuthzFailClosedWhenUnreachable(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mw := newExtAuthz(t, server, nil, false)
	server.Close()

	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail closed)", rec.Code)
	}
}

func TestExtAuthzFailOpenWhenUnreachable(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mw := newExtAuthz(t, server, nil, true)
	server.Close()

	var called atomic.Bool
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !called.Load() {
		t.Fatalf("fail_open should let request through: status=%d called=%v", rec.Code, called.Load())
	}
}

// Ensure the client IP resolved by the edge is forwarded to the authorizer.
func TestExtAuthzForwardsClientIP(t *testing.T) {
	t.Parallel()

	var gotXFF string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	mw := newExtAuthz(t, server, nil, false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req = httpx.WithResolvedClientIP(req, nil)
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, req)

	if gotXFF != "203.0.113.9" {
		t.Fatalf("forwarded X-Forwarded-For = %q, want 203.0.113.9", gotXFF)
	}
}

func TestExtAuthzConfiguresProbeMethod(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodHead} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			var got string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Method
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(server.Close)

			mw, err := NewExtAuthz(ExtAuthzConfig{URL: server.URL, Method: method, Client: server.Client()})
			if err != nil {
				t.Fatalf("NewExtAuthz() error = %v", err)
			}
			rec := httptest.NewRecorder()
			mw(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != http.StatusOK || got != method {
				t.Fatalf("status=%d method=%q, want 200 and %q", rec.Code, got, method)
			}
		})
	}
}

func TestBuildExtAuthzWiresRequestContract(t *testing.T) {
	t.Parallel()

	var gotMethod, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotMethod, gotBody = r.Method, string(body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	mw, closer, err := Build(config.MiddlewareRuntime{
		Name: "authz",
		Type: "ext_authz",
		Config: config.MiddlewareSettingsConfig{
			AuthzURL:               server.URL,
			AuthzMethod:            http.MethodPost,
			AuthzBody:              "original",
			AuthzMaxBodyBytes:      64,
			AuthzContentType:       "text/plain",
			AuthzAllowInsecureHTTP: true,
		},
	}, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("factory-body")))
	if rec.Code != http.StatusOK || gotMethod != http.MethodPost || gotBody != "factory-body" {
		t.Fatalf("status=%d method=%q body=%q", rec.Code, gotMethod, gotBody)
	}
}

func TestExtAuthzOriginalBodyIsReplayedUpstream(t *testing.T) {
	t.Parallel()

	const payload = `{"action":"create"}`
	var authzBody, authzContentType string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		authzBody = string(body)
		authzContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	mw, err := NewExtAuthz(ExtAuthzConfig{
		URL:          server.URL,
		Method:       http.MethodPost,
		Body:         ExtAuthzBodyOriginal,
		MaxBodyBytes: 1024,
		ContentType:  "application/vnd.authz+json",
		Client:       server.Client(),
	})
	if err != nil {
		t.Fatalf("NewExtAuthz() error = %v", err)
	}
	var upstreamBody string
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/orders", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || authzBody != payload || upstreamBody != payload {
		t.Fatalf("status=%d authz body=%q upstream body=%q", rec.Code, authzBody, upstreamBody)
	}
	if authzContentType != "application/vnd.authz+json" {
		t.Fatalf("authz Content-Type = %q", authzContentType)
	}
	replay, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody() error = %v", err)
	}
	replayed, _ := io.ReadAll(replay)
	if string(replayed) != payload {
		t.Fatalf("GetBody() = %q, want %q", replayed, payload)
	}
}

func TestExtAuthzOriginalBodyOversizedAlwaysReturns413(t *testing.T) {
	t.Parallel()

	for _, failOpen := range []bool{false, true} {
		failOpen := failOpen
		t.Run(map[bool]string{false: "closed", true: "open"}[failOpen], func(t *testing.T) {
			t.Parallel()
			var authzCalled, upstreamCalled atomic.Bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authzCalled.Store(true)
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(server.Close)
			mw, err := NewExtAuthz(ExtAuthzConfig{
				URL: server.URL, Method: http.MethodPost, Body: ExtAuthzBodyOriginal,
				MaxBodyBytes: 4, FailOpen: failOpen, Client: server.Client(),
			})
			if err != nil {
				t.Fatalf("NewExtAuthz() error = %v", err)
			}
			h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalled.Store(true)
			}))
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345"))
			req.ContentLength = -1 // exercise the bounded read, not the fast size check
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413", rec.Code)
			}
			if authzCalled.Load() || upstreamCalled.Load() {
				t.Fatalf("oversized body called authz=%v upstream=%v", authzCalled.Load(), upstreamCalled.Load())
			}
			if !strings.Contains(rec.Body.String(), "authz_body_too_large") {
				t.Fatalf("body = %q, want clear error code", rec.Body.String())
			}
		})
	}
}

func TestExtAuthzDoesNotReadStreamingOrUpgradeBodies(t *testing.T) {
	t.Parallel()

	requestKinds := map[string]func(*http.Request){
		"chunked":   func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		"websocket": func(r *http.Request) { r.Header.Set("Connection", "Upgrade"); r.Header.Set("Upgrade", "websocket") },
	}
	for name, configureRequest := range requestKinds {
		name, configureRequest := name, configureRequest
		for _, failOpen := range []bool{false, true} {
			failOpen := failOpen
			t.Run(name+"/"+map[bool]string{false: "closed", true: "open"}[failOpen], func(t *testing.T) {
				t.Parallel()
				var authzCalled atomic.Bool
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					authzCalled.Store(true)
				}))
				t.Cleanup(server.Close)
				mw, err := NewExtAuthz(ExtAuthzConfig{
					URL: server.URL, Method: http.MethodPost, Body: ExtAuthzBodyOriginal,
					MaxBodyBytes: 32, FailOpen: failOpen, Client: server.Client(),
				})
				if err != nil {
					t.Fatalf("NewExtAuthz() error = %v", err)
				}
				body := &countingReadCloser{Reader: strings.NewReader("stream")}
				var upstreamCalled atomic.Bool
				h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreamCalled.Store(true)
					w.WriteHeader(http.StatusOK)
				}))
				req := httptest.NewRequest(http.MethodPost, "/", body)
				configureRequest(req)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)

				wantStatus := http.StatusServiceUnavailable
				if failOpen {
					wantStatus = http.StatusOK
				}
				if rec.Code != wantStatus || upstreamCalled.Load() != failOpen {
					t.Fatalf("status=%d upstream=%v, want %d/%v", rec.Code, upstreamCalled.Load(), wantStatus, failOpen)
				}
				if body.reads.Load() != 0 {
					t.Fatalf("body was read %d times", body.reads.Load())
				}
				if authzCalled.Load() {
					t.Fatal("authorizer was called for a streaming or upgrade body")
				}
			})
		}
	}
}

func TestExtAuthzMetadataIncludesOnlySelectedHeaders(t *testing.T) {
	t.Parallel()

	var got extAuthzMetadata
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode metadata: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	mw, err := NewExtAuthz(ExtAuthzConfig{
		URL: server.URL, Method: http.MethodPost, Body: ExtAuthzBodyMetadata,
		ForwardHeaders: []string{"X-Tenant"}, Client: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewExtAuthz() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, "/orders?q=1", nil)
	req.Host = "api.example.test"
	req.RemoteAddr = "198.51.100.8:4321"
	req.Header.Set("X-Tenant", "acme")
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Cookie", "session=secret")
	req = httpx.WithResolvedClientIP(req, nil)
	req = httpx.WithRequestID(req, "request-123")
	uri, _ := url.Parse("spiffe://example.test/client")
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "client-a"}, DNSNames: []string{"client.example.test"}, URIs: []*url.URL{uri}}
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got.Method != http.MethodPut || got.Path != "/orders?q=1" || got.Host != "api.example.test" ||
		got.ClientIP != "198.51.100.8" || got.RequestID != "request-123" {
		t.Fatalf("metadata = %+v", got)
	}
	if len(got.Headers) != 1 || got.Headers["X-Tenant"][0] != "acme" {
		t.Fatalf("selected headers = %#v", got.Headers)
	}
	encoded, _ := json.Marshal(got.Headers)
	if bytes.Contains(encoded, []byte("secret")) {
		t.Fatalf("metadata leaked unselected secret headers: %s", encoded)
	}
	if got.MTLSIdentity == nil || got.MTLSIdentity.Subject != "CN=client-a" ||
		len(got.MTLSIdentity.URIs) != 1 || got.MTLSIdentity.URIs[0] != uri.String() {
		t.Fatalf("mTLS identity = %+v", got.MTLSIdentity)
	}
}

func TestExtAuthzMetadataHonorsBodyLimit(t *testing.T) {
	t.Parallel()

	var authzCalled, upstreamCalled atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authzCalled.Store(true)
	}))
	t.Cleanup(server.Close)
	mw, err := NewExtAuthz(ExtAuthzConfig{
		URL: server.URL, Method: http.MethodPost, Body: ExtAuthzBodyMetadata,
		MaxBodyBytes: 1, FailOpen: true, Client: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewExtAuthz() error = %v", err)
	}
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled.Store(true)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusRequestEntityTooLarge || authzCalled.Load() || upstreamCalled.Load() {
		t.Fatalf("status=%d authz=%v upstream=%v, want 413/false/false", rec.Code, authzCalled.Load(), upstreamCalled.Load())
	}
}

func TestExtAuthzRelayHeadersCannotBeSpoofedByAllowlist(t *testing.T) {
	t.Parallel()

	var gotMethod string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = strings.Join(r.Header.Values("X-Forwarded-Method"), ",")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	mw, err := NewExtAuthz(ExtAuthzConfig{
		URL: server.URL, ForwardHeaders: []string{"X-Forwarded-Method"}, Client: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewExtAuthz() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, "/", nil)
	req.Header.Set("X-Forwarded-Method", http.MethodDelete)
	mw(okHandler()).ServeHTTP(httptest.NewRecorder(), req)
	if gotMethod != http.MethodPut {
		t.Fatalf("X-Forwarded-Method = %q, want trusted %q", gotMethod, http.MethodPut)
	}
}

func TestExtAuthzCancellationNeverFailsOpen(t *testing.T) {
	t.Parallel()

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	mw, err := NewExtAuthz(ExtAuthzConfig{
		URL: "https://authz.example.test/check", FailOpen: true,
		Client: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatalf("NewExtAuthz() error = %v", err)
	}
	var upstreamCalled atomic.Bool
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled.Store(true)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	cancel()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || upstreamCalled.Load() {
		t.Fatalf("status=%d upstream=%v, want 503/false", rec.Code, upstreamCalled.Load())
	}
}

func TestExtAuthzRejectsInvalidRequestContracts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  ExtAuthzConfig
	}{
		{name: "method", cfg: ExtAuthzConfig{Method: http.MethodDelete}},
		{name: "body", cfg: ExtAuthzConfig{Body: "protobuf"}},
		{name: "get body", cfg: ExtAuthzConfig{Method: http.MethodGet, Body: ExtAuthzBodyMetadata}},
		{name: "negative limit", cfg: ExtAuthzConfig{MaxBodyBytes: -1}},
		{name: "content type without body", cfg: ExtAuthzConfig{ContentType: "application/json"}},
		{name: "invalid content type", cfg: ExtAuthzConfig{Method: http.MethodPost, Body: ExtAuthzBodyOriginal, ContentType: "bad\nvalue"}},
		{name: "metadata non-json", cfg: ExtAuthzConfig{Method: http.MethodPost, Body: ExtAuthzBodyMetadata, ContentType: "text/plain"}},
		{name: "invalid header", cfg: ExtAuthzConfig{ForwardHeaders: []string{"bad\nname"}}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.cfg.URL = "https://authz.example.test/check"
			if _, err := NewExtAuthz(tt.cfg); err == nil {
				t.Fatal("NewExtAuthz() error = nil")
			}
		})
	}
}

type countingReadCloser struct {
	io.Reader
	reads atomic.Int64
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	r.reads.Add(1)
	return r.Reader.Read(p)
}

func (*countingReadCloser) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
