package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// introspectionServer returns a TLS server that validates client credentials and
// responds per the provided handler. calls counts requests reaching it.
func introspectionServer(t *testing.T, calls *atomic.Int64, respond func(token string) introspectionResponse) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		id, secret, ok := r.BasicAuth()
		if !ok || id != "relay" || secret != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(respond(r.PostFormValue("token")))
	}))
	t.Cleanup(server.Close)
	return server
}

func newIntrospection(t *testing.T, server *httptest.Server, scopes []string, ttl time.Duration, now func() time.Time) Middleware {
	t.Helper()
	mw, err := NewIntrospection(IntrospectionConfig{
		URL:            server.URL,
		ClientID:       "relay",
		ClientSecret:   "s3cret",
		RequiredScopes: scopes,
		CacheTTL:       ttl,
		Client:         server.Client(),
		Now:            now,
	})
	if err != nil {
		t.Fatalf("NewIntrospection() error = %v", err)
	}
	return mw
}

func TestIntrospectionActiveTokenPasses(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	server := introspectionServer(t, &calls, func(token string) introspectionResponse {
		return introspectionResponse{
			Active: true, Sub: "user-1", Scope: "read write",
			TenantID: "tenant-1", ClientID: "client-1",
		}
	})
	mw := newIntrospection(t, server, nil, time.Minute, nil)

	var gotSub, gotScope string
	var identity AuthIdentity
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSub = r.Header.Get(defaultSubjectHeader)
		gotScope = r.Header.Get(tokenScopeHeader)
		identity, _ = authIdentityFromRequest(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer opaque-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotSub != "user-1" {
		t.Fatalf("injected sub = %q, want user-1", gotSub)
	}
	if gotScope != "read write" {
		t.Fatalf("injected scope = %q, want 'read write'", gotScope)
	}
	if identity.Source != "oauth2" || identity.Subject != "user-1" ||
		identity.Tenant != "tenant-1" || identity.KeyID != "client-1" {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestIntrospectionInactiveTokenRejected(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	server := introspectionServer(t, &calls, func(token string) introspectionResponse {
		return introspectionResponse{Active: false}
	})
	mw := newIntrospection(t, server, nil, time.Minute, nil)

	h := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer dead-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestIntrospectionMissingTokenRejected(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	server := introspectionServer(t, &calls, func(token string) introspectionResponse {
		return introspectionResponse{Active: true}
	})
	mw := newIntrospection(t, server, nil, time.Minute, nil)

	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if calls.Load() != 0 {
		t.Fatalf("introspection calls = %d, want 0 (no token, no call)", calls.Load())
	}
}

func TestIntrospectionInsufficientScope(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	server := introspectionServer(t, &calls, func(token string) introspectionResponse {
		return introspectionResponse{Active: true, Sub: "u", Scope: "read"}
	})
	mw := newIntrospection(t, server, []string{"read", "admin"}, time.Minute, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestIntrospectionCachesPositiveResult(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	server := introspectionServer(t, &calls, func(token string) introspectionResponse {
		return introspectionResponse{Active: true, Sub: "u", Scope: "read"}
	})
	now := time.Unix(5_000_000, 0)
	mw := newIntrospection(t, server, nil, time.Minute, func() time.Time { return now })
	h := mw(okHandler())

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer same-token")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if calls.Load() != 1 {
		t.Fatalf("introspection calls = %d, want 1 (result should be cached)", calls.Load())
	}
}

func TestIntrospectionFailsClosedOnUnreachable(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	server := introspectionServer(t, &calls, func(token string) introspectionResponse {
		return introspectionResponse{Active: true}
	})
	mw := newIntrospection(t, server, nil, time.Minute, nil)
	server.Close() // now unreachable

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail closed)", rec.Code)
	}
}
