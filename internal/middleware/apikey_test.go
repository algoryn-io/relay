package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func okHandlerT(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func captureHeaderHandler(t *testing.T, header string, out *string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*out = r.Header.Get(header)
		w.WriteHeader(http.StatusOK)
	})
}

// TestAPIKeyValidKey verifies that a correct key in the default header passes.
func TestAPIKeyValidKey(t *testing.T) {
	t.Parallel()

	mw, err := NewAPIKey(APIKeyConfig{Keys: map[string]string{"sk-abc": "client-a"}})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "sk-abc")
	rr := httptest.NewRecorder()
	applyMiddleware(mw, okHandlerT(t)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestAPIKeyMissingKey verifies that a request without any key gets 401.
func TestAPIKeyMissingKey(t *testing.T) {
	t.Parallel()

	mw, err := NewAPIKey(APIKeyConfig{Keys: map[string]string{"sk-abc": "client-a"}})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	applyMiddleware(mw, okHandlerT(t)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

// TestAPIKeyInvalidKey verifies that an unrecognised key gets 401.
func TestAPIKeyInvalidKey(t *testing.T) {
	t.Parallel()

	mw, err := NewAPIKey(APIKeyConfig{Keys: map[string]string{"sk-abc": "client-a"}})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "sk-wrong")
	rr := httptest.NewRecorder()
	applyMiddleware(mw, okHandlerT(t)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

// TestAPIKeyCustomHeader verifies that a non-default header name works.
func TestAPIKeyCustomHeader(t *testing.T) {
	t.Parallel()

	mw, err := NewAPIKey(APIKeyConfig{
		KeyHeader: "Authorization",
		Keys:      map[string]string{"token-xyz": "svc-b"},
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "token-xyz")
	rr := httptest.NewRecorder()
	applyMiddleware(mw, okHandlerT(t)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestAPIKeyQueryParam verifies that the key can be supplied as a query parameter.
func TestAPIKeyQueryParam(t *testing.T) {
	t.Parallel()

	mw, err := NewAPIKey(APIKeyConfig{
		KeyQuery: "api_key",
		Keys:     map[string]string{"sk-qp": "client-q"},
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/?api_key=sk-qp", nil)
	rr := httptest.NewRecorder()
	applyMiddleware(mw, okHandlerT(t)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestAPIKeyHeaderTakesPriorityOverQuery ensures the header is checked first.
func TestAPIKeyHeaderTakesPriorityOverQuery(t *testing.T) {
	t.Parallel()

	mw, err := NewAPIKey(APIKeyConfig{
		KeyQuery: "api_key",
		Keys:     map[string]string{"sk-good": "c1", "sk-bad": "c2"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Header has valid key; query has invalid key → should pass.
	req := httptest.NewRequest(http.MethodGet, "/?api_key=sk-bad", nil)
	req.Header.Set("X-API-Key", "sk-good")
	rr := httptest.NewRecorder()
	applyMiddleware(mw, okHandlerT(t)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestAPIKeyQueryDisabled verifies that when KeyQuery is empty, query params are ignored.
func TestAPIKeyQueryDisabled(t *testing.T) {
	t.Parallel()

	mw, err := NewAPIKey(APIKeyConfig{Keys: map[string]string{"sk-abc": "c1"}})
	if err != nil {
		t.Fatal(err)
	}

	// Key only in query param (not in header); KeyQuery is empty → must reject.
	req := httptest.NewRequest(http.MethodGet, "/?X-API-Key=sk-abc", nil)
	rr := httptest.NewRecorder()
	applyMiddleware(mw, okHandlerT(t)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

// TestAPIKeyToHeader verifies that the matched caller ID is forwarded upstream.
func TestAPIKeyToHeader(t *testing.T) {
	t.Parallel()

	var upstreamID string
	mw, err := NewAPIKey(APIKeyConfig{
		Keys:        map[string]string{"sk-secret": "my-service"},
		KeyToHeader: "X-Caller-ID",
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "sk-secret")
	rr := httptest.NewRecorder()
	applyMiddleware(mw, captureHeaderHandler(t, "X-Caller-ID", &upstreamID)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if upstreamID != "my-service" {
		t.Errorf("X-Caller-ID = %q, want %q", upstreamID, "my-service")
	}
}

// TestAPIKeyToHeaderNotSetWhenDisabled verifies KeyToHeader is a no-op when empty.
func TestAPIKeyToHeaderNotSetWhenDisabled(t *testing.T) {
	t.Parallel()

	var upstreamID string
	mw, err := NewAPIKey(APIKeyConfig{
		Keys: map[string]string{"sk-x": "svc"},
		// KeyToHeader intentionally empty
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "sk-x")
	rr := httptest.NewRecorder()
	applyMiddleware(mw, captureHeaderHandler(t, "X-Caller-ID", &upstreamID)).ServeHTTP(rr, req)

	if upstreamID != "" {
		t.Errorf("X-Caller-ID = %q, want empty", upstreamID)
	}
}

// TestAPIKeyNewAPIKeyEmptyKeysError verifies that NewAPIKey rejects an empty map.
func TestAPIKeyNewAPIKeyEmptyKeysError(t *testing.T) {
	t.Parallel()

	_, err := NewAPIKey(APIKeyConfig{Keys: map[string]string{}})
	if err == nil {
		t.Error("expected error for empty key map, got nil")
	}
}

// TestLoadAPIKeysFromEnvString verifies comma-separated and newline-separated parsing.
func TestLoadAPIKeysFromEnvString(t *testing.T) {
	t.Parallel()

	keys, err := LoadAPIKeys("svc-a:sk-111,svc-b:sk-222\nsvc-c:sk-333", "")
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"sk-111": "svc-a",
		"sk-222": "svc-b",
		"sk-333": "svc-c",
	}
	for secret, wantID := range cases {
		if got := keys[secret]; got != wantID {
			t.Errorf("keys[%q] = %q, want %q", secret, got, wantID)
		}
	}
}

// TestLoadAPIKeysFromFile verifies loading from a keys file.
func TestLoadAPIKeysFromFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	f := filepath.Join(dir, "keys.txt")
	if err := os.WriteFile(f, []byte("svc-x:sk-aaa\nsvc-y:sk-bbb\n"), 0600); err != nil {
		t.Fatal(err)
	}

	keys, err := LoadAPIKeys("", f)
	if err != nil {
		t.Fatal(err)
	}

	if keys["sk-aaa"] != "svc-x" {
		t.Errorf("keys[sk-aaa] = %q, want svc-x", keys["sk-aaa"])
	}
	if keys["sk-bbb"] != "svc-y" {
		t.Errorf("keys[sk-bbb] = %q, want svc-y", keys["sk-bbb"])
	}
}

// TestLoadAPIKeysMissingFileError verifies that a missing keys file returns an error.
func TestLoadAPIKeysMissingFileError(t *testing.T) {
	t.Parallel()

	_, err := LoadAPIKeys("", "/nonexistent/path/keys.txt")
	if err == nil {
		t.Error("expected error for missing keys file, got nil")
	}
}

// TestLoadAPIKeysEntryWithoutID verifies "secret-only" entries use secret as ID.
func TestLoadAPIKeysEntryWithoutID(t *testing.T) {
	t.Parallel()

	keys, err := LoadAPIKeys("raw-secret-key", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := keys["raw-secret-key"]; got != "raw-secret-key" {
		t.Errorf("id = %q, want raw-secret-key", got)
	}
}

// TestAPIKeyMultipleKeys verifies that multiple valid keys all work independently.
func TestAPIKeyMultipleKeys(t *testing.T) {
	t.Parallel()

	mw, err := NewAPIKey(APIKeyConfig{
		Keys: map[string]string{
			"sk-one": "client-1",
			"sk-two": "client-2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"sk-one", "sk-two"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", key)
		rr := httptest.NewRecorder()
		applyMiddleware(mw, okHandlerT(t)).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("key %q: status = %d, want 200", key, rr.Code)
		}
	}
}

// applyMiddleware wraps handler with mw for test use.
func applyMiddleware(mw Middleware, h http.Handler) http.Handler {
	return mw(h)
}
