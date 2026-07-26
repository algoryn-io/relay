package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestJSONBodyTransformRequestRenameAddRemove(t *testing.T) {
	t.Parallel()

	mw := mustJSONBodyTransform(t, JSONBodyTransformConfig{
		MaxBytes:     1024,
		ContentTypes: []string{"application/json"},
		Request: JSONBodyOps{
			Rename: map[string]string{"user_id": "id"},
			Add:    map[string]any{"source": "relay"},
			Remove: []string{"password"},
		},
	})

	var got map[string]any
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		if cl := r.Header.Get("Content-Length"); cl != strconv.Itoa(len(body)) {
			t.Fatalf("Content-Length = %q, want %d", cl, len(body))
		}
		w.WriteHeader(http.StatusNoContent)
	}), mw)

	req := httptest.NewRequest(http.MethodPost, "/v1", bytes.NewBufferString(`{"user_id":"u1","password":"secret","keep":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got["id"] != "u1" {
		t.Fatalf("id = %v, want u1", got["id"])
	}
	if _, ok := got["user_id"]; ok {
		t.Fatal("user_id should have been renamed away")
	}
	if _, ok := got["password"]; ok {
		t.Fatal("password should have been removed")
	}
	if got["source"] != "relay" {
		t.Fatalf("source = %v, want relay", got["source"])
	}
	if got["keep"] != true {
		t.Fatalf("keep = %v, want true", got["keep"])
	}
}

func TestJSONBodyTransformSkipsNonJSONContentTypeWithoutBuffering(t *testing.T) {
	t.Parallel()

	mw := mustJSONBodyTransform(t, JSONBodyTransformConfig{
		MaxBytes:     1024,
		ContentTypes: []string{"application/json"},
		Request: JSONBodyOps{
			Remove: []string{"password"},
		},
	})

	original := `{"password":"secret"}`
	body := &readTrackingBody{Reader: strings.NewReader(original)}
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body.read {
			t.Fatal("expected body not to be read for non-JSON content type")
		}
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if string(buf) != original {
			t.Fatalf("body = %q, want original", string(buf))
		}
		w.WriteHeader(http.StatusNoContent)
	}), mw)

	req := httptest.NewRequest(http.MethodPost, "/v1", body)
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len(original))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestJSONBodyTransformSkipsStreamingRequestWithoutBuffering(t *testing.T) {
	t.Parallel()

	mw := mustJSONBodyTransform(t, JSONBodyTransformConfig{
		MaxBytes:     1024,
		ContentTypes: []string{"application/json"},
		Request: JSONBodyOps{
			Remove: []string{"password"},
		},
	})

	original := `{"password":"secret"}`
	body := &readTrackingBody{Reader: strings.NewReader(original)}
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body.read {
			t.Fatal("expected streaming body not to be buffered by transform")
		}
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if string(buf) != original {
			t.Fatalf("body = %q, want original", string(buf))
		}
		w.WriteHeader(http.StatusNoContent)
	}), mw)

	req := httptest.NewRequest(http.MethodPost, "/v1", body)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestJSONBodyTransformInvalidRequestJSON(t *testing.T) {
	t.Parallel()

	mw := mustJSONBodyTransform(t, JSONBodyTransformConfig{
		MaxBytes:     1024,
		ContentTypes: []string{"application/json"},
		Request:      JSONBodyOps{Add: map[string]any{"v": 1}},
	})

	called := false
	handler := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}), mw)

	req := httptest.NewRequest(http.MethodPost, "/v1", bytes.NewBufferString(`{"broken"`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if called {
		t.Fatal("downstream should not be called for invalid JSON")
	}
	if !strings.Contains(rec.Body.String(), "json_body_invalid") {
		t.Fatalf("body = %q, want json_body_invalid", rec.Body.String())
	}
}

func TestJSONBodyTransformLeavesNonObjectJSONUntouched(t *testing.T) {
	t.Parallel()

	mw := mustJSONBodyTransform(t, JSONBodyTransformConfig{
		MaxBytes:     1024,
		ContentTypes: []string{"application/json"},
		Request:      JSONBodyOps{Add: map[string]any{"v": 1}},
	})

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if string(body) != `[1,2,3]` {
			t.Fatalf("body = %q, want array unchanged", string(body))
		}
		w.WriteHeader(http.StatusNoContent)
	}), mw)

	req := httptest.NewRequest(http.MethodPost, "/v1", bytes.NewBufferString(`[1,2,3]`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestJSONBodyTransformResponse(t *testing.T) {
	t.Parallel()

	mw := mustJSONBodyTransform(t, JSONBodyTransformConfig{
		MaxBytes:     1024,
		ContentTypes: []string{"application/json"},
		Response: JSONBodyOps{
			Rename: map[string]string{"internal_id": "id"},
			Remove: []string{"secret"},
			Add:    map[string]any{"gateway": true},
		},
	})

	payload := `{"internal_id":"x","secret":"nope","ok":1}`
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(payload))
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/v1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v body=%q", err, rec.Body.String())
	}
	if got["id"] != "x" {
		t.Fatalf("id = %v, want x", got["id"])
	}
	if _, ok := got["internal_id"]; ok {
		t.Fatal("internal_id should be renamed")
	}
	if _, ok := got["secret"]; ok {
		t.Fatal("secret should be removed")
	}
	if got["gateway"] != true {
		t.Fatalf("gateway = %v, want true", got["gateway"])
	}
}

func TestJSONBodyTransformResponseStreamingPassthrough(t *testing.T) {
	t.Parallel()

	mw := mustJSONBodyTransform(t, JSONBodyTransformConfig{
		MaxBytes:     1024,
		ContentTypes: []string{"application/json"},
		Response: JSONBodyOps{
			Remove: []string{"secret"},
		},
	})

	payload := `{"secret":"nope"}`
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// No Content-Length => streaming / unknown size => no buffer/transform.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(payload))
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/v1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Body.String() != payload {
		t.Fatalf("body = %q, want unmodified streaming payload", rec.Body.String())
	}
}

func TestJSONBodyTransformRequiresBounds(t *testing.T) {
	t.Parallel()

	if _, err := NewJSONBodyTransform(JSONBodyTransformConfig{
		ContentTypes: []string{"application/json"},
		Request:      JSONBodyOps{Remove: []string{"a"}},
	}); err == nil {
		t.Fatal("expected error for missing max_bytes")
	}
	if _, err := NewJSONBodyTransform(JSONBodyTransformConfig{
		MaxBytes: 10,
		Request:  JSONBodyOps{Remove: []string{"a"}},
	}); err == nil {
		t.Fatal("expected error for missing content_types")
	}
	if _, err := NewJSONBodyTransform(JSONBodyTransformConfig{
		MaxBytes:     10,
		ContentTypes: []string{"application/json"},
	}); err == nil {
		t.Fatal("expected error for empty transforms")
	}
}

func TestApplyJSONBodyOpsOrder(t *testing.T) {
	t.Parallel()

	out, ok, err := applyJSONBodyOps([]byte(`{"a":1,"b":2}`), JSONBodyOps{
		Rename: map[string]string{"a": "b"},
		Remove: []string{"b"},
		Add:    map[string]any{"b": 9, "c": 3},
	})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !ok {
		t.Fatal("expected object transform")
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	// rename a→b, remove b (the renamed value), add b=9 and c=3
	if got["b"] != float64(9) {
		t.Fatalf("b = %v, want 9", got["b"])
	}
	if got["c"] != float64(3) {
		t.Fatalf("c = %v, want 3", got["c"])
	}
	if _, ok := got["a"]; ok {
		t.Fatal("a should be gone after rename")
	}
}

type readTrackingBody struct {
	io.Reader
	read bool
}

func (b *readTrackingBody) Read(p []byte) (int, error) {
	b.read = true
	return b.Reader.Read(p)
}

func (b *readTrackingBody) Close() error { return nil }

func mustJSONBodyTransform(t *testing.T, cfg JSONBodyTransformConfig) Middleware {
	t.Helper()
	mw, err := NewJSONBodyTransform(cfg)
	if err != nil {
		t.Fatalf("NewJSONBodyTransform() error = %v", err)
	}
	return mw
}
