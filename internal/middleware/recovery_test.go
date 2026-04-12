package middleware

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoveryHandlesPanicAndReturns500(t *testing.T) {
	t.Parallel()

	handler := Chain(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("boom")
		}),
		Recovery(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panic", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["error"] != "internal_error" {
		t.Fatalf("error = %q, want internal_error", body["error"])
	}
}
