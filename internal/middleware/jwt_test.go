package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTValidTokenPasses(t *testing.T) {
	t.Parallel()

	token := signJWT(t, "test-secret", time.Now().Add(5*time.Minute))
	mw, err := NewJWT(JWTConfig{Secret: "test-secret", Header: "Authorization"})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	called := false
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Fatal("expected downstream handler to be called")
	}
}

func TestJWTMissingTokenReturns401(t *testing.T) {
	t.Parallel()

	mw, err := NewJWT(JWTConfig{Secret: "test-secret", Header: "Authorization"})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secure", nil))

	assertUnauthorizedBody(t, rec)
}

func TestJWTMalformedTokenReturns401(t *testing.T) {
	t.Parallel()

	mw, err := NewJWT(JWTConfig{Secret: "test-secret", Header: "Authorization"})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer malformed.token.value")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assertUnauthorizedBody(t, rec)
}

func TestJWTExpiredTokenReturns401(t *testing.T) {
	t.Parallel()

	token := signJWT(t, "test-secret", time.Now().Add(-1*time.Minute))
	mw, err := NewJWT(JWTConfig{Secret: "test-secret", Header: "Authorization"})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assertUnauthorizedBody(t, rec)
}

func signJWT(t *testing.T, secret string, exp time.Time) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-1",
		"exp": exp.Unix(),
	})
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return signed
}

func assertUnauthorizedBody(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["error"] != "unauthorized" {
		t.Fatalf("error = %q, want unauthorized", body["error"])
	}
	if body["status"] != "error" {
		t.Fatalf("status = %q, want error", body["status"])
	}
}
