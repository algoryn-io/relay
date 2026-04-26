package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTValidTokenPasses(t *testing.T) {
	t.Parallel()

	secret := strings.Repeat("a", 32)
	token := signJWT(t, secret, time.Now().Add(5*time.Minute))
	mw, err := NewJWT(JWTConfig{Secret: secret, Header: "Authorization"})
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

	mw, err := NewJWT(JWTConfig{Secret: strings.Repeat("a", 32), Header: "Authorization"})
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

	mw, err := NewJWT(JWTConfig{Secret: strings.Repeat("a", 32), Header: "Authorization"})
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

	secret := strings.Repeat("a", 32)
	token := signJWT(t, secret, time.Now().Add(-1*time.Minute))
	mw, err := NewJWT(JWTConfig{Secret: secret, Header: "Authorization"})
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

func TestJWTMissingExpirationReturns401(t *testing.T) {
	t.Parallel()

	secret := strings.Repeat("a", 32)
	token := signJWTClaims(t, secret, jwt.MapClaims{
		"sub": "user-1",
	})
	mw, err := NewJWT(JWTConfig{Secret: secret, Header: "Authorization"})
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

func TestJWTFutureIssuedAtReturns401(t *testing.T) {
	t.Parallel()

	secret := strings.Repeat("a", 32)
	token := signJWTClaims(t, secret, jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Add(5 * time.Minute).Unix(),
	})
	mw, err := NewJWT(JWTConfig{Secret: secret, Header: "Authorization"})
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

func TestJWTInjectsAuthenticatedSubHeader(t *testing.T) {
	t.Parallel()

	secret := strings.Repeat("a", 32)
	token := signJWTClaims(t, secret, jwt.MapClaims{
		"sub": "user-123",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	mw, err := NewJWT(JWTConfig{Secret: secret, Header: "Authorization"})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	var gotSub string
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSub = r.Header.Get("X-Authenticated-Sub")
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotSub != "user-123" {
		t.Fatalf("X-Authenticated-Sub = %q, want user-123", gotSub)
	}
}

func TestJWTInjectsClaimMappedHeaders(t *testing.T) {
	t.Parallel()

	secret := strings.Repeat("a", 32)
	token := signJWTClaims(t, secret, jwt.MapClaims{
		"sub":  "user-999",
		"role": "admin",
		"exp":  time.Now().Add(5 * time.Minute).Unix(),
	})
	mw, err := NewJWT(JWTConfig{
		Secret: secret,
		Header: "Authorization",
		ClaimsToHeaders: map[string]string{
			"role": "X-Test-Role",
		},
	})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	var gotSub, gotRole string
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSub = r.Header.Get("X-Authenticated-Sub")
		gotRole = r.Header.Get("X-Test-Role")
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotSub != "user-999" {
		t.Fatalf("X-Authenticated-Sub = %q, want user-999", gotSub)
	}
	if gotRole != "admin" {
		t.Fatalf("X-Test-Role = %q, want admin", gotRole)
	}
}

func TestJWTMappedStripsClientSpoofBeforeInject(t *testing.T) {
	t.Parallel()

	secret := strings.Repeat("a", 32)
	token := signJWTClaims(t, secret, jwt.MapClaims{
		"sub":  "user-1",
		"role": "from-token",
		"exp":  time.Now().Add(5 * time.Minute).Unix(),
	})
	mw, err := NewJWT(JWTConfig{
		Secret: secret,
		Header: "Authorization",
		ClaimsToHeaders: map[string]string{
			"role": "X-Test-Role",
		},
	})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	var gotRole string
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRole = r.Header.Get("X-Test-Role")
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Test-Role", "spoofed")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotRole != "from-token" {
		t.Fatalf("X-Test-Role = %q, want from-token", gotRole)
	}
}

func TestJWTMappedWithSubInMapNoDefaultSubHeader(t *testing.T) {
	t.Parallel()

	secret := strings.Repeat("a", 32)
	token := signJWTClaims(t, secret, jwt.MapClaims{
		"sub": "id-from-jwt",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	mw, err := NewJWT(JWTConfig{
		Secret: secret,
		Header: "Authorization",
		ClaimsToHeaders: map[string]string{
			"sub": "X-Subject-Custom",
		},
	})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	var gotDefault, gotCustom string
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDefault = r.Header.Get("X-Authenticated-Sub")
		gotCustom = r.Header.Get("X-Subject-Custom")
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotDefault != "" {
		t.Fatalf("X-Authenticated-Sub = %q, want empty (mapped via claims_to_headers)", gotDefault)
	}
	if gotCustom != "id-from-jwt" {
		t.Fatalf("X-Subject-Custom = %q, want id-from-jwt", gotCustom)
	}
}

func TestJWTDefaultSubStripsClientSpoof(t *testing.T) {
	t.Parallel()

	secret := strings.Repeat("a", 32)
	token := signJWTClaims(t, secret, jwt.MapClaims{
		"sub": "token-sub",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	mw, err := NewJWT(JWTConfig{Secret: secret, Header: "Authorization"})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	var got string
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Authenticated-Sub")
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Authenticated-Sub", "spoofed")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got != "token-sub" {
		t.Fatalf("X-Authenticated-Sub = %q, want token-sub", got)
	}
}

func TestJWTRejectsShortSecret(t *testing.T) {
	t.Parallel()

	_, err := NewJWT(JWTConfig{Secret: "short-secret", Header: "Authorization"})
	if err == nil {
		t.Fatal("NewJWT() error = nil, want error")
	}
	if err.Error() != "jwt secret must be at least 32 bytes" {
		t.Fatalf("error = %q, want jwt secret must be at least 32 bytes", err.Error())
	}
}

func signJWT(t *testing.T, secret string, exp time.Time) string {
	t.Helper()

	return signJWTClaims(t, secret, jwt.MapClaims{
		"sub": "user-1",
		"exp": exp.Unix(),
	})
}

func signJWTClaims(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
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
