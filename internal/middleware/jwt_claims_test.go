package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newHS256(t *testing.T, cfg JWTConfig) Middleware {
	t.Helper()
	cfg.Algorithm = "hs256"
	mw, err := NewJWT(cfg)
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}
	return mw
}

func TestJWTRejectsWrongIssuer(t *testing.T) {
	t.Parallel()
	secret := strings.Repeat("a", 32)
	mw := newHS256(t, JWTConfig{Secret: secret, ExpectedIssuer: "https://idp.trusted"})

	token := signJWTClaims(t, secret, jwt.MapClaims{
		"sub": "user-1",
		"iss": "https://idp.evil",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	Chain(okHandler(), mw).ServeHTTP(rec, req)

	assertUnauthorizedBody(t, rec)
}

func TestJWTAcceptsMatchingIssuerAndAudience(t *testing.T) {
	t.Parallel()
	secret := strings.Repeat("a", 32)
	mw := newHS256(t, JWTConfig{
		Secret:           secret,
		ExpectedIssuer:   "https://idp.trusted",
		ExpectedAudience: "relay",
	})

	token := signJWTClaims(t, secret, jwt.MapClaims{
		"sub": "user-1",
		"iss": "https://idp.trusted",
		"aud": "relay",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	Chain(okHandler(), mw).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestJWTRejectsWrongAudience(t *testing.T) {
	t.Parallel()
	secret := strings.Repeat("a", 32)
	mw := newHS256(t, JWTConfig{Secret: secret, ExpectedAudience: "relay"})

	token := signJWTClaims(t, secret, jwt.MapClaims{
		"sub": "user-1",
		"aud": "some-other-service",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	Chain(okHandler(), mw).ServeHTTP(rec, req)

	assertUnauthorizedBody(t, rec)
}

func TestJWTJWKSRejectsPlaintextURL(t *testing.T) {
	t.Parallel()
	_, err := NewJWT(JWTConfig{
		Algorithm: "rs256",
		JWKSUrl:   "http://idp.example/jwks",
	})
	if err == nil {
		t.Fatal("expected error for non-https jwks_url, got nil")
	}
}
