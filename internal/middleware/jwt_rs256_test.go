package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ── RS256 static key ──────────────────────────────────────────────────────────

func TestJWTRS256ValidTokenPasses(t *testing.T) {
	t.Parallel()

	priv, pemPath := rsaKeyFixture(t)
	token := signRS256(t, priv, "kid-1", time.Now().Add(5*time.Minute))

	mw, err := NewJWT(JWTConfig{
		Algorithm:     "rs256",
		PublicKeyFile: pemPath,
		Header:        "Authorization",
	})
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
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Fatal("downstream handler not called")
	}
}

func TestJWTRS256ExpiredTokenReturns401(t *testing.T) {
	t.Parallel()

	priv, pemPath := rsaKeyFixture(t)
	token := signRS256(t, priv, "kid-1", time.Now().Add(-time.Minute))

	mw, err := NewJWT(JWTConfig{Algorithm: "rs256", PublicKeyFile: pemPath})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	Chain(okHandler(), mw).ServeHTTP(rec, req)

	assertUnauthorizedBody(t, rec)
}

func TestJWTRS256WrongKeyReturns401(t *testing.T) {
	t.Parallel()

	priv, _ := rsaKeyFixture(t)          // key used to sign
	_, pemPath := rsaKeyFixture(t)        // different key for verification

	token := signRS256(t, priv, "kid-1", time.Now().Add(5*time.Minute))

	mw, err := NewJWT(JWTConfig{Algorithm: "rs256", PublicKeyFile: pemPath})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	Chain(okHandler(), mw).ServeHTTP(rec, req)

	assertUnauthorizedBody(t, rec)
}

func TestJWTRS256MissingPEMFileErrors(t *testing.T) {
	t.Parallel()

	_, err := NewJWT(JWTConfig{
		Algorithm:     "rs256",
		PublicKeyFile: "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("expected error for missing PEM file, got nil")
	}
}

// ── RS256 via JWKS ────────────────────────────────────────────────────────────

func TestJWTJWKSValidTokenPasses(t *testing.T) {
	t.Parallel()

	priv, jwksServer := jwksServerFixture(t, "key-1")
	token := signRS256(t, priv, "key-1", time.Now().Add(5*time.Minute))

	mw, err := NewJWT(JWTConfig{
		Algorithm:    "rs256",
		JWKSUrl:      jwksServer.URL + "/jwks",
		JWKSCacheTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	Chain(okHandler(), mw).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestJWTJWKSUnknownKidReturns401(t *testing.T) {
	t.Parallel()

	priv, _ := rsaKeyFixture(t)
	_, jwksServer := jwksServerFixture(t, "key-registered")
	// Token signed with a kid not in the JWKS
	token := signRS256(t, priv, "key-unknown", time.Now().Add(5*time.Minute))

	mw, err := NewJWT(JWTConfig{
		Algorithm: "rs256",
		JWKSUrl:   jwksServer.URL + "/jwks",
	})
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	Chain(okHandler(), mw).ServeHTTP(rec, req)

	assertUnauthorizedBody(t, rec)
}

func TestJWTJWKSCacheRefreshOnKidMiss(t *testing.T) {
	t.Parallel()

	priv1, _ := rsaKeyFixture(t)
	priv2, _ := rsaKeyFixture(t)

	// Start server with only key-1; token uses key-2.
	var currentKeys []*rsaKidPair
	currentKeys = []*rsaKidPair{{kid: "key-1", priv: priv1}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(buildJWKS(currentKeys))
	}))
	t.Cleanup(server.Close)

	// Very short TTL so the cache expires quickly.
	cache := newJWKSCache(server.URL, 50*time.Millisecond)

	// Prime the cache with key-1.
	_, _ = cache.getKey("key-1")

	// Rotate server keys to include key-2.
	currentKeys = append(currentKeys, &rsaKidPair{kid: "key-2", priv: priv2})

	// Wait for TTL to expire.
	time.Sleep(60 * time.Millisecond)

	// Token signed with key-2 should resolve after a cache refresh.
	token := signRS256(t, priv2, "key-2", time.Now().Add(5*time.Minute))
	parsed, err := jwt.Parse(token, cache.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !parsed.Valid {
		t.Fatalf("expected valid token after cache refresh, err=%v", err)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

type rsaKidPair struct {
	kid  string
	priv *rsa.PrivateKey
}

// rsaKeyFixture generates a 2048-bit RSA key and writes the public key PEM to a
// temp file. Returns the private key and the path to the PEM file.
func rsaKeyFixture(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return priv, path
}

// jwksServerFixture creates an httptest server exposing a /jwks endpoint with
// one RSA key identified by kid. Returns the private key and the server.
func jwksServerFixture(t *testing.T, kid string) (*rsa.PrivateKey, *httptest.Server) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	pairs := []*rsaKidPair{{kid: kid, priv: priv}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(buildJWKS(pairs))
	}))
	t.Cleanup(server.Close)
	return priv, server
}

func buildJWKS(pairs []*rsaKidPair) map[string]any {
	keys := make([]map[string]any, 0, len(pairs))
	for _, p := range pairs {
		keys = append(keys, map[string]any{
			"kty": "RSA",
			"kid": p.kid,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(p.priv.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.priv.PublicKey.E)).Bytes()),
		})
	}
	return map[string]any{"keys": keys}
}

func signRS256(t *testing.T, priv *rsa.PrivateKey, kid string, exp time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user-rs256",
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
	})
	token.Header["kid"] = kid
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString(RS256) error = %v", err)
	}
	return signed
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}
