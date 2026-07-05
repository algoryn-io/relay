package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// oidcServerFixture starts a TLS server exposing both the OIDC discovery
// document and a JWKS endpoint backed by one RSA key. The discovery issuer is
// the server's own URL.
func oidcServerFixture(t *testing.T, kid string) (*rsa.PrivateKey, *httptest.Server) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	pairs := []*rsaKidPair{{kid: kid, priv: priv}}

	mux := http.NewServeMux()
	var baseURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   baseURL,
			"jwks_uri": baseURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(buildJWKS(pairs))
	})
	server := httptest.NewTLSServer(mux)
	baseURL = server.URL
	t.Cleanup(server.Close)
	return priv, server
}

func signRS256WithIssuer(t *testing.T, priv *rsa.PrivateKey, kid, iss string, exp time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user-oidc",
		"iss": iss,
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

func TestJWTOIDCDiscoveryValidToken(t *testing.T) {
	t.Parallel()

	priv, server := oidcServerFixture(t, "oidc-key")
	token := signRS256WithIssuer(t, priv, "oidc-key", server.URL, time.Now().Add(5*time.Minute))

	mw, err := NewJWT(JWTConfig{
		Algorithm:  "rs256",
		OIDCIssuer: server.URL,
		JWKSClient: server.Client(),
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

func TestJWTOIDCRejectsWrongIssuer(t *testing.T) {
	t.Parallel()

	priv, server := oidcServerFixture(t, "oidc-key")
	// Token minted with a different issuer must be rejected because ExpectedIssuer
	// defaults to the discovered issuer.
	token := signRS256WithIssuer(t, priv, "oidc-key", "https://evil.example.com", time.Now().Add(5*time.Minute))

	mw, err := NewJWT(JWTConfig{
		Algorithm:  "rs256",
		OIDCIssuer: server.URL,
		JWKSClient: server.Client(),
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

func TestJWTOIDCDiscoveryFailsClosedOnUnreachable(t *testing.T) {
	t.Parallel()

	priv, server := oidcServerFixture(t, "oidc-key")
	issuer := server.URL
	server.Close() // discovery endpoint is now unreachable

	_, err := NewJWT(JWTConfig{
		Algorithm:  "rs256",
		OIDCIssuer: issuer,
		JWKSClient: server.Client(),
	})
	if err == nil {
		t.Fatal("expected NewJWT to fail when discovery is unreachable")
	}
	_ = priv
}
