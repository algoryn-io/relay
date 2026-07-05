package middleware

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxOIDCDiscoveryBytes caps the OpenID discovery document size. The document is
// a small JSON object; the cap prevents a hostile endpoint from streaming an
// oversized body.
const maxOIDCDiscoveryBytes = 1 << 20 // 1 MB

// oidcDiscovery is the subset of the OpenID Provider configuration document
// (RFC 8414 / OpenID Connect Discovery) that Relay consumes.
type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// discoverOIDC fetches <issuer>/.well-known/openid-configuration and returns the
// provider's issuer identifier and JWKS URI. The JWKS URI must be https so the
// signing keys cannot be substituted in transit.
func discoverOIDC(issuer string, client *http.Client) (*oidcDiscovery, error) {
	base := strings.TrimRight(strings.TrimSpace(issuer), "/")
	if u, err := url.Parse(base); err != nil || !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("oidc_issuer must be an https URL")
	}
	wellKnown := base + "/.well-known/openid-configuration"

	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Get(wellKnown)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned %d", resp.StatusCode)
	}

	var doc oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOIDCDiscoveryBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}
	if u, err := url.Parse(strings.TrimSpace(doc.JWKSURI)); err != nil || !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("discovery jwks_uri must be an https URL")
	}
	return &doc, nil
}

// newJWTOIDC resolves the JWKS URI from the issuer's discovery document and then
// verifies RS256 tokens against that JWKS. When ExpectedIssuer is not explicitly
// configured, it defaults to the discovered issuer so tokens minted by a
// different provider are rejected.
func newJWTOIDC(cfg JWTConfig, claimsToHeaders map[string]string) (Middleware, error) {
	doc, err := discoverOIDC(cfg.OIDCIssuer, cfg.JWKSClient)
	if err != nil {
		return nil, fmt.Errorf("jwt: oidc discovery: %w", err)
	}
	cfg.JWKSUrl = doc.JWKSURI
	if strings.TrimSpace(cfg.ExpectedIssuer) == "" {
		cfg.ExpectedIssuer = strings.TrimSpace(doc.Issuer)
	}
	if cfg.Logger != nil {
		cfg.Logger.Info("jwt middleware resolved OIDC discovery",
			"oidc_issuer", cfg.OIDCIssuer,
			"jwks_uri", doc.JWKSURI,
			"expected_issuer", cfg.ExpectedIssuer,
		)
	}
	return newJWTJWKS(cfg, claimsToHeaders)
}
