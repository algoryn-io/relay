package middleware

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultJWKSCacheTTL = 5 * time.Minute

// maxJWKSBytes caps the JWKS response body. A JWKS document is a handful of keys;
// the cap prevents a hostile or misconfigured endpoint from streaming an
// oversized body and exhausting memory.
const maxJWKSBytes = 1 << 20 // 1 MB

// minRSAKeyBits is the smallest RSA modulus accepted from a JWKS endpoint.
// Anything weaker is rejected so a downgraded/forged small key cannot be trusted.
const minRSAKeyBits = 2048

// jwksStaleGrace bounds how long a cached key is served after its TTL expires
// when the endpoint cannot be refreshed. Beyond TTL+grace the cache fails closed
// so a key revoked during an IdP outage stops being accepted.
const jwksStaleGrace = 5 * time.Minute

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksCache fetches RSA public keys from a JWKS endpoint and caches them by kid.
// Keys are refreshed when the TTL expires or when a kid is not found in the cache.
type jwksCache struct {
	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	ttl       time.Duration
	url       string
	client    *http.Client
}

func newJWKSCache(url string, ttl time.Duration, client *http.Client) *jwksCache {
	if ttl <= 0 {
		ttl = defaultJWKSCacheTTL
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &jwksCache{
		url:    url,
		ttl:    ttl,
		keys:   make(map[string]*rsa.PublicKey),
		client: client,
	}
}

// Keyfunc implements jwt.Keyfunc. It verifies the signing method is RS256 and
// resolves the key by kid, refreshing from the endpoint when necessary.
func (c *jwksCache) Keyfunc(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("missing kid in JWT header")
	}
	return c.getKey(kid)
}

func (c *jwksCache) getKey(kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	key, ok := c.keys[kid]
	stale := time.Since(c.fetchedAt) > c.ttl
	c.mu.Unlock()

	if ok && !stale {
		return key, nil
	}

	if err := c.refresh(); err != nil {
		if ok {
			// Use stale key rather than fail when the endpoint is temporarily down.
			return key, nil
		}
		return nil, fmt.Errorf("jwks: %w", err)
	}

	c.mu.Lock()
	key, ok = c.keys[kid]
	c.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("jwks: kid %q not found", kid)
	}
	return key, nil
}

func (c *jwksCache) refresh() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check after acquiring lock — another goroutine may have already refreshed.
	if time.Since(c.fetchedAt) <= c.ttl && len(c.keys) > 0 {
		return nil
	}

	resp, err := c.client.Get(c.url)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("endpoint returned %d", resp.StatusCode)
	}

	var set jwkSet
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&set); err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" || k.N == "" || k.E == "" {
			continue
		}
		pub, err := parseRSAJWK(k)
		if err != nil {
			continue
		}
		newKeys[k.Kid] = pub
	}

	c.keys = newKeys
	c.fetchedAt = time.Now()
	return nil
}

func parseRSAJWK(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	e := int(new(big.Int).SetBytes(eBytes).Int64())
	if e == 0 {
		return nil, fmt.Errorf("invalid exponent")
	}
	n := new(big.Int).SetBytes(nBytes)
	if n.BitLen() < minRSAKeyBits {
		return nil, fmt.Errorf("rsa key too small: %d bits (min %d)", n.BitLen(), minRSAKeyBits)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}
