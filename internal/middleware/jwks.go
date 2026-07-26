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
const maxJWKSStaleGrace = 24 * time.Hour

// maxJWKSBytes caps the JWKS response body. A JWKS document is a handful of keys;
// the cap prevents a hostile or misconfigured endpoint from streaming an
// oversized body and exhausting memory.
const maxJWKSBytes = 1 << 20 // 1 MB

// minRSAKeyBits is the smallest RSA modulus accepted from a JWKS endpoint.
// Anything weaker is rejected so a downgraded/forged small key cannot be trusted.
const minRSAKeyBits = 2048

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type retiredJWKSKey struct {
	key       *rsa.PublicKey
	retiredAt time.Time
}

// jwksCache fetches RSA public keys from a JWKS endpoint and caches them by kid.
// ttl controls refresh frequency. staleGrace is a separate, opt-in availability
// window for keys removed by a successful refresh and for active keys when a
// refresh fails. Both windows are measured from successful refresh timestamps.
type jwksCache struct {
	mu                    sync.Mutex
	keys                  map[string]*rsa.PublicKey
	retired               map[string]retiredJWKSKey
	lastSuccessfulRefresh time.Time
	ttl                   time.Duration
	staleGrace            time.Duration
	url                   string
	client                *http.Client
	now                   func() time.Time
}

func newJWKSCache(url string, ttl, staleGrace time.Duration, client *http.Client) *jwksCache {
	if ttl <= 0 {
		ttl = defaultJWKSCacheTTL
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &jwksCache{
		url:        url,
		ttl:        ttl,
		staleGrace: staleGrace,
		keys:       make(map[string]*rsa.PublicKey),
		retired:    make(map[string]retiredJWKSKey),
		client:     client,
		now:        time.Now,
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
	now := c.now()
	key, active := c.keys[kid]
	retired, retiredOK := c.retired[kid]
	fresh := c.isFreshLocked(now)
	retiredValid := retiredOK && c.retiredKeyValidLocked(retired, now)
	observedRefresh := c.lastSuccessfulRefresh
	c.mu.Unlock()

	if active && fresh {
		return key, nil
	}
	if retiredValid && fresh {
		return retired.key, nil
	}
	if fresh {
		// The current set is authoritative until its refresh TTL. Avoid turning
		// attacker-controlled unknown kids into unbounded requests to the IdP.
		return nil, fmt.Errorf("jwks: kid %q not found", kid)
	}

	if err := c.refresh(observedRefresh); err != nil {
		c.mu.Lock()
		defer c.mu.Unlock()

		now = c.now()
		// A failed fetch never advances lastSuccessfulRefresh. Active stale keys
		// therefore stop being accepted at last success + TTL + grace, even if
		// every later refresh attempt fails.
		if key, ok := c.keys[kid]; ok && c.staleSetValidLocked(now) {
			return key, nil
		}
		if retired, ok := c.retired[kid]; ok &&
			c.retiredKeyValidLocked(retired, now) &&
			c.staleSetValidLocked(now) {
			return retired.key, nil
		}
		return nil, fmt.Errorf("jwks: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if key, ok := c.keys[kid]; ok {
		return key, nil
	}
	if retired, ok := c.retired[kid]; ok && c.retiredKeyValidLocked(retired, c.now()) {
		return retired.key, nil
	}
	return nil, fmt.Errorf("jwks: kid %q not found", kid)
}

func (c *jwksCache) isFreshLocked(now time.Time) bool {
	return !c.lastSuccessfulRefresh.IsZero() &&
		now.Sub(c.lastSuccessfulRefresh) <= c.ttl
}

func (c *jwksCache) staleSetValidLocked(now time.Time) bool {
	return c.staleGrace > 0 &&
		!c.lastSuccessfulRefresh.IsZero() &&
		now.Sub(c.lastSuccessfulRefresh) <= c.ttl+c.staleGrace
}

func (c *jwksCache) retiredKeyValidLocked(retired retiredJWKSKey, now time.Time) bool {
	return c.staleGrace > 0 && now.Sub(retired.retiredAt) <= c.staleGrace
}

func (c *jwksCache) refresh(observedRefresh time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check after acquiring the lock so concurrent requests that observed the
	// same expired set coalesce into one refresh.
	if !c.lastSuccessfulRefresh.Equal(observedRefresh) {
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

	refreshedAt := c.now()
	for kid, key := range c.keys {
		if _, stillActive := newKeys[kid]; !stillActive && c.staleGrace > 0 {
			c.retired[kid] = retiredJWKSKey{key: key, retiredAt: refreshedAt}
		}
	}
	for kid := range newKeys {
		delete(c.retired, kid)
	}
	for kid, retired := range c.retired {
		if !c.retiredKeyValidLocked(retired, refreshedAt) {
			delete(c.retired, kid)
		}
	}

	c.keys = newKeys
	c.lastSuccessfulRefresh = refreshedAt
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
