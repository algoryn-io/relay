package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"algoryn.io/relay/internal/httpx"
)

const defaultIntrospectionCacheTTL = 60 * time.Second
const defaultIntrospectionTimeout = 5 * time.Second
const maxIntrospectionCacheEntries = 10000
const maxIntrospectionBodyBytes = 1 << 20 // 1 MB

// tokenScopeHeader carries the granted scopes to the backend after a successful
// introspection. Like the subject header, any client-supplied value is stripped
// first so it cannot be spoofed.
// #nosec G101 -- this constant is an HTTP header name, not a credential.
const tokenScopeHeader = "X-Token-Scope"

// IntrospectionConfig configures the OAuth2 token introspection middleware.
type IntrospectionConfig struct {
	// URL is the RFC 7662 introspection endpoint (must be https).
	URL string
	// ClientID / ClientSecret authenticate Relay to the introspection endpoint
	// via HTTP Basic auth.
	ClientID     string
	ClientSecret string
	// RequiredScopes, when set, requires the token to carry every listed scope.
	RequiredScopes []string
	// Header is the inbound header carrying the token. Defaults to Authorization
	// (Bearer scheme).
	Header string
	// CacheTTL bounds how long a positive introspection result is cached. The
	// effective TTL is the smaller of this and the token's own expiry.
	CacheTTL time.Duration
	// Client overrides the HTTP client (tests). Timeout defaults to 5s.
	Client *http.Client
	// Now overrides the clock (tests).
	Now    func() time.Time
	Logger *slog.Logger
}

type introspectionResponse struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope"`
	Sub      string `json:"sub"`
	Tenant   string `json:"tenant"`
	TenantID string `json:"tenant_id"`
	ClientID string `json:"client_id"`
	JTI      string `json:"jti"`
	Exp      int64  `json:"exp"`
}

type introspectionCacheEntry struct {
	sub       string
	scope     string
	tenant    string
	keyID     string
	expiresAt time.Time
}

type introspectionMiddleware struct {
	url            string
	clientID       string
	clientSecret   string
	requiredScopes []string
	header         string
	cacheTTL       time.Duration
	client         *http.Client
	now            func() time.Time
	logger         *slog.Logger

	mu    sync.Mutex
	cache map[string]introspectionCacheEntry
}

// NewIntrospection builds the OAuth2 token introspection middleware.
func NewIntrospection(cfg IntrospectionConfig) (Middleware, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("introspection: url is required")
	}
	if u, err := url.Parse(strings.TrimSpace(cfg.URL)); err != nil || !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("introspection: url must be https")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, fmt.Errorf("introspection: client_id is required")
	}
	if strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, fmt.Errorf("introspection: client secret is required")
	}

	header := strings.TrimSpace(cfg.Header)
	if header == "" {
		header = "Authorization"
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = defaultIntrospectionCacheTTL
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: defaultIntrospectionTimeout}
	}

	scopes := make([]string, 0, len(cfg.RequiredScopes))
	for _, s := range cfg.RequiredScopes {
		if s = strings.TrimSpace(s); s != "" {
			scopes = append(scopes, s)
		}
	}

	m := &introspectionMiddleware{
		url:            strings.TrimSpace(cfg.URL),
		clientID:       strings.TrimSpace(cfg.ClientID),
		clientSecret:   cfg.ClientSecret,
		requiredScopes: scopes,
		header:         header,
		cacheTTL:       ttl,
		client:         client,
		now:            now,
		logger:         cfg.Logger,
		cache:          make(map[string]introspectionCacheEntry),
	}
	return m.handler, nil
}

func (m *introspectionMiddleware) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := readTokenFromHeader(r, m.header)
		if !ok {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		entry, ok := m.lookup(token)
		if !ok {
			result, err := m.introspect(r.Context(), token)
			if err != nil {
				if m.logger != nil {
					m.logger.WarnContext(r.Context(), "token introspection failed",
						"event", "introspection_error",
						"error", err.Error(),
						"path", r.URL.Path,
					)
				}
				// Fail closed: we cannot verify the token, so we must not forward it.
				httpx.WriteError(w, http.StatusServiceUnavailable, "introspection_unavailable")
				return
			}
			if !result.Active {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			tenant := result.Tenant
			if tenant == "" {
				tenant = result.TenantID
			}
			keyID := result.ClientID
			if keyID == "" {
				keyID = result.JTI
			}
			entry = introspectionCacheEntry{
				sub: result.Sub, scope: result.Scope, tenant: tenant, keyID: keyID,
			}
			m.store(token, entry, result.Exp)
		}

		if !m.hasRequiredScopes(entry.scope) {
			httpx.WriteError(w, http.StatusForbidden, "insufficient_scope")
			return
		}

		// Strip client-supplied identity headers, then inject the verified values.
		r.Header.Del(defaultSubjectHeader)
		r.Header.Del(tokenScopeHeader)
		if entry.sub != "" {
			r.Header.Set(defaultSubjectHeader, entry.sub)
		}
		if entry.scope != "" {
			r.Header.Set(tokenScopeHeader, entry.scope)
		}
		next.ServeHTTP(w, withAuthIdentity(r, AuthIdentity{
			Source:  "oauth2",
			Subject: entry.sub,
			Tenant:  entry.tenant,
			KeyID:   entry.keyID,
			Claims: map[string]string{
				"scope": entry.scope,
			},
		}))
	})
}

func (m *introspectionMiddleware) introspect(ctx context.Context, token string) (*introspectionResponse, error) {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.url, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(m.clientID, m.clientSecret)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("endpoint returned %d", resp.StatusCode)
	}

	var out introspectionResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIntrospectionBodyBytes)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

func (m *introspectionMiddleware) hasRequiredScopes(scope string) bool {
	if len(m.requiredScopes) == 0 {
		return true
	}
	granted := make(map[string]struct{})
	for _, s := range strings.Fields(scope) {
		granted[s] = struct{}{}
	}
	for _, req := range m.requiredScopes {
		if _, ok := granted[req]; !ok {
			return false
		}
	}
	return true
}

func introspectionKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (m *introspectionMiddleware) lookup(token string) (introspectionCacheEntry, bool) {
	key := introspectionKey(token)
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.cache[key]
	if !ok {
		return introspectionCacheEntry{}, false
	}
	if !entry.expiresAt.After(m.now()) {
		delete(m.cache, key)
		return introspectionCacheEntry{}, false
	}
	return entry, true
}

// store caches a positive result. The TTL is the smaller of the configured
// cache TTL and the token's own expiry, so a token is never honored from cache
// past its expiry.
func (m *introspectionMiddleware) store(token string, entry introspectionCacheEntry, tokenExp int64) {
	now := m.now()
	expiresAt := now.Add(m.cacheTTL)
	if tokenExp > 0 {
		tokenExpiry := time.Unix(tokenExp, 0)
		if tokenExpiry.Before(expiresAt) {
			expiresAt = tokenExpiry
		}
	}
	if !expiresAt.After(now) {
		return
	}
	entry.expiresAt = expiresAt

	key := introspectionKey(token)
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.cache) >= maxIntrospectionCacheEntries {
		// Bound memory: drop expired entries first; if none are expired, skip
		// caching this result rather than growing without limit.
		m.pruneExpiredLocked(now)
		if len(m.cache) >= maxIntrospectionCacheEntries {
			return
		}
	}
	m.cache[key] = entry
}

func (m *introspectionMiddleware) pruneExpiredLocked(now time.Time) {
	for k, e := range m.cache {
		if !e.expiresAt.After(now) {
			delete(m.cache, k)
		}
	}
}
