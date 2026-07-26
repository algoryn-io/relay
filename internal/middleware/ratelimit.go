package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"algoryn.io/relay/internal/httpx"
	"golang.org/x/net/http/httpguts"
)

type Strategy string

const (
	TokenBucket   Strategy = "token_bucket"
	SlidingWindow Strategy = "sliding_window"
)

type RateLimitConfig struct {
	Strategy Strategy
	Limit    int
	Window   time.Duration
	By       string
	Header   string
	Key      RateLimitKeyConfig
	// Store selects the rate limit backend: "memory" (default) or "redis".
	Store string
	// RedisURL is the Redis connection URL when Store == "redis".
	// Accepts the redis:// and rediss:// schemes.
	RedisURL string
	// FailOpen permits a request when the backing store fails. It defaults to
	// false: rate limiting must not silently vanish during a Redis outage.
	FailOpen bool
	// MemoryMaxBuckets strictly caps in-process key cardinality.
	MemoryMaxBuckets int
	// MemoryBucketTTL expires idle buckets. It must be at least Window so
	// cleanup cannot reset a still-active sliding window.
	MemoryBucketTTL time.Duration
	// MemoryCleanupInterval controls the single store-wide cleanup loop.
	MemoryCleanupInterval time.Duration
	Metrics               RateLimitMetrics
	Events                RateLimitOperationalEvents
	ObserverKey           string
}

type RateLimitSelector struct {
	Type  string
	Name  string
	Claim string
}

type RateLimitKeyConfig struct {
	Selectors     []RateLimitSelector
	Fallback      *RateLimitSelector
	RejectMissing bool
	Namespace     string
}

// RateLimitMetrics intentionally exposes only aggregate values: bucket keys
// are never metric labels, avoiding a second cardinality problem.
type RateLimitMetrics interface {
	AddRateLimitMemoryBuckets(delta int)
	RecordRateLimitMemoryEviction()
}

// RateLimitOperationalEvents is implemented outside this package to avoid an
// observability dependency cycle.
type RateLimitOperationalEvents interface {
	RecordRateLimitRedisResult(source string, success, failOpen bool)
	RecordRateLimitFailOpenBypass()
}

type rateLimiter struct {
	limit         int
	window        time.Duration
	by            string
	header        string
	selectors     []RateLimitSelector
	fallback      *RateLimitSelector
	rejectMissing bool
	namespace     string
	store         rateLimitStore
	failOpen      bool
	redis         bool
	events        RateLimitOperationalEvents
	observerKey   string
}

// NewRateLimit returns a sliding-window rate limit middleware. The returned
// io.Closer releases store resources (the in-memory pruner goroutine or the
// Redis connection pool) and must be closed when the middleware is discarded
// (e.g. on config reload). It is nil when the store holds no resources.
func NewRateLimit(cfg RateLimitConfig) (Middleware, io.Closer, error) {
	if cfg.Strategy == "" {
		cfg.Strategy = SlidingWindow
	}
	if cfg.Strategy != SlidingWindow {
		return nil, nil, fmt.Errorf("unsupported rate limit strategy %q", cfg.Strategy)
	}
	if cfg.Limit <= 0 {
		return nil, nil, fmt.Errorf("rate limit must be greater than 0")
	}
	if cfg.Window <= 0 {
		return nil, nil, fmt.Errorf("rate limit window must be greater than 0")
	}
	if cfg.MemoryMaxBuckets == 0 {
		cfg.MemoryMaxBuckets = defaultMemoryMaxBuckets
	}
	if cfg.MemoryBucketTTL == 0 {
		cfg.MemoryBucketTTL = cfg.Window
	}
	if cfg.MemoryCleanupInterval == 0 {
		cfg.MemoryCleanupInterval = defaultMemoryCleanupInterval
	}
	if len(cfg.Key.Selectors) > 0 && strings.TrimSpace(cfg.By) != "" {
		return nil, nil, fmt.Errorf("rate limit by and key.selectors are mutually exclusive")
	}
	if len(cfg.Key.Selectors) == 0 && strings.TrimSpace(cfg.By) == "" {
		cfg.By = "ip"
	}
	if len(cfg.Key.Selectors) == 0 {
		switch cfg.By {
		case "ip", "route", "api_key":
		default:
			return nil, nil, fmt.Errorf("unsupported rate limit key %q", cfg.By)
		}
	}
	if cfg.By == "api_key" && strings.TrimSpace(cfg.Header) == "" {
		cfg.Header = "X-API-Key"
	}

	var store rateLimitStore
	switch strings.ToLower(strings.TrimSpace(cfg.Store)) {
	case "redis":
		if strings.TrimSpace(cfg.RedisURL) == "" {
			return nil, nil, fmt.Errorf("redis_url is required when store is redis")
		}
		rs, err := newRedisStore(cfg.RedisURL)
		if err != nil {
			return nil, nil, fmt.Errorf("create redis store: %w", err)
		}
		store = rs
	case "", "memory":
		if cfg.MemoryMaxBuckets <= 0 {
			return nil, nil, fmt.Errorf("memory_max_buckets must be greater than 0")
		}
		if cfg.MemoryBucketTTL < cfg.Window {
			return nil, nil, fmt.Errorf("memory_bucket_ttl must be at least the rate limit window")
		}
		if cfg.MemoryCleanupInterval <= 0 {
			return nil, nil, fmt.Errorf("memory_cleanup_interval must be greater than 0")
		}
		ms, err := newMemoryStoreWithOptions(memoryStoreOptions{
			maxBuckets:      cfg.MemoryMaxBuckets,
			bucketTTL:       cfg.MemoryBucketTTL,
			cleanupInterval: cfg.MemoryCleanupInterval,
			metrics:         cfg.Metrics,
		})
		if err != nil {
			return nil, nil, err
		}
		store = ms
	default:
		return nil, nil, fmt.Errorf("unsupported rate limit store %q", cfg.Store)
	}

	mw, err := newRateLimitWithStore(cfg, store)
	if err != nil {
		if c, ok := store.(io.Closer); ok {
			_ = c.Close()
		}
		return nil, nil, err
	}
	closer, _ := store.(io.Closer)
	return mw, closer, nil
}

// newRateLimitWithStore creates the middleware using an already-constructed
// store. Used internally and in tests to inject stores (e.g. miniredis).
func newRateLimitWithStore(cfg RateLimitConfig, store rateLimitStore) (Middleware, error) {
	rl := &rateLimiter{
		limit:         cfg.Limit,
		window:        cfg.Window,
		by:            cfg.By,
		header:        cfg.Header,
		rejectMissing: cfg.Key.RejectMissing,
		namespace:     strings.TrimSpace(cfg.Key.Namespace),
		store:         store,
		failOpen:      cfg.FailOpen,
		redis:         strings.EqualFold(strings.TrimSpace(cfg.Store), "redis") || isRedisStore(store),
		events:        cfg.Events,
		observerKey:   cfg.ObserverKey,
	}
	if rl.namespace == "" {
		rl.namespace = "relay:ratelimit:v1"
	}
	if err := validateRateLimitNamespace(rl.namespace); err != nil {
		return nil, err
	}
	for _, selector := range cfg.Key.Selectors {
		normalized, err := normalizeRateLimitSelector(selector)
		if err != nil {
			return nil, err
		}
		rl.selectors = append(rl.selectors, normalized)
	}
	if cfg.Key.Fallback != nil {
		normalized, err := normalizeRateLimitSelector(*cfg.Key.Fallback)
		if err != nil {
			return nil, fmt.Errorf("fallback: %w", err)
		}
		rl.fallback = &normalized
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, complete := rl.rateLimitKey(r)
			if !complete && rl.rejectMissing {
				httpx.WriteError(w, http.StatusBadRequest, "rate_limit_key_missing")
				return
			}

			now := time.Now()
			allowed, remaining, reset, err := rl.store.Check(r.Context(), key, rl.limit, rl.window, now)
			if rl.redis && rl.events != nil {
				rl.events.RecordRateLimitRedisResult(rl.observerKey, err == nil, rl.failOpen)
			}
			if err != nil && !rl.failOpen {
				httpx.WriteError(w, http.StatusServiceUnavailable, "rate_limit_unavailable")
				return
			}
			if err != nil && rl.failOpen && rl.events != nil {
				rl.events.RecordRateLimitFailOpenBypass()
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))

			if !allowed {
				retryAfter := int(time.Until(reset).Seconds()) + 1
				if retryAfter < 1 {
					retryAfter = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				httpx.WriteError(w, http.StatusTooManyRequests, "rate_limited")
				return
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

func isRedisStore(store rateLimitStore) bool {
	_, ok := store.(*redisStore)
	return ok
}

func (l *rateLimiter) keyFromRequest(r *http.Request) string {
	raw := ""
	switch l.by {
	case "route":
		raw = r.Method + ":" + r.URL.Path
	case "api_key":
		raw = strings.TrimSpace(r.Header.Get(l.header))
		if raw == "" {
			return ""
		}
	default:
		raw = httpx.ClientIP(r)
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (l *rateLimiter) rateLimitKey(r *http.Request) (string, bool) {
	if len(l.selectors) == 0 {
		key := l.keyFromRequest(r)
		if key == "" {
			return l.namespace + ":" + hashRateLimitComponents([]string{"missing"}), false
		}
		return l.namespace + ":" + key, true
	}

	components := make([]string, 0, len(l.selectors))
	for _, selector := range l.selectors {
		value, ok := selectorValue(r, selector)
		if !ok {
			if l.fallback != nil {
				fallback, fallbackOK := selectorValue(r, *l.fallback)
				if fallbackOK {
					return l.namespace + ":" + hashRateLimitComponents([]string{
						"fallback", selectorDescriptor(*l.fallback), fallback,
					}), true
				}
			}
			return l.namespace + ":" + hashRateLimitComponents([]string{"missing"}), false
		}
		components = append(components, selectorDescriptor(selector), value)
	}
	return l.namespace + ":" + hashRateLimitComponents(components), true
}

func selectorValue(r *http.Request, selector RateLimitSelector) (string, bool) {
	var value string
	switch selector.Type {
	case "ip":
		value = httpx.ClientIP(r)
	case "route":
		value = r.Method + ":" + r.URL.Path
	case "header":
		values := r.Header.Values(selector.Name)
		if len(values) == 0 {
			return "", false
		}
		value = encodeRateLimitValues(values)
	case "identity":
		identity, ok := authIdentityFromRequest(r)
		if !ok {
			return "", false
		}
		value = identity.Subject
		if value == "" {
			value = identity.KeyID
		}
		if value != "" {
			value = encodeRateLimitValues([]string{identity.Source, value})
		}
	case "tenant":
		identity, ok := authIdentityFromRequest(r)
		if !ok {
			return "", false
		}
		if identity.Tenant != "" {
			value = encodeRateLimitValues([]string{identity.Source, identity.Tenant})
		}
	case "claim":
		identity, ok := authIdentityFromRequest(r)
		if !ok {
			return "", false
		}
		// Claims are Relay-owned (JWT scalars, OAuth2 introspection, or
		// ext_authz decision headers). Client headers never populate them.
		value = identity.Claims[selector.Claim]
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

func selectorDescriptor(selector RateLimitSelector) string {
	switch selector.Type {
	case "header":
		return "header:" + http.CanonicalHeaderKey(selector.Name)
	case "claim":
		return "claim:" + selector.Claim
	default:
		return selector.Type
	}
}

func hashRateLimitComponents(components []string) string {
	h := sha256.New()
	for _, component := range components {
		value := []byte(component)
		_, _ = h.Write([]byte(strconv.Itoa(len(value))))
		_, _ = h.Write([]byte{':'})
		_, _ = h.Write(value)
		_, _ = h.Write([]byte{';'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func encodeRateLimitValues(values []string) string {
	var encoded strings.Builder
	for _, value := range values {
		value = strings.TrimSpace(value)
		encoded.WriteString(strconv.Itoa(len(value)))
		encoded.WriteByte(':')
		encoded.WriteString(value)
		encoded.WriteByte(';')
	}
	return encoded.String()
}

func normalizeRateLimitSelector(selector RateLimitSelector) (RateLimitSelector, error) {
	selector.Type = strings.ToLower(strings.TrimSpace(selector.Type))
	selector.Name = strings.TrimSpace(selector.Name)
	selector.Claim = strings.TrimSpace(selector.Claim)
	if selector.Type == "jwt_claim" {
		selector.Type = "claim"
	}
	switch selector.Type {
	case "ip", "route", "identity", "tenant":
		if selector.Name != "" || selector.Claim != "" {
			return selector, fmt.Errorf("selector %q does not accept name or claim", selector.Type)
		}
	case "header":
		if !httpguts.ValidHeaderFieldName(selector.Name) {
			return selector, fmt.Errorf("header selector requires a valid explicit name")
		}
		selector.Name = http.CanonicalHeaderKey(selector.Name)
		if selector.Claim != "" {
			return selector, fmt.Errorf("header selector does not accept claim")
		}
	case "claim":
		if selector.Claim != "" && selector.Name != "" {
			return selector, fmt.Errorf("claim selector accepts only one of claim or name")
		}
		if selector.Claim == "" {
			selector.Claim = selector.Name
			selector.Name = ""
		}
		if selector.Claim == "" {
			return selector, fmt.Errorf("claim selector requires claim")
		}
		if !safeIdentityClaimName(selector.Claim) {
			return selector, fmt.Errorf("claim selector cannot select credential-bearing claim %q", selector.Claim)
		}
	default:
		return selector, fmt.Errorf("unsupported rate limit selector %q", selector.Type)
	}
	return selector, nil
}

func validateRateLimitNamespace(namespace string) error {
	if len(namespace) > 64 {
		return fmt.Errorf("rate limit namespace must be at most 64 characters")
	}
	for _, r := range namespace {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') &&
			!(r >= '0' && r <= '9') && r != '.' && r != '_' && r != '-' && r != ':' {
			return fmt.Errorf("rate limit namespace contains unsupported character %q", r)
		}
	}
	return nil
}
