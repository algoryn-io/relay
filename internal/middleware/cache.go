package middleware

import (
	"bytes"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultCacheTTL = 60 * time.Second
const defaultCacheMaxObjectBytes = 1 << 20 // 1 MB

// hopByHopCacheHeaders are never replayed from cache; they describe a single
// connection, not the cached representation.
var hopByHopCacheHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// CacheConfig configures the response cache middleware.
type CacheConfig struct {
	// TTL is the default lifetime of a cached response when the upstream does not
	// specify a max-age. Defaults to 60s.
	TTL time.Duration
	// Methods are the request methods eligible for caching. Defaults to GET, HEAD.
	Methods []string
	// CacheableStatus lists response status codes that may be cached. Defaults to
	// {200}.
	CacheableStatus []int
	// MaxObjectBytes caps the size of a cacheable response body. Larger responses
	// stream through uncached. Defaults to 1 MB.
	MaxObjectBytes int64
	// MaxEntries bounds the number of cached responses for the memory store
	// (LRU eviction). Ignored by the Redis store (TTL governs retention).
	MaxEntries int
	// Vary lists request header names whose values are folded into the cache key,
	// so responses that differ by those headers are cached separately.
	Vary []string
	// Store selects the backend: "memory" (default) or "redis".
	Store string
	// RedisURL is the Redis connection URL when Store == "redis".
	RedisURL string
	// Namespace prefixes Redis keys. Defaults to relay:cache:v1.
	Namespace string
	// OperationTimeout bounds a single Redis command. Defaults to 100ms.
	OperationTimeout time.Duration
	// FailOpen controls Redis failure behavior on lookup/invalidation:
	// true treats errors as a miss/bypass; false returns 503. Set errors never
	// fail the already-written origin response. Defaults to false.
	FailOpen bool
	// StoreBackend overrides the backing store (tests). Defaults from Store.
	StoreBackend cacheStore
	// Now overrides the clock (tests).
	Now func() time.Time
}

type cacheMiddleware struct {
	ttl            time.Duration
	methods        map[string]struct{}
	cacheable      map[int]struct{}
	maxObjectBytes int64
	vary           []string
	store          cacheStore
	failOpen       bool
	now            func() time.Time
}

// NewCache builds the response cache middleware. It returns the middleware and a
// Closer that releases the backing store on reload/shutdown.
func NewCache(cfg CacheConfig) (Middleware, *cacheMiddleware, error) {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	maxObj := cfg.MaxObjectBytes
	if maxObj <= 0 {
		maxObj = defaultCacheMaxObjectBytes
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	methods := make(map[string]struct{})
	if len(cfg.Methods) == 0 {
		methods[http.MethodGet] = struct{}{}
		methods[http.MethodHead] = struct{}{}
	} else {
		for _, m := range cfg.Methods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m != "" {
				methods[m] = struct{}{}
			}
		}
	}

	cacheable := make(map[int]struct{})
	if len(cfg.CacheableStatus) == 0 {
		cacheable[http.StatusOK] = struct{}{}
	} else {
		for _, s := range cfg.CacheableStatus {
			cacheable[s] = struct{}{}
		}
	}

	vary := make([]string, 0, len(cfg.Vary))
	for _, v := range cfg.Vary {
		if v = strings.TrimSpace(v); v != "" {
			vary = append(vary, http.CanonicalHeaderKey(v))
		}
	}
	sort.Strings(vary)

	store := cfg.StoreBackend
	if store == nil {
		switch strings.ToLower(strings.TrimSpace(cfg.Store)) {
		case "redis":
			if strings.TrimSpace(cfg.RedisURL) == "" {
				return nil, nil, fmt.Errorf("redis_url is required when store is redis")
			}
			namespace := strings.TrimSpace(cfg.Namespace)
			if namespace == "" {
				namespace = defaultCacheRedisNamespace
			}
			if err := validateCacheNamespace(namespace); err != nil {
				return nil, nil, err
			}
			rs, err := newCacheRedisStore(cfg.RedisURL, namespace, cfg.OperationTimeout, maxObj, now)
			if err != nil {
				return nil, nil, fmt.Errorf("create redis cache store: %w", err)
			}
			store = rs
		case "", "memory":
			store = newCacheMemoryStore(cfg.MaxEntries, now)
		default:
			return nil, nil, fmt.Errorf("unsupported cache store %q", cfg.Store)
		}
	}

	m := &cacheMiddleware{
		ttl:            ttl,
		methods:        methods,
		cacheable:      cacheable,
		maxObjectBytes: maxObj,
		vary:           vary,
		store:          store,
		failOpen:       cfg.FailOpen,
		now:            now,
	}
	return m.handler, m, nil
}

// Close releases the backing store.
func (m *cacheMiddleware) Close() error {
	if m == nil || m.store == nil {
		return nil
	}
	return m.store.Close()
}

func (m *cacheMiddleware) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PURGE" {
			m.handlePurge(w, r)
			return
		}

		if _, ok := m.methods[r.Method]; !ok {
			w.Header().Set("X-Cache", "BYPASS")
			next.ServeHTTP(w, r)
			return
		}

		reqCC := parseCacheControl(r.Header.Get("Cache-Control"))
		if _, noStore := reqCC["no-store"]; noStore {
			w.Header().Set("X-Cache", "BYPASS")
			next.ServeHTTP(w, r)
			return
		}

		key := m.cacheKey(r)
		authed := requestIsAuthenticated(r)

		// A request "no-cache" forces revalidation: skip the read but still allow
		// the fresh response to be stored.
		if _, noCache := reqCC["no-cache"]; !noCache {
			entry, err := m.store.Get(key)
			if err != nil {
				if !m.failOpen {
					http.Error(w, "cache unavailable", http.StatusServiceUnavailable)
					return
				}
				// Fail-open: treat Redis errors as a miss and continue to origin.
			} else if entry != nil {
				// A shared cache must not reuse a stored response for an
				// authenticated request unless the origin marked it shareable
				// (public/s-maxage). This prevents returning one user's response to
				// another (RFC 7234 §3.2).
				if entry.public || !authed {
					m.serve(w, r, entry)
					return
				}
			}
		}

		cw := &cacheCaptureWriter{
			ResponseWriter: w,
			limit:          m.maxObjectBytes,
		}
		cw.Header().Set("X-Cache", "MISS")
		next.ServeHTTP(cw, r)

		if resp := m.buildEntry(cw, authed); resp != nil {
			// Set failures never fail the already-written origin response.
			_ = m.store.Set(key, resp)
		}
	})
}

// handlePurge invalidates the cached GET/HEAD variants for the request URL
// (including configured Vary headers). It does not forward to the origin.
func (m *cacheMiddleware) handlePurge(w http.ResponseWriter, r *http.Request) {
	targets := []string{http.MethodGet, http.MethodHead}
	var firstErr error
	for _, method := range targets {
		key := m.cacheKeyWithMethod(r, method)
		if err := m.store.Delete(key); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		if !m.failOpen {
			http.Error(w, "cache unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-Cache", "BYPASS")
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("X-Cache", "PURGED")
	w.WriteHeader(http.StatusOK)
}

// requestIsAuthenticated reports whether a request carries a credential that can
// make the response user-specific. Cookie is treated like Authorization (a
// session credential) so session-scoped responses are never shared.
func requestIsAuthenticated(r *http.Request) bool {
	return r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != ""
}

func (m *cacheMiddleware) cacheKey(r *http.Request) string {
	return m.cacheKeyWithMethod(r, r.Method)
}

func (m *cacheMiddleware) cacheKeyWithMethod(r *http.Request, method string) string {
	var b strings.Builder
	b.WriteString(method)
	b.WriteByte('\x00')
	b.WriteString(strings.ToLower(hostWithoutPort(r.Host)))
	b.WriteByte('\x00')
	b.WriteString(r.URL.Path)
	b.WriteByte('?')
	b.WriteString(canonicalQuery(r.URL.RawQuery))
	for _, h := range m.vary {
		b.WriteByte('\x00')
		b.WriteString(h)
		b.WriteByte('=')
		b.WriteString(r.Header.Get(h))
	}
	return b.String()
}

// buildEntry decides whether the captured response is cacheable and, if so,
// returns the entry to store. authed reports whether the originating request
// carried a credential. Returns nil when the response must not be cached.
func (m *cacheMiddleware) buildEntry(cw *cacheCaptureWriter, authed bool) *cachedResponse {
	if cw.overflow {
		return nil
	}
	if _, ok := m.cacheable[cw.statusCode()]; !ok {
		return nil
	}
	header := cw.snapshotHeader
	if header == nil {
		header = cw.Header()
	}
	// Never cache responses that carry a session or that the origin marks
	// private/uncacheable.
	if header.Get("Set-Cookie") != "" {
		return nil
	}
	// Honor the origin's Vary: "*" is uncacheable, and we can only cache a varied
	// response if every listed request header is folded into our cache key.
	if !m.varyCovered(header.Get("Vary")) {
		return nil
	}
	respCC := parseCacheControl(header.Get("Cache-Control"))
	if _, ok := respCC["no-store"]; ok {
		return nil
	}
	if _, ok := respCC["no-cache"]; ok {
		return nil
	}
	if _, ok := respCC["private"]; ok {
		return nil
	}

	// A response is shareable across users only when the origin says so.
	_, hasPublic := respCC["public"]
	_, hasSMaxAge := respCC["s-maxage"]
	public := hasPublic || hasSMaxAge

	// RFC 7234 §3.2: a shared cache must not store a response to an authenticated
	// request unless it is explicitly shareable. This is the core guard against
	// caching (and later serving) one user's private response.
	if authed && !public {
		return nil
	}

	ttl := m.ttl
	if v, ok := respCC["s-maxage"]; ok {
		if d, err := strconv.Atoi(v); err == nil {
			ttl = time.Duration(d) * time.Second
		}
	} else if v, ok := respCC["max-age"]; ok {
		if d, err := strconv.Atoi(v); err == nil {
			ttl = time.Duration(d) * time.Second
		}
	}
	if ttl <= 0 {
		return nil
	}

	now := m.now()
	return &cachedResponse{
		status:    cw.statusCode(),
		header:    cloneCacheHeader(header),
		body:      append([]byte(nil), cw.buf.Bytes()...),
		storedAt:  now,
		expiresAt: now.Add(ttl),
		public:    public,
	}
}

// varyCovered reports whether a response Vary header can be represented by this
// cache's key. An empty Vary is always fine; "*" and any header not folded into
// the configured cache key (m.vary) make the response impossible to key
// correctly, so it must not be cached.
func (m *cacheMiddleware) varyCovered(respVary string) bool {
	respVary = strings.TrimSpace(respVary)
	if respVary == "" {
		return true
	}
	configured := make(map[string]struct{}, len(m.vary))
	for _, h := range m.vary {
		configured[h] = struct{}{}
	}
	for _, h := range strings.Split(respVary, ",") {
		h = http.CanonicalHeaderKey(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, ok := configured[h]; !ok {
			return false
		}
	}
	return true
}

func (m *cacheMiddleware) serve(w http.ResponseWriter, r *http.Request, entry *cachedResponse) {
	dst := w.Header()
	for k, vs := range entry.header {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	age := int(m.now().Sub(entry.storedAt).Seconds())
	if age < 0 {
		age = 0
	}
	dst.Set("Age", strconv.Itoa(age))
	dst.Set("X-Cache", "HIT")
	w.WriteHeader(entry.status)
	if r.Method != http.MethodHead {
		// Replays an opaque upstream body with the origin Content-Type; not HTML templating.
		_, _ = w.Write(entry.body) // #nosec G705
	}
}

// cacheCaptureWriter tees the upstream response to the client while buffering the
// body (up to limit) so it can be cached. If the body exceeds limit it keeps
// streaming to the client but marks itself overflowed so it will not be cached.
type cacheCaptureWriter struct {
	http.ResponseWriter
	status         int
	wroteHeader    bool
	buf            bytes.Buffer
	limit          int64
	overflow       bool
	snapshotHeader http.Header
}

func (cw *cacheCaptureWriter) WriteHeader(code int) {
	if cw.wroteHeader {
		return
	}
	cw.status = code
	cw.wroteHeader = true
	cw.snapshotHeader = cloneCacheHeader(cw.Header())
	cw.ResponseWriter.WriteHeader(code)
}

func (cw *cacheCaptureWriter) Write(b []byte) (int, error) {
	if !cw.wroteHeader {
		cw.WriteHeader(http.StatusOK)
	}
	if !cw.overflow {
		if int64(cw.buf.Len()+len(b)) > cw.limit {
			cw.overflow = true
			cw.buf.Reset()
		} else {
			cw.buf.Write(b)
		}
	}
	return cw.ResponseWriter.Write(b)
}

// Flush passes through so streaming responses (SSE) are not stalled. A flushed
// response is inherently unbounded, so mark it uncacheable.
func (cw *cacheCaptureWriter) Flush() {
	cw.overflow = true
	cw.buf.Reset()
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (cw *cacheCaptureWriter) statusCode() int {
	if cw.status == 0 {
		return http.StatusOK
	}
	return cw.status
}

func cloneCacheHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		if _, hop := hopByHopCacheHeaders[k]; hop {
			continue
		}
		if k == "X-Cache" || k == "Age" {
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// parseCacheControl parses a Cache-Control header into a directive map. Valueless
// directives (e.g. "no-store") map to "". Directive names are lowercased.
func parseCacheControl(v string) map[string]string {
	out := make(map[string]string)
	if v == "" {
		return out
	}
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, found := strings.Cut(part, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if found {
			out[name] = strings.Trim(strings.TrimSpace(val), `"`)
		} else {
			out[name] = ""
		}
	}
	return out
}

// canonicalQuery returns the query string with parameters sorted so that two
// requests differing only in parameter order share a cache key.
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	pairs := strings.Split(raw, "&")
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func hostWithoutPort(host string) string {
	if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[i:], "]") {
		return host[:i]
	}
	return host
}
