package middleware

import (
	"bytes"
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
	// MaxEntries bounds the number of cached responses (LRU eviction).
	MaxEntries int
	// Vary lists request header names whose values are folded into the cache key,
	// so responses that differ by those headers are cached separately.
	Vary []string
	// Store overrides the backing store (tests). Defaults to an in-memory LRU.
	Store cacheStore
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

	store := cfg.Store
	if store == nil {
		store = newCacheMemoryStore(cfg.MaxEntries, now)
	}

	m := &cacheMiddleware{
		ttl:            ttl,
		methods:        methods,
		cacheable:      cacheable,
		maxObjectBytes: maxObj,
		vary:           vary,
		store:          store,
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

		// A request "no-cache" forces revalidation: skip the read but still allow
		// the fresh response to be stored.
		if _, noCache := reqCC["no-cache"]; !noCache {
			if entry, ok := m.store.Get(key); ok {
				m.serve(w, r, entry)
				return
			}
		}

		cw := &cacheCaptureWriter{
			ResponseWriter: w,
			limit:          m.maxObjectBytes,
		}
		cw.Header().Set("X-Cache", "MISS")
		next.ServeHTTP(cw, r)

		if resp := m.buildEntry(cw); resp != nil {
			m.store.Set(key, resp)
		}
	})
}

func (m *cacheMiddleware) cacheKey(r *http.Request) string {
	var b strings.Builder
	b.WriteString(r.Method)
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
// returns the entry to store. Returns nil when the response must not be cached.
func (m *cacheMiddleware) buildEntry(cw *cacheCaptureWriter) *cachedResponse {
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
	if strings.Contains(strings.ToLower(header.Get("Vary")), "*") {
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
	}
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
		_, _ = w.Write(entry.body)
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
