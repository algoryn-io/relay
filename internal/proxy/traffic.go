package proxy

import (
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
)

// Always stripped from mirrored requests so credentials never cross into the
// shadow path by accident.
var mirrorSensitiveHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"Cookie",
	"Cookie2",
	"Set-Cookie",
	"X-Internal-Auth",
	"X-Admin",
}

// hopHeaders are connection-specific and must not be forwarded on the mirror.
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// resolveTrafficBackend applies canary selection, then failover. When the canary
// is selected but cannot serve, the primary (+ failover) is tried next.
func (p *Proxy) resolveTrafficBackend(route *config.RouteRuntime, r *http.Request, clientIP string) (config.BackendRuntime, func(), error) {
	if route == nil {
		return config.BackendRuntime{}, func() {}, fmt.Errorf("route is nil")
	}
	preferred := pickCanaryBackend(route, r, clientIP)
	if preferred == "" {
		preferred = route.BackendName
	}

	if preferred == route.BackendName {
		return p.resolveBackendChain(route.Name, preferred, route.FailoverBackends)
	}

	backend, release, err := p.resolveBackendChain(route.Name, preferred, nil)
	if err == nil {
		return backend, release, nil
	}
	// Canary unavailable: fall back to primary (+ route failover).
	return p.resolveBackendChain(route.Name, route.BackendName, route.FailoverBackends)
}

// pickCanaryBackend returns the canary backend when the deterministic bucket for
// this request falls below the configured percent; otherwise the primary.
func pickCanaryBackend(route *config.RouteRuntime, r *http.Request, clientIP string) string {
	if route == nil {
		return ""
	}
	primary := route.BackendName
	if route.Traffic == nil || route.Traffic.Canary == nil || route.Traffic.Canary.Percent <= 0 {
		return primary
	}
	canary := route.Traffic.Canary
	key := trafficKey(r, clientIP, canary.KeyHeader, canary.KeyCookie)
	if trafficBucket(key) < canary.Percent {
		return canary.Backend
	}
	return primary
}

func trafficKey(r *http.Request, clientIP, headerName, cookieName string) string {
	if r != nil && headerName != "" {
		if v := strings.TrimSpace(r.Header.Get(headerName)); v != "" {
			return v
		}
	}
	if r != nil && cookieName != "" {
		if c, err := r.Cookie(cookieName); err == nil && c != nil {
			if v := strings.TrimSpace(c.Value); v != "" {
				return v
			}
		}
	}
	if clientIP != "" {
		return clientIP
	}
	if r != nil {
		return httpx.ClientIP(r)
	}
	return ""
}

// trafficBucket maps a key to a stable 0–99 bucket.
func trafficBucket(key string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % 100)
}

func stickyInstanceID(instanceURL string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(instanceURL))
	return strconv.FormatUint(uint64(h.Sum32()), 16)
}

// selectInstanceForRequest applies sticky affinity when configured, otherwise
// falls back to the backend load-balancing strategy. setCookie is non-empty when
// the response should establish/refresh a sticky cookie.
func (p *Proxy) selectInstanceForRequest(
	backendName, strategy string,
	r *http.Request,
	sticky *config.RouteStickyRuntime,
) (selected *instanceState, setCookie string, err error) {
	if sticky == nil {
		selected, err = p.selectInstance(backendName, strategy)
		return selected, "", err
	}

	if sticky.Cookie != "" && r != nil {
		if c, cookieErr := r.Cookie(sticky.Cookie); cookieErr == nil && c != nil {
			if id := strings.TrimSpace(c.Value); id != "" {
				if inst, ok := p.lookupStickyInstance(backendName, id); ok {
					inst.activeRequests.Add(1)
					return inst, id, nil
				}
			}
		}
	}

	if sticky.Header != "" && r != nil {
		if key := strings.TrimSpace(r.Header.Get(sticky.Header)); key != "" {
			if inst, ok := p.pickStickyByKey(backendName, key); ok {
				inst.activeRequests.Add(1)
				if sticky.Cookie != "" {
					return inst, stickyInstanceID(inst.URL.String()), nil
				}
				return inst, "", nil
			}
		}
	}

	selected, err = p.selectInstance(backendName, strategy)
	if err != nil {
		return nil, "", err
	}
	if sticky.Cookie != "" && selected.URL != nil {
		return selected, stickyInstanceID(selected.URL.String()), nil
	}
	return selected, "", nil
}

func (p *Proxy) lookupStickyInstance(backendName, id string) (*instanceState, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := p.clock.Now()
	for _, state := range p.instances[backendName] {
		if state == nil || state.URL == nil || !state.Healthy {
			continue
		}
		if ejected, _ := state.outlier.ejectionStatus(now); ejected {
			continue
		}
		if state.circuit != nil && state.circuit.IsOpen() {
			continue
		}
		if stickyInstanceID(state.URL.String()) == id {
			return state, true
		}
	}
	return nil, false
}

func (p *Proxy) pickStickyByKey(backendName, key string) (*instanceState, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := p.clock.Now()
	healthy := make([]*instanceState, 0, len(p.instances[backendName]))
	for _, state := range p.instances[backendName] {
		if state == nil || state.URL == nil || !state.Healthy {
			continue
		}
		if ejected, _ := state.outlier.ejectionStatus(now); ejected {
			continue
		}
		if state.circuit != nil && state.circuit.IsOpen() {
			continue
		}
		healthy = append(healthy, state)
	}
	if len(healthy) == 0 {
		return nil, false
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	idx := int(h.Sum32()) % len(healthy)
	return healthy[idx], true
}

func buildStickyCookie(sticky *config.RouteStickyRuntime, value string) *http.Cookie {
	if sticky == nil || sticky.Cookie == "" || value == "" {
		return nil
	}
	path := sticky.CookiePath
	if path == "" {
		path = "/"
	}
	c := &http.Cookie{
		Name:     sticky.Cookie,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		Secure:   true, // affinity cookies are only meaningful on HTTPS edges
		SameSite: http.SameSiteLaxMode,
	}
	if sticky.CookieTTL > 0 {
		c.MaxAge = int(sticky.CookieTTL / time.Second)
		if c.MaxAge == 0 {
			c.MaxAge = 1
		}
	}
	return c
}

type stickyResponseWriter struct {
	http.ResponseWriter
	cookie  *http.Cookie
	wrote   bool
	writeMu sync.Mutex
}

func (w *stickyResponseWriter) WriteHeader(status int) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if !w.wrote {
		if w.cookie != nil {
			http.SetCookie(w.ResponseWriter, w.cookie)
		}
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *stickyResponseWriter) Write(b []byte) (int, error) {
	w.writeMu.Lock()
	if !w.wrote {
		if w.cookie != nil {
			http.SetCookie(w.ResponseWriter, w.cookie)
		}
		w.wrote = true
	}
	w.writeMu.Unlock()
	return w.ResponseWriter.Write(b)
}

func (w *stickyResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (p *Proxy) mirrorGate(routeName string, maxConcurrent int) *bulkhead {
	if maxConcurrent <= 0 {
		maxConcurrent = 32
	}
	p.mirrorMu.Lock()
	defer p.mirrorMu.Unlock()
	if p.mirrorGates == nil {
		p.mirrorGates = make(map[string]*bulkhead)
	}
	if g, ok := p.mirrorGates[routeName]; ok {
		return g
	}
	g := newBulkhead(maxConcurrent)
	p.mirrorGates[routeName] = g
	return g
}

// maybeMirrorRequest launches a best-effort async shadow request. It never
// affects the client response. Bodies and sensitive headers are excluded unless
// explicitly configured otherwise.
func (p *Proxy) maybeMirrorRequest(
	route *config.RouteRuntime,
	r *http.Request,
	clientIP string,
	bodyBytes []byte,
	bodyBuffered bool,
) {
	if p == nil || route == nil || route.Traffic == nil || route.Traffic.Mirror == nil || r == nil {
		return
	}
	mirror := route.Traffic.Mirror
	if mirror.Percent <= 0 {
		return
	}

	var keyHeader, keyCookie string
	if route.Traffic.Canary != nil {
		keyHeader = route.Traffic.Canary.KeyHeader
		keyCookie = route.Traffic.Canary.KeyCookie
	}
	key := trafficKey(r, clientIP, keyHeader, keyCookie)
	if trafficBucket("mirror:"+key) >= mirror.Percent {
		return
	}

	backend, ok := p.backends[mirror.Backend]
	if !ok || !p.backendHasSelectableInstance(mirror.Backend) {
		return
	}

	gate := p.mirrorGate(route.Name, mirror.MaxConcurrent)
	if !gate.Acquire() {
		return
	}

	method := r.Method
	reqPath := r.URL.Path
	rawQuery := r.URL.RawQuery
	header := cloneMirrorHeaders(r.Header, mirror.ExcludeHeaders)

	var body []byte
	forwardBody := !mirror.ExcludeRequestBody && bodyBuffered && len(bodyBytes) > 0
	if forwardBody {
		body = append([]byte(nil), bodyBytes...)
	}

	timeout := mirror.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	strategy := backend.Strategy
	backendName := mirror.Backend

	p.mirrorWG.Add(1)
	go func() {
		defer p.mirrorWG.Done()
		defer gate.Release()

		ctx, cancel := context.WithTimeout(p.ctx, timeout)
		defer cancel()

		selected, selErr := p.selectInstance(backendName, strategy)
		if selErr != nil {
			return
		}
		defer p.releaseInstance(backendName, selected)

		if selected.circuit != nil && !selected.circuit.Allow() {
			return
		}

		target := selected.URL.ResolveReference(&url.URL{Path: reqPath, RawQuery: rawQuery})

		var bodyReader io.ReadCloser = http.NoBody
		contentLength := int64(0)
		if forwardBody {
			bodyReader = io.NopCloser(bytes.NewReader(body))
			contentLength = int64(len(body))
		}

		outReq, err := http.NewRequestWithContext(ctx, method, target.String(), bodyReader)
		if err != nil {
			return
		}
		outReq.URL = target
		outReq.Host = target.Host
		outReq.Header = header
		outReq.ContentLength = contentLength
		if !forwardBody {
			outReq.Header.Del("Content-Length")
			outReq.Header.Del("Content-Type")
			outReq.ContentLength = 0
		}

		transport := p.transportFor(backendName, selected.circuit)
		resp, err := transport.RoundTrip(outReq)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()
}

func cloneMirrorHeaders(in http.Header, extraExclude []string) http.Header {
	out := in.Clone()
	if out == nil {
		out = make(http.Header)
	}
	for _, h := range mirrorSensitiveHeaders {
		out.Del(h)
	}
	for _, h := range clientIdentityHeaders {
		out.Del(h)
	}
	for _, h := range extraExclude {
		out.Del(h)
	}
	for _, h := range hopHeaders {
		out.Del(h)
	}
	return out
}
