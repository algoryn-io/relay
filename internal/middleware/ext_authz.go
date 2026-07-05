package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"algoryn.io/relay/internal/httpx"
)

const defaultExtAuthzTimeout = 2 * time.Second

// ExtAuthzConfig configures the external authorization middleware. Each request
// is checked against an external HTTP authorization service (Envoy ext_authz
// style) before it is forwarded to the backend.
type ExtAuthzConfig struct {
	// URL is the external authorization endpoint.
	URL string
	// ForwardHeaders lists inbound request headers to copy onto the authorization
	// probe so the authorizer can make its decision. The request method, path,
	// host and client IP are always forwarded.
	ForwardHeaders []string
	// CopyHeaders lists headers from a 2xx authorization response to inject into
	// the upstream request (e.g. an identity header the authorizer resolved).
	CopyHeaders []string
	// Timeout bounds each authorization call. Defaults to 2s.
	Timeout time.Duration
	// FailOpen controls behavior when the authorizer is unreachable or errors:
	// true allows the request through, false (default) denies with 503.
	FailOpen bool
	// Client overrides the HTTP client (tests).
	Client *http.Client
	Logger *slog.Logger
}

type extAuthzMiddleware struct {
	url            string
	forwardHeaders []string
	copyHeaders    []string
	failOpen       bool
	client         *http.Client
	logger         *slog.Logger
}

// NewExtAuthz builds the external authorization middleware.
func NewExtAuthz(cfg ExtAuthzConfig) (Middleware, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("ext_authz: url is required")
	}
	if u, err := url.Parse(strings.TrimSpace(cfg.URL)); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("ext_authz: url must be http or https")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultExtAuthzTimeout
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	m := &extAuthzMiddleware{
		url:            strings.TrimSpace(cfg.URL),
		forwardHeaders: canonicalizeHeaderList(cfg.ForwardHeaders),
		copyHeaders:    canonicalizeHeaderList(cfg.CopyHeaders),
		failOpen:       cfg.FailOpen,
		client:         client,
		logger:         cfg.Logger,
	}
	return m.handler, nil
}

func canonicalizeHeaderList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, http.CanonicalHeaderKey(h))
		}
	}
	return out
}

func (m *extAuthzMiddleware) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := m.check(r)
		if err != nil {
			if m.logger != nil {
				m.logger.WarnContext(r.Context(), "ext_authz check failed",
					"event", "ext_authz_error",
					"error", err.Error(),
					"fail_open", m.failOpen,
					"path", r.URL.Path,
				)
			}
			if m.failOpen {
				next.ServeHTTP(w, r)
				return
			}
			httpx.WriteError(w, http.StatusServiceUnavailable, "authz_unavailable")
			return
		}
		defer resp.Body.Close()

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			// Allowed: optionally graft headers the authorizer resolved onto the
			// upstream request (e.g. a verified identity).
			for _, h := range m.copyHeaders {
				if v := resp.Header.Get(h); v != "" {
					r.Header.Set(h, v)
				}
			}
			next.ServeHTTP(w, r)
		case resp.StatusCode == http.StatusUnauthorized:
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
		case resp.StatusCode == http.StatusForbidden:
			httpx.WriteError(w, http.StatusForbidden, "forbidden")
		default:
			// Any other status is treated as a decision failure.
			if m.logger != nil {
				m.logger.WarnContext(r.Context(), "ext_authz unexpected status",
					"event", "ext_authz_unexpected_status",
					"status", resp.StatusCode,
					"fail_open", m.failOpen,
				)
			}
			if m.failOpen {
				next.ServeHTTP(w, r)
				return
			}
			httpx.WriteError(w, http.StatusServiceUnavailable, "authz_unavailable")
		}
	})
}

func (m *extAuthzMiddleware) check(r *http.Request) (*http.Response, error) {
	ctx := r.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	// Describe the original request for the authorizer (Envoy ext_authz style).
	req.Header.Set("X-Forwarded-Method", r.Method)
	req.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
	req.Header.Set("X-Forwarded-Host", r.Host)
	if ip := httpx.ClientIP(r); ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	for _, h := range m.forwardHeaders {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}

	return m.client.Do(req)
}
