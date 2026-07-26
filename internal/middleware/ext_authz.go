package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"algoryn.io/relay/internal/httpx"
	"golang.org/x/net/http/httpguts"
)

const (
	defaultExtAuthzTimeout      = 2 * time.Second
	defaultExtAuthzMaxBodyBytes = 1 << 20
	extAuthzSubjectHeader       = "X-Relay-Auth-Subject"
	extAuthzTenantHeader        = "X-Relay-Auth-Tenant"
	extAuthzKeyIDHeader         = "X-Relay-Auth-Key-Id"
	extAuthzClaimHeaderPrefix   = "X-Relay-Auth-Claim-"
)

type ExtAuthzBodyMode string

const (
	ExtAuthzBodyNone     ExtAuthzBodyMode = "none"
	ExtAuthzBodyOriginal ExtAuthzBodyMode = "original"
	ExtAuthzBodyMetadata ExtAuthzBodyMode = "metadata"
)

// ExtAuthzConfig configures the external authorization middleware. Each request
// is checked against an external HTTP authorization service (Envoy ext_authz
// style) before it is forwarded to the backend.
type ExtAuthzConfig struct {
	// URL is the external authorization endpoint.
	URL string
	// Method is the method used for the authorization call. Defaults to GET.
	Method string
	// Body controls the authorization request body: none (default), original,
	// or metadata. Body-bearing modes require POST.
	Body ExtAuthzBodyMode
	// MaxBodyBytes bounds original request bodies buffered for authorization and
	// safe replay to the upstream. Defaults to 1 MiB.
	MaxBodyBytes int64
	// ContentType overrides the authorization request Content-Type. Metadata
	// bodies default to application/json and original bodies inherit the inbound
	// Content-Type (falling back to application/octet-stream).
	ContentType string
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
	// AllowInsecureHTTP explicitly permits an HTTP authorization endpoint.
	AllowInsecureHTTP bool
	// Client overrides the HTTP client (tests).
	Client *http.Client
	Logger *slog.Logger
}

type extAuthzMiddleware struct {
	url            string
	method         string
	body           ExtAuthzBodyMode
	maxBodyBytes   int64
	contentType    string
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
	if u, err := url.Parse(strings.TrimSpace(cfg.URL)); err != nil || u.Scheme != "https" && !(u.Scheme == "http" && cfg.AllowInsecureHTTP) {
		return nil, fmt.Errorf("ext_authz: url must be https unless allow_insecure_http is set")
	}
	method := strings.ToUpper(strings.TrimSpace(cfg.Method))
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodHead:
	default:
		return nil, fmt.Errorf("ext_authz: method must be GET, POST, or HEAD")
	}
	bodyMode := ExtAuthzBodyMode(strings.ToLower(strings.TrimSpace(string(cfg.Body))))
	if bodyMode == "" {
		bodyMode = ExtAuthzBodyNone
	}
	switch bodyMode {
	case ExtAuthzBodyNone:
	case ExtAuthzBodyOriginal, ExtAuthzBodyMetadata:
		if method != http.MethodPost {
			return nil, fmt.Errorf("ext_authz: body %q requires method POST", bodyMode)
		}
	default:
		return nil, fmt.Errorf("ext_authz: body must be none, original, or metadata")
	}
	maxBodyBytes := cfg.MaxBodyBytes
	if maxBodyBytes < 0 || maxBodyBytes == math.MaxInt64 {
		return nil, fmt.Errorf("ext_authz: max_body_bytes must be between 0 and %d", int64(math.MaxInt64-1))
	}
	if maxBodyBytes == 0 {
		maxBodyBytes = defaultExtAuthzMaxBodyBytes
	}
	contentType := strings.TrimSpace(cfg.ContentType)
	if bodyMode == ExtAuthzBodyNone && contentType != "" {
		return nil, fmt.Errorf("ext_authz: content_type requires a request body")
	}
	if contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			return nil, fmt.Errorf("ext_authz: invalid content_type: %w", err)
		}
		if bodyMode == ExtAuthzBodyMetadata && mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
			return nil, fmt.Errorf("ext_authz: metadata content_type must be application/json or +json")
		}
	}
	forwardHeaders, err := canonicalizeHeaderList(cfg.ForwardHeaders)
	if err != nil {
		return nil, fmt.Errorf("ext_authz: forward_headers: %w", err)
	}
	copyHeaders, err := canonicalizeHeaderList(cfg.CopyHeaders)
	if err != nil {
		return nil, fmt.Errorf("ext_authz: copy_headers: %w", err)
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
		method:         method,
		body:           bodyMode,
		maxBodyBytes:   maxBodyBytes,
		contentType:    contentType,
		forwardHeaders: forwardHeaders,
		copyHeaders:    copyHeaders,
		failOpen:       cfg.FailOpen,
		client:         client,
		logger:         cfg.Logger,
	}
	return m.handler, nil
}

func canonicalizeHeaderList(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, h := range in {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if !httpguts.ValidHeaderFieldName(h) {
			return nil, fmt.Errorf("invalid header name %q", h)
		}
		h = http.CanonicalHeaderKey(h)
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	return out, nil
}

func (m *extAuthzMiddleware) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never forward client-spoofed Relay auth headers on any path, including
		// fail-open bypasses where withAuthIdentity is not called.
		stripClientAuthIdentityHeaders(r)

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
			var requestErr *extAuthzRequestError
			if errors.As(err, &requestErr) {
				if m.failOpen && requestErr.failOpenSafe && r.Context().Err() == nil {
					next.ServeHTTP(w, r)
					return
				}
				httpx.WriteError(w, requestErr.status, requestErr.code)
				return
			}
			if m.failOpen && r.Context().Err() == nil {
				next.ServeHTTP(w, r)
				return
			}
			httpx.WriteError(w, http.StatusServiceUnavailable, "authz_unavailable")
			return
		}
		defer resp.Body.Close()

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			claims := make(map[string]string)
			for name, values := range resp.Header {
				if strings.HasPrefix(http.CanonicalHeaderKey(name), extAuthzClaimHeaderPrefix) && len(values) != 0 {
					claim := strings.TrimPrefix(http.CanonicalHeaderKey(name), extAuthzClaimHeaderPrefix)
					if claim != "" {
						claims[strings.ToLower(claim)] = values[0]
					}
				}
			}
			// Publish Relay-owned identity first (also strips client spoof of
			// X-Relay-Auth-*). Then graft authorizer copy_headers so operators
			// can still forward those values upstream when explicitly listed.
			r = withAuthIdentity(r, AuthIdentity{
				Source:  "ext_authz",
				Subject: resp.Header.Get(extAuthzSubjectHeader),
				Tenant:  resp.Header.Get(extAuthzTenantHeader),
				KeyID:   resp.Header.Get(extAuthzKeyIDHeader),
				Claims:  claims,
			})
			for _, h := range m.copyHeaders {
				r.Header.Del(h)
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
			if m.failOpen && r.Context().Err() == nil {
				next.ServeHTTP(w, r)
				return
			}
			httpx.WriteError(w, http.StatusServiceUnavailable, "authz_unavailable")
		}
	})
}

type extAuthzRequestError struct {
	status       int
	code         string
	failOpenSafe bool
	err          error
}

func (e *extAuthzRequestError) Error() string { return e.err.Error() }
func (e *extAuthzRequestError) Unwrap() error { return e.err }

type extAuthzMetadata struct {
	Method       string                `json:"method"`
	Path         string                `json:"path"`
	Host         string                `json:"host"`
	ClientIP     string                `json:"client_ip,omitempty"`
	Headers      map[string][]string   `json:"headers,omitempty"`
	RequestID    string                `json:"request_id,omitempty"`
	MTLSIdentity *extAuthzMTLSIdentity `json:"mtls_identity,omitempty"`
}

type extAuthzMTLSIdentity struct {
	Subject        string   `json:"subject"`
	DNSNames       []string `json:"dns_names,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`
}

func (m *extAuthzMiddleware) check(r *http.Request) (*http.Response, error) {
	body, contentType, err := m.authorizationBody(r)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(r.Context(), m.method, m.url, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	for _, h := range m.forwardHeaders {
		for _, v := range r.Header.Values(h) {
			req.Header.Add(h, v)
		}
	}
	// Set Relay-owned contract headers after allowlisted headers so inbound
	// values cannot append to or spoof them.
	req.Header.Set("X-Forwarded-Method", r.Method)
	req.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
	req.Header.Set("X-Forwarded-Host", r.Host)
	if ip := httpx.ClientIP(r); ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// The destination is the administrator-configured and validated authz URL;
	// no request-derived value can select or alter it.
	return m.client.Do(req) // #nosec G704 -- intentional call to the configured authorization service
}

func (m *extAuthzMiddleware) authorizationBody(r *http.Request) (io.Reader, string, error) {
	switch m.body {
	case ExtAuthzBodyNone:
		return nil, "", nil
	case ExtAuthzBodyMetadata:
		body, err := json.Marshal(m.metadata(r))
		if err != nil {
			return nil, "", fmt.Errorf("marshal metadata: %w", err)
		}
		if int64(len(body)) > m.maxBodyBytes {
			return nil, "", bodyTooLargeError(m.maxBodyBytes)
		}
		contentType := m.contentType
		if contentType == "" {
			contentType = "application/json"
		}
		return bytes.NewReader(body), contentType, nil
	case ExtAuthzBodyOriginal:
		return m.originalBody(r)
	default:
		return nil, "", fmt.Errorf("unsupported body mode %q", m.body)
	}
}

func (m *extAuthzMiddleware) originalBody(r *http.Request) (io.Reader, string, error) {
	if isUpgradeRequest(r) || len(r.TransferEncoding) > 0 {
		return nil, "", &extAuthzRequestError{
			status:       http.StatusServiceUnavailable,
			code:         "authz_body_unavailable",
			failOpenSafe: true,
			err:          fmt.Errorf("original body is streaming or an upgrade request"),
		}
	}
	if r.ContentLength > m.maxBodyBytes {
		return nil, "", bodyTooLargeError(m.maxBodyBytes)
	}

	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, m.maxBodyBytes+1))
		if err != nil {
			return nil, "", &extAuthzRequestError{
				status: http.StatusServiceUnavailable,
				code:   "authz_body_unavailable",
				err:    fmt.Errorf("read original body: %w", err),
			}
		}
		if int64(len(body)) > m.maxBodyBytes {
			return nil, "", bodyTooLargeError(m.maxBodyBytes)
		}
		_ = r.Body.Close()
	}
	if err := r.Context().Err(); err != nil {
		return nil, "", &extAuthzRequestError{
			status: http.StatusServiceUnavailable,
			code:   "authz_unavailable",
			err:    fmt.Errorf("request canceled while buffering body: %w", err),
		}
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	contentType := m.contentType
	if contentType == "" {
		contentType = r.Header.Get("Content-Type")
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return bytes.NewReader(body), contentType, nil
}

func bodyTooLargeError(maxBytes int64) error {
	return &extAuthzRequestError{
		status: http.StatusRequestEntityTooLarge,
		code:   "authz_body_too_large",
		err:    fmt.Errorf("authorization body exceeds %d bytes", maxBytes),
	}
}

func isUpgradeRequest(r *http.Request) bool {
	return strings.TrimSpace(r.Header.Get("Upgrade")) != "" ||
		headerHasToken(r.Header.Get("Connection"), "upgrade")
}

func headerHasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func (m *extAuthzMiddleware) metadata(r *http.Request) extAuthzMetadata {
	headers := make(map[string][]string, len(m.forwardHeaders))
	for _, name := range m.forwardHeaders {
		if values := r.Header.Values(name); len(values) > 0 {
			headers[name] = append([]string(nil), values...)
		}
	}
	metadata := extAuthzMetadata{
		Method:    r.Method,
		Path:      r.URL.RequestURI(),
		Host:      r.Host,
		ClientIP:  httpx.ClientIP(r),
		Headers:   headers,
		RequestID: httpx.GetRequestID(r),
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return metadata
	}
	cert := r.TLS.VerifiedChains[0][0]
	identity := &extAuthzMTLSIdentity{
		Subject:        cert.Subject.String(),
		DNSNames:       append([]string(nil), cert.DNSNames...),
		EmailAddresses: append([]string(nil), cert.EmailAddresses...),
	}
	for _, uri := range cert.URIs {
		identity.URIs = append(identity.URIs, uri.String())
	}
	metadata.MTLSIdentity = identity
	return metadata
}
