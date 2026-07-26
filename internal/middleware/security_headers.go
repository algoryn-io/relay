package middleware

import (
	"fmt"
	"net/http"
	"strings"
)

const securityHeaderOff = "off"

type SecurityHeadersConfig struct {
	Preset                  string
	StrictTransportSecurity string
	ContentSecurityPolicy   string
	XFrameOptions           string
	XContentTypeOptions     string
	ReferrerPolicy          string
	PermissionsPolicy       string
}

var securityHeaderPresets = map[string]map[string]string{
	"secure": {
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'self'; object-src 'none'; base-uri 'self'",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
	},
	"strict": {
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
		"Content-Security-Policy":   "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
	},
}

func NewSecurityHeaders(cfg SecurityHeadersConfig) (Middleware, error) {
	if err := validateSecurityHeaderOverrides(cfg); err != nil {
		return nil, err
	}
	preset := strings.ToLower(strings.TrimSpace(cfg.Preset))
	headers := make(map[string]string)
	if preset != "" {
		values, ok := securityHeaderPresets[preset]
		if !ok {
			return nil, fmt.Errorf("security_headers: unknown preset %q", cfg.Preset)
		}
		for name, value := range values {
			headers[name] = value
		}
	}

	overrides := map[string]string{
		"Strict-Transport-Security": cfg.StrictTransportSecurity,
		"Content-Security-Policy":   cfg.ContentSecurityPolicy,
		"X-Frame-Options":           cfg.XFrameOptions,
		"X-Content-Type-Options":    cfg.XContentTypeOptions,
		"Referrer-Policy":           cfg.ReferrerPolicy,
		"Permissions-Policy":        cfg.PermissionsPolicy,
	}
	for name, value := range overrides {
		value = strings.TrimSpace(value)
		switch {
		case value == "":
		case strings.EqualFold(value, securityHeaderOff):
			delete(headers, name)
		default:
			headers[name] = value
		}
	}
	if len(headers) == 0 {
		return nil, fmt.Errorf("security_headers: preset or at least one enabled header is required")
	}
	if _, hasXFO := headers["X-Frame-Options"]; hasXFO && cspHasFrameAncestors(headers["Content-Security-Policy"]) {
		return nil, fmt.Errorf("security_headers: X-Frame-Options conflicts with CSP frame-ancestors")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writer := &securityHeadersWriter{ResponseWriter: w, headers: headers}
			writer.apply()
			next.ServeHTTP(writer, r)
		})
	}, nil
}

func validateSecurityHeaderOverrides(cfg SecurityHeadersConfig) error {
	values := map[string]string{
		"strict_transport_security": cfg.StrictTransportSecurity,
		"content_security_policy":   cfg.ContentSecurityPolicy,
		"x_frame_options":           cfg.XFrameOptions,
		"x_content_type_options":    cfg.XContentTypeOptions,
		"referrer_policy":           cfg.ReferrerPolicy,
		"permissions_policy":        cfg.PermissionsPolicy,
	}
	for name, value := range values {
		for _, r := range value {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("security_headers: %s contains a control character", name)
			}
		}
	}
	if value := strings.ToUpper(strings.TrimSpace(cfg.XFrameOptions)); value != "" && value != "OFF" && value != "DENY" && value != "SAMEORIGIN" {
		return fmt.Errorf("security_headers: x_frame_options must be DENY, SAMEORIGIN, or off")
	}
	if value := strings.ToLower(strings.TrimSpace(cfg.XContentTypeOptions)); value != "" && value != "off" && value != "nosniff" {
		return fmt.Errorf("security_headers: x_content_type_options must be nosniff or off")
	}
	csp := strings.ToLower(cfg.ContentSecurityPolicy)
	if strings.Contains(csp, "'unsafe-inline'") || strings.Contains(csp, "'unsafe-eval'") {
		return fmt.Errorf("security_headers: unsafe-inline and unsafe-eval are not allowed")
	}
	if strings.Contains(cfg.PermissionsPolicy, "*") {
		return fmt.Errorf("security_headers: wildcard permissions are not allowed")
	}
	if strings.EqualFold(strings.TrimSpace(cfg.ReferrerPolicy), "unsafe-url") {
		return fmt.Errorf("security_headers: unsafe-url referrer policy is not allowed")
	}
	return nil
}

type securityHeadersWriter struct {
	http.ResponseWriter
	headers     map[string]string
	wroteHeader bool
}

func (w *securityHeadersWriter) apply() {
	for name, value := range w.headers {
		w.ResponseWriter.Header().Set(name, value)
	}
}

func (w *securityHeadersWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.apply()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *securityHeadersWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *securityHeadersWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func cspHasFrameAncestors(value string) bool {
	for _, directive := range strings.Split(value, ";") {
		fields := strings.Fields(directive)
		if len(fields) > 0 && strings.EqualFold(fields[0], "frame-ancestors") {
			return true
		}
	}
	return false
}
