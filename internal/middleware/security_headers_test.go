package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"algoryn.io/relay/internal/config"
)

func TestSecurityHeadersSecurePreset(t *testing.T) {
	t.Parallel()

	mw, err := NewSecurityHeaders(SecurityHeadersConfig{Preset: "secure"})
	if err != nil {
		t.Fatalf("NewSecurityHeaders() error = %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Middleware must replace a weaker downstream value.
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'self'; object-src 'none'; base-uri 'self'",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
	}
	for name, value := range want {
		if got := rec.Header().Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

func TestSecurityHeadersOverridesAndOff(t *testing.T) {
	t.Parallel()

	mw, err := NewSecurityHeaders(SecurityHeadersConfig{
		Preset:                "secure",
		XFrameOptions:         "off",
		ContentSecurityPolicy: "default-src 'self'; frame-ancestors 'self'",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	})
	if err != nil {
		t.Fatalf("NewSecurityHeaders() error = %v", err)
	}
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("X-Frame-Options"); got != "" {
		t.Fatalf("X-Frame-Options = %q, want disabled", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'self'; frame-ancestors 'self'" {
		t.Fatalf("Content-Security-Policy = %q", got)
	}
}

func TestSecurityHeadersRejectsFramingConflict(t *testing.T) {
	t.Parallel()

	_, err := NewSecurityHeaders(SecurityHeadersConfig{
		ContentSecurityPolicy: "frame-ancestors 'none'",
		XFrameOptions:         "DENY",
	})
	if err == nil {
		t.Fatal("NewSecurityHeaders() error = nil, want framing conflict")
	}
}

func TestSecurityHeadersRejectsUnsafeDirectConfiguration(t *testing.T) {
	t.Parallel()

	_, err := NewSecurityHeaders(SecurityHeadersConfig{
		ContentSecurityPolicy: "script-src 'unsafe-inline'",
	})
	if err == nil {
		t.Fatal("NewSecurityHeaders() error = nil, want unsafe CSP rejection")
	}
}

func TestFactoryBuildsSecurityHeaders(t *testing.T) {
	t.Parallel()

	mw, closer, err := Build(config.MiddlewareRuntime{
		Name: "browser-security",
		Type: "security_headers",
		Config: config.MiddlewareSettingsConfig{
			SecurityHeadersPreset: "strict",
		},
	}, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if closer != nil {
		t.Fatal("security_headers unexpectedly returned a closer")
	}
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatal("Content-Security-Policy was not set")
	}
}
