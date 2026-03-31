package middleware

import (
	"net/http"
	"strings"
)

type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool
}

type corsMiddleware struct {
	allowCredentials bool
	allowedHeaders   []string
	allowedMethods   []string
	allowedOrigins   map[string]struct{}
	headerSet        map[string]struct{}
	methodSet        map[string]struct{}
}

func NewCORS(cfg CORSConfig) (Middleware, error) {
	mw := &corsMiddleware{
		allowCredentials: cfg.AllowCredentials,
		allowedHeaders:   append([]string(nil), cfg.AllowedHeaders...),
		allowedMethods:   make([]string, 0, len(cfg.AllowedMethods)),
		allowedOrigins:   make(map[string]struct{}, len(cfg.AllowedOrigins)),
		headerSet:        make(map[string]struct{}, len(cfg.AllowedHeaders)),
		methodSet:        make(map[string]struct{}, len(cfg.AllowedMethods)),
	}

	for _, origin := range cfg.AllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		mw.allowedOrigins[origin] = struct{}{}
	}

	for _, method := range cfg.AllowedMethods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			continue
		}
		mw.allowedMethods = append(mw.allowedMethods, method)
		mw.methodSet[method] = struct{}{}
	}

	for _, header := range cfg.AllowedHeaders {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}
		mw.headerSet[strings.ToLower(header)] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			_, originAllowed := mw.allowedOrigins[origin]
			if isPreflightRequest(r) {
				if !originAllowed || !mw.isMethodAllowed(r.Header.Get("Access-Control-Request-Method")) || !mw.areHeadersAllowed(r.Header.Get("Access-Control-Request-Headers")) {
					writeJSONError(w, http.StatusForbidden, "forbidden")
					return
				}
				appendVary(w.Header(), "Access-Control-Request-Method")
				appendVary(w.Header(), "Access-Control-Request-Headers")

				setCORSHeaders(w.Header(), origin, mw.allowedMethods, mw.allowedHeaders, mw.allowCredentials)
				w.WriteHeader(http.StatusNoContent)
				return
			}

			if originAllowed {
				setCORSHeaders(w.Header(), origin, nil, nil, mw.allowCredentials)
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

func isPreflightRequest(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		strings.TrimSpace(r.Header.Get("Origin")) != "" &&
		strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")) != ""
}

func (c *corsMiddleware) isMethodAllowed(method string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return false
	}
	_, ok := c.methodSet[method]
	return ok
}

func (c *corsMiddleware) areHeadersAllowed(requested string) bool {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return true
	}

	for _, header := range strings.Split(requested, ",") {
		header = strings.ToLower(strings.TrimSpace(header))
		if header == "" {
			continue
		}
		if _, ok := c.headerSet[header]; !ok {
			return false
		}
	}
	return true
}

func setCORSHeaders(header http.Header, origin string, methods, allowedHeaders []string, allowCredentials bool) {
	appendVary(header, "Origin")
	header.Set("Access-Control-Allow-Origin", origin)
	if allowCredentials {
		header.Set("Access-Control-Allow-Credentials", "true")
	}
	if len(methods) > 0 {
		header.Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
	}
	if len(allowedHeaders) > 0 {
		header.Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
	}
}

func appendVary(header http.Header, value string) {
	current := header.Values("Vary")
	for _, existing := range current {
		for _, part := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(part), value) {
				return
			}
		}
	}
	header.Add("Vary", value)
}
