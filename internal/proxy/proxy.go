package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"algoryn.io/relay/internal/config"
)

type Proxy struct {
	backends map[string]config.BackendRuntime
}

func New(rt *config.RuntimeConfig) (*Proxy, error) {
	if rt == nil {
		return nil, fmt.Errorf("runtime config is nil")
	}

	return &Proxy{
		backends: rt.Backends,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, route *config.RouteRuntime) {
	if p == nil || route == nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	backend, ok := p.backends[route.BackendName]
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	if len(backend.Instances) == 0 {
		writeJSONError(w, http.StatusBadGateway, "bad_gateway")
		return
	}

	target, err := url.Parse(backend.Instances[0].URL)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalHost := req.Host
		proto := "http"
		if req.TLS != nil {
			proto = "https"
		}

		director(req)
		setForwardedHeaders(req, originalHost, proto)
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		writeJSONError(rw, http.StatusBadGateway, "bad_gateway")
	}

	proxy.ServeHTTP(w, r)
}

func setForwardedHeaders(req *http.Request, originalHost, proto string) {
	req.Header.Set("X-Forwarded-Host", originalHost)
	req.Header.Set("X-Forwarded-Proto", proto)
}

func writeJSONError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  code,
		"status": "error",
	})
}
