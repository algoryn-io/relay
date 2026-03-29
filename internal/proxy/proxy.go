package proxy

import (
	"net/http"
	"net/http/httputil"
)

type Proxy struct {
	reverseProxy *httputil.ReverseProxy
	registry     BackendRegistry
	balancer     Balancer
}

var _ http.Handler = (*Proxy)(nil)

func New(registry BackendRegistry, balancer Balancer) *Proxy {
	p := &Proxy{
		registry: registry,
		balancer: balancer,
	}
	p.reverseProxy = &httputil.ReverseProxy{
		Director:       p.director,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.reverseProxy.ServeHTTP(w, r)
}

func (p *Proxy) director(req *http.Request) {
	_ = req
	// TODO: implement backend resolution and request URL rewrite before proxy forwarding.
}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	_ = resp
	// TODO: implement response mutation hooks and telemetry enrichment for proxied traffic.
	return nil
}

func (p *Proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	_, _, _ = w, r, err
	// TODO: implement proxy error translation and fallback behavior for upstream failures.
}
