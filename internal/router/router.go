package router

import (
	"net/http"

	"algoryn.io/relay/internal/config"
)

type contextKey string

const (
	ContextKeyBackend     contextKey = "relay.backend"
	ContextKeyMiddlewares contextKey = "relay.middlewares"
)

type Router struct {
	mux *http.ServeMux
}

var _ http.Handler = (*Router)(nil)

func New(routes []config.RouteConfig) *Router {
	r := &Router{mux: http.NewServeMux()}
	for _, route := range routes {
		r.register(route)
	}
	return r
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

func (r *Router) register(route config.RouteConfig) {
	_ = route
	// TODO: register route matchers and inject backend/middleware metadata into request context.
}
