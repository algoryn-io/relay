package middleware

import "net/http"

type IPFilterConfig struct {
	Whitelist []string
	Blacklist []string
}

func NewIPFilter(cfg IPFilterConfig) Middleware {
	_ = cfg
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: implement CIDR and exact-IP allow/deny filtering for client addresses.
			next.ServeHTTP(w, r)
		})
	}
}
