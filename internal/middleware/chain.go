package middleware

import "net/http"

type Middleware func(http.Handler) http.Handler

func Chain(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		if next == nil {
			next = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		}
		for i := len(middlewares) - 1; i >= 0; i-- {
			if middlewares[i] == nil {
				continue
			}
			next = middlewares[i](next)
		}
		return next
	}
}

func Resolve(names []string, registry map[string]Middleware) []Middleware {
	out := make([]Middleware, 0, len(names))
	for _, name := range names {
		m, ok := registry[name]
		if !ok {
			continue
		}
		out = append(out, m)
	}
	return out
}
