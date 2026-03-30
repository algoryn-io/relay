package middleware

import (
	"fmt"
	"net/http"
)

type Middleware func(http.Handler) http.Handler

func Chain(final http.Handler, middlewares ...Middleware) http.Handler {
	if final == nil {
		final = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}

	handler := final
	for i := len(middlewares) - 1; i >= 0; i-- {
		if middlewares[i] == nil {
			continue
		}
		handler = middlewares[i](handler)
	}
	return handler
}

func Resolve(names []string, registry map[string]Middleware) ([]Middleware, error) {
	out := make([]Middleware, 0, len(names))
	for _, name := range names {
		m, ok := registry[name]
		if !ok {
			return nil, fmt.Errorf("middleware %q not found", name)
		}
		out = append(out, m)
	}
	return out, nil
}
