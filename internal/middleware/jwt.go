package middleware

import "net/http"

type JWTConfig struct {
	Secret string
	Header string
}

func NewJWT(cfg JWTConfig) Middleware {
	_ = cfg
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: implement JWT signature validation using github.com/golang-jwt/jwt/v5.
			next.ServeHTTP(w, r)
		})
	}
}
