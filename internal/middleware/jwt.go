package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"algoryn.io/relay/internal/httpx"
	"github.com/golang-jwt/jwt/v5"
)

type JWTConfig struct {
	Secret string
	Header string
}

func NewJWT(cfg JWTConfig) (Middleware, error) {
	if strings.TrimSpace(cfg.Secret) == "" {
		return nil, fmt.Errorf("jwt secret is required")
	}
	if len(strings.TrimSpace(cfg.Secret)) < 32 {
		return nil, fmt.Errorf("jwt secret must be at least 32 bytes")
	}
	if strings.TrimSpace(cfg.Header) == "" {
		cfg.Header = "Authorization"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, ok := readTokenFromHeader(r, cfg.Header)
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return []byte(cfg.Secret), nil
			}, jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
			if err != nil || token == nil || !token.Valid {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if sub, ok := claims["sub"].(string); ok && strings.TrimSpace(sub) != "" {
					r.Header.Set("X-Authenticated-Sub", sub)
				}
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

func readTokenFromHeader(r *http.Request, header string) (string, bool) {
	raw := strings.TrimSpace(r.Header.Get(header))
	if raw == "" {
		return "", false
	}

	if strings.EqualFold(header, "Authorization") {
		if len(raw) < len("Bearer ")+1 {
			return "", false
		}
		if !strings.EqualFold(raw[:len("Bearer ")], "Bearer ") {
			return "", false
		}
		raw = strings.TrimSpace(raw[len("Bearer "):])
		if raw == "" {
			return "", false
		}
	}

	return raw, true
}
