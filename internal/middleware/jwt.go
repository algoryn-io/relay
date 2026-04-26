package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"algoryn.io/relay/internal/httpx"
	"github.com/golang-jwt/jwt/v5"
)

// defaultSubjectHeader is the default outgoing header for the "sub" claim when
// claims_to_headers is not configured. Kept in one place; deployment-specific
// names are set via claims_to_headers in config.
const defaultSubjectHeader = "X-Authenticated-Sub"

func normalizeClaimsToHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

type JWTConfig struct {
	Secret          string
	Header          string
	ClaimsToHeaders map[string]string
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

	claimsToHeaders := normalizeClaimsToHeaders(cfg.ClaimsToHeaders)

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

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			if len(claimsToHeaders) == 0 {
				stripAndSetSubOnly(r, claims)
				next.ServeHTTP(w, r)
				return
			}
			stripAndInjectMappedClaims(r, claims, claimsToHeaders)
			next.ServeHTTP(w, r)
		})
	}, nil
}

// stripAndSetSubOnly clears any client-supplied default subject header, then
// re-applies the value from a valid token (legacy behavior).
func stripAndSetSubOnly(r *http.Request, claims jwt.MapClaims) {
	r.Header.Del(defaultSubjectHeader)
	if sub, ok := stringFromClaim(claims, "sub"); ok {
		r.Header.Set(defaultSubjectHeader, sub)
	}
}

func stripAndInjectMappedClaims(r *http.Request, claims jwt.MapClaims, m map[string]string) {
	_, hasSubInMap := m["sub"]

	for _, dest := range m {
		if h := strings.TrimSpace(dest); h != "" {
			r.Header.Del(h)
		}
	}
	if !hasSubInMap {
		r.Header.Del(defaultSubjectHeader)
	}

	for claim, dest := range m {
		dest = strings.TrimSpace(dest)
		if dest == "" {
			continue
		}
		if v, ok := stringFromClaim(claims, claim); ok {
			r.Header.Set(dest, v)
		}
	}
	if !hasSubInMap {
		if sub, ok := stringFromClaim(claims, "sub"); ok {
			r.Header.Set(defaultSubjectHeader, sub)
		}
	}
}

func stringFromClaim(claims jwt.MapClaims, key string) (string, bool) {
	v, ok := claims[key]
	if !ok || v == nil {
		return "", false
	}

	switch x := v.(type) {
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return "", false
		}
		return s, true
	case float64:
		// json.Unmarshal uses float64 for numbers
		if x != float64(int64(x)) {
			return strconv.FormatFloat(x, 'f', -1, 64), true
		}
		return strconv.FormatInt(int64(x), 10), true
	case float32:
		return fmt.Sprint(x), true
	case int:
		return strconv.Itoa(x), true
	case int32:
		return strconv.FormatInt(int64(x), 10), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case bool:
		return strconv.FormatBool(x), true
	default:
		s := strings.TrimSpace(fmt.Sprint(x))
		if s == "" {
			return "", false
		}
		return s, true
	}
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
