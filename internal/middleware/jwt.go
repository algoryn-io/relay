package middleware

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
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
	Logger          *slog.Logger
	LogFailures     bool
}

func NewJWT(cfg JWTConfig) (Middleware, error) {
	if strings.TrimSpace(cfg.Secret) == "" {
		return nil, fmt.Errorf("jwt secret is required")
	}
	secret := strings.TrimSpace(cfg.Secret)
	if len(secret) < 32 {
		return nil, fmt.Errorf("jwt secret must be at least 32 bytes")
	}
	if strings.TrimSpace(cfg.Header) == "" {
		cfg.Header = "Authorization"
	}

	claimsToHeaders := normalizeClaimsToHeaders(cfg.ClaimsToHeaders)

	if cfg.Logger != nil {
		cfg.Logger.Info("jwt middleware initialized",
			"authorization_header", cfg.Header,
			"secret_byte_length", len(secret),
			"claims_to_headers_mappings", len(claimsToHeaders),
			"jwt_log_failures", cfg.LogFailures,
		)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, ok := readTokenFromHeader(r, cfg.Header)
			if !ok {
				cfg.logReject(r, "missing_or_malformed_authorization", nil, "",
					slog.String("note", "expected Bearer scheme when header is Authorization"))
				httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return []byte(secret), nil
			}, jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
			if err != nil || token == nil || !token.Valid {
				cfg.logReject(r, "invalid_token", err, tokenString, slog.Bool("parser_reports_valid", token != nil && token.Valid))
				httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				cfg.logReject(r, "claims_not_map", nil, tokenString)
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

func (cfg JWTConfig) logReject(r *http.Request, reason string, parseErr error, rawJWT string, extra ...slog.Attr) {
	if !cfg.LogFailures || cfg.Logger == nil {
		return
	}
	attrs := []any{
		slog.String("event", "jwt_rejected"),
		slog.String("reason", reason),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	}
	if parseErr != nil {
		attrs = append(attrs, slog.String("parse_error", parseErr.Error()))
	}
	for _, a := range extra {
		attrs = append(attrs, a)
	}
	if rawJWT != "" {
		if keys, exp, inspErr := inspectJWTPayload(rawJWT); inspErr != nil {
			attrs = append(attrs, slog.String("payload_inspect_error", inspErr.Error()))
		} else {
			attrs = append(attrs,
				slog.Any("payload_claim_keys", keys),
				slog.Any("payload_exp", exp),
			)
		}
	}
	cfg.Logger.WarnContext(r.Context(), "jwt unauthorized", attrs...)
}

// inspectJWTPayload decodes the JWT payload segment without verifying the signature.
// Used only for troubleshooting (jwt_log_failures). Never log the full token.
func inspectJWTPayload(token string) (keys []string, exp any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("expected 3 JWT segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("payload base64: %w", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, nil, fmt.Errorf("payload json: %w", err)
	}
	keys = make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var expAny any
	if raw, ok := m["exp"]; ok {
		var n json.Number
		if err := json.Unmarshal(raw, &n); err == nil {
			expAny = n.String()
		} else {
			var f float64
			if err := json.Unmarshal(raw, &f); err == nil {
				expAny = f
			} else {
				expAny = strings.Trim(string(raw), `"`)
			}
		}
	}
	return keys, expAny, nil
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
