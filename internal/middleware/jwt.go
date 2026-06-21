package middleware

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

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
	// Algorithm selects the verification strategy: "hs256" (default) or "rs256".
	Algorithm       string
	// HS256
	Secret          string
	// RS256 with static PEM key
	PublicKeyFile   string
	// RS256 with JWKS endpoint
	JWKSUrl         string
	JWKSCacheTTL    time.Duration
	// Common
	Header          string
	ClaimsToHeaders map[string]string
	Logger          *slog.Logger
	LogFailures     bool
}

func NewJWT(cfg JWTConfig) (Middleware, error) {
	if strings.TrimSpace(cfg.Header) == "" {
		cfg.Header = "Authorization"
	}
	claimsToHeaders := normalizeClaimsToHeaders(cfg.ClaimsToHeaders)

	alg := strings.ToLower(strings.TrimSpace(cfg.Algorithm))
	if alg == "" {
		alg = "hs256"
	}

	switch alg {
	case "hs256":
		return newJWTHS256(cfg, claimsToHeaders)
	case "rs256":
		if strings.TrimSpace(cfg.JWKSUrl) != "" {
			return newJWTJWKS(cfg, claimsToHeaders)
		}
		return newJWTRS256Static(cfg, claimsToHeaders)
	default:
		return nil, fmt.Errorf("jwt: unsupported algorithm %q", alg)
	}
}

func newJWTHS256(cfg JWTConfig, claimsToHeaders map[string]string) (Middleware, error) {
	secret := strings.TrimSpace(cfg.Secret)
	if secret == "" {
		return nil, fmt.Errorf("jwt: secret is required for hs256")
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("jwt: secret must be at least 32 bytes")
	}
	if cfg.Logger != nil {
		cfg.Logger.Info("jwt middleware initialized",
			"algorithm", "hs256",
			"header", cfg.Header,
			"claims_to_headers", len(claimsToHeaders),
		)
	}
	keyfunc := func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(secret), nil
	}
	return jwtHandler(cfg, claimsToHeaders, keyfunc, []string{"HS256", "HS384", "HS512"}), nil
}

func newJWTRS256Static(cfg JWTConfig, claimsToHeaders map[string]string) (Middleware, error) {
	pubKey, err := loadRSAPublicKeyPEM(cfg.PublicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("jwt: %w", err)
	}
	if cfg.Logger != nil {
		cfg.Logger.Info("jwt middleware initialized",
			"algorithm", "rs256",
			"header", cfg.Header,
			"public_key_file", cfg.PublicKeyFile,
			"claims_to_headers", len(claimsToHeaders),
		)
	}
	keyfunc := func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return pubKey, nil
	}
	return jwtHandler(cfg, claimsToHeaders, keyfunc, []string{"RS256", "RS384", "RS512"}), nil
}

func newJWTJWKS(cfg JWTConfig, claimsToHeaders map[string]string) (Middleware, error) {
	cache := newJWKSCache(strings.TrimSpace(cfg.JWKSUrl), cfg.JWKSCacheTTL)
	if cfg.Logger != nil {
		cfg.Logger.Info("jwt middleware initialized",
			"algorithm", "rs256",
			"header", cfg.Header,
			"jwks_url", cfg.JWKSUrl,
			"jwks_cache_ttl", cache.ttl,
			"claims_to_headers", len(claimsToHeaders),
		)
	}
	return jwtHandler(cfg, claimsToHeaders, cache.Keyfunc, []string{"RS256"}), nil
}

// jwtHandler builds the actual middleware handler given a keyfunc and allowed methods.
func jwtHandler(cfg JWTConfig, claimsToHeaders map[string]string, keyfunc jwt.Keyfunc, validMethods []string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, ok := readTokenFromHeader(r, cfg.Header)
			if !ok {
				cfg.logReject(r, "missing_or_malformed_authorization", nil, "",
					slog.String("note", "expected Bearer scheme when header is Authorization"))
				httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			token, err := jwt.Parse(tokenString, keyfunc,
				jwt.WithValidMethods(validMethods),
				jwt.WithExpirationRequired(),
				jwt.WithIssuedAt(),
			)
			if err != nil || token == nil || !token.Valid {
				cfg.logReject(r, "invalid_token", err, tokenString,
					slog.Bool("parser_reports_valid", token != nil && token.Valid))
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
			} else {
				stripAndInjectMappedClaims(r, claims, claimsToHeaders)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// loadRSAPublicKeyPEM reads a PEM file and returns the RSA public key.
// Supports PKIX ("PUBLIC KEY") and PKCS1 ("RSA PUBLIC KEY") formats.
func loadRSAPublicKeyPEM(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key file %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}
	switch block.Type {
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PEM key is not RSA")
		}
		return rsaPub, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
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
