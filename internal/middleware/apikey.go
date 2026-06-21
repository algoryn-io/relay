package middleware

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"

	"algoryn.io/relay/internal/httpx"
)

// APIKeyConfig holds the options for the api_key middleware.
type APIKeyConfig struct {
	// KeyHeader is the request header that carries the API key. Default: X-API-Key.
	KeyHeader string
	// KeyQuery is the query-parameter name to fall back to when KeyHeader is
	// absent. Empty string disables query-parameter lookup.
	KeyQuery string
	// Keys maps each accepted secret to a caller identity string. The identity
	// is forwarded upstream via KeyToHeader when set.
	// Format of entries passed at construction time: "id:secret" → id="id",
	// secret="secret"; "secret" only → id=secret.
	Keys map[string]string // secret → id
	// KeyToHeader, when non-empty, sets this upstream request header to the
	// matched caller identity so backends can identify the caller.
	KeyToHeader string
}

type apiKeyEntry struct {
	secret []byte
	id     string
}

// NewAPIKey returns a Middleware that validates bearer API keys.
//
// Keys are compared in constant time to prevent timing side-channels.
// Requests missing the key receive 401 "missing_api_key"; requests with an
// invalid key receive 401 "invalid_api_key".
func NewAPIKey(cfg APIKeyConfig) (Middleware, error) {
	if len(cfg.Keys) == 0 {
		return nil, fmt.Errorf("at least one api key must be provided")
	}

	header := strings.TrimSpace(cfg.KeyHeader)
	if header == "" {
		header = "X-API-Key"
	}

	entries := make([]apiKeyEntry, 0, len(cfg.Keys))
	for secret, id := range cfg.Keys {
		if strings.TrimSpace(secret) == "" {
			continue
		}
		entries = append(entries, apiKeyEntry{secret: []byte(secret), id: id})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("all provided api keys are empty")
	}

	keyQuery := cfg.KeyQuery
	keyToHeader := cfg.KeyToHeader

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := strings.TrimSpace(r.Header.Get(header))
			if key == "" && keyQuery != "" {
				key = strings.TrimSpace(r.URL.Query().Get(keyQuery))
			}
			if key == "" {
				httpx.WriteError(w, http.StatusUnauthorized, "missing_api_key")
				return
			}

			given := []byte(key)
			matchedID := ""
			// Constant-time scan: visit every entry regardless of early match to
			// prevent timing attacks that enumerate valid keys.
			for _, e := range entries {
				if subtle.ConstantTimeCompare(given, e.secret) == 1 {
					matchedID = e.id
				}
			}
			if matchedID == "" {
				httpx.WriteError(w, http.StatusUnauthorized, "invalid_api_key")
				return
			}

			if keyToHeader != "" {
				r = r.Clone(r.Context())
				r.Header.Set(keyToHeader, matchedID)
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

// LoadAPIKeys parses key material from an already-resolved environment string
// and/or a keys file. Both sources use the same entry format:
//
//	"caller-id:sk-secret"  →  id = "caller-id",  secret = "sk-secret"
//	"sk-secret"            →  id = "sk-secret",   secret = "sk-secret"
//
// Entries in the env string are comma- or newline-separated. Entries in the
// file are one per line. Both sources may be used simultaneously; duplicate
// secrets are silently overwritten by the last occurrence.
func LoadAPIKeys(resolvedEnv, keysFile string) (map[string]string, error) {
	keys := make(map[string]string) // secret → id

	if resolvedEnv != "" {
		for _, entry := range splitKeyEntries(resolvedEnv) {
			id, secret := parseKeyEntry(entry)
			keys[secret] = id
		}
	}

	if keysFile != "" {
		data, err := os.ReadFile(keysFile)
		if err != nil {
			return nil, fmt.Errorf("read keys_file %q: %w", keysFile, err)
		}
		for _, entry := range splitKeyEntries(string(data)) {
			id, secret := parseKeyEntry(entry)
			keys[secret] = id
		}
	}

	return keys, nil
}

func splitKeyEntries(s string) []string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parseKeyEntry(entry string) (id, secret string) {
	id, secret, found := strings.Cut(entry, ":")
	if !found {
		return entry, entry
	}
	return id, secret
}
