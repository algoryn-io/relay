package middleware

import (
	"context"
	"net/http"
	"strings"
)

// AuthIdentity is Relay-owned authentication state. It is carried only in the
// request context, so client-supplied headers can never create or alter it.
// Values are identifiers and verified claims only; credentials and tokens must
// never be stored here.
type AuthIdentity struct {
	Source  string
	Subject string
	Tenant  string
	KeyID   string
	Claims  map[string]string
}

type authIdentityContextKey struct{}

func withAuthIdentity(r *http.Request, identity AuthIdentity) *http.Request {
	// Drop client-supplied Relay auth headers so they cannot reach upstream or
	// be mistaken for verified identity outside the private context value.
	stripClientAuthIdentityHeaders(r)

	identity.Source = strings.TrimSpace(identity.Source)
	identity.Subject = strings.TrimSpace(identity.Subject)
	identity.Tenant = strings.TrimSpace(identity.Tenant)
	identity.KeyID = strings.TrimSpace(identity.KeyID)
	if len(identity.Claims) != 0 {
		claims := make(map[string]string, len(identity.Claims))
		for name, value := range identity.Claims {
			if name = strings.TrimSpace(name); safeIdentityClaimName(name) {
				if value = strings.TrimSpace(value); value != "" {
					claims[name] = value
				}
			}
		}
		identity.Claims = claims
	}
	return r.WithContext(context.WithValue(r.Context(), authIdentityContextKey{}, identity))
}

func stripClientAuthIdentityHeaders(r *http.Request) {
	r.Header.Del(extAuthzSubjectHeader)
	r.Header.Del(extAuthzTenantHeader)
	r.Header.Del(extAuthzKeyIDHeader)
	for name := range r.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), extAuthzClaimHeaderPrefix) {
			r.Header.Del(name)
		}
	}
}

func safeIdentityClaimName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	switch name {
	case "api_key", "apikey", "authorization", "cookie", "password", "secret":
		return false
	}
	return !strings.Contains(name, "token") &&
		!strings.Contains(name, "password") &&
		!strings.Contains(name, "secret") &&
		!strings.Contains(name, "credential") &&
		!strings.Contains(name, "cookie")
}

func authIdentityFromRequest(r *http.Request) (AuthIdentity, bool) {
	identity, ok := r.Context().Value(authIdentityContextKey{}).(AuthIdentity)
	return identity, ok && identity.Source != ""
}
