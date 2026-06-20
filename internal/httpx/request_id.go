package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

type requestIDKey struct{}

// WithRequestID stores the request ID in the request context.
func WithRequestID(r *http.Request, id string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
}

// GetRequestID returns the request ID from context, falling back to the X-Request-ID header.
func GetRequestID(r *http.Request) string {
	if id, ok := r.Context().Value(requestIDKey{}).(string); ok && id != "" {
		return id
	}
	return r.Header.Get("X-Request-ID")
}

// GenerateRequestID returns a cryptographically random 16-byte hex string.
func GenerateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
