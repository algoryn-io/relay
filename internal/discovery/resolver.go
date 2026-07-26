// Package discovery provides DNS-based backend endpoint discovery.
// Only standard DNS resolution is supported (A/AAAA/SRV), including Kubernetes
// Service DNS names resolved through the cluster's normal DNS servers. There is
// no Kubernetes Endpoints API or Consul integration.
package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Record type constants accepted by DNS discovery.
const (
	RecordTypeA    = "A"
	RecordTypeAAAA = "AAAA"
	RecordTypeSRV  = "SRV"
)

// Query describes a DNS lookup for backend discovery.
type Query struct {
	Name       string
	RecordType string // A, AAAA, or SRV
}

// Endpoint is one discovered upstream address.
type Endpoint struct {
	Host   string // IPv4/IPv6 literal or hostname (SRV target)
	Port   int
	Weight int // >= 1; from SRV weight or configured default
}

// Result is a resolved endpoint set plus the DNS TTL that should drive refresh.
type Result struct {
	Endpoints []Endpoint
	TTL       time.Duration
}

// Resolver performs DNS discovery lookups. Tests inject a fake implementation.
type Resolver interface {
	Resolve(ctx context.Context, q Query) (Result, error)
}

// NormalizeRecordType returns the canonical upper-case record type or an error.
func NormalizeRecordType(raw string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "", RecordTypeA:
		return RecordTypeA, nil
	case RecordTypeAAAA:
		return RecordTypeAAAA, nil
	case RecordTypeSRV:
		return RecordTypeSRV, nil
	default:
		return "", fmt.Errorf("unsupported DNS record type %q", raw)
	}
}

// ClampTTL bounds a DNS TTL between min and max. When ttl is zero, refresh is
// used as the effective TTL. max <= 0 means no upper bound beyond refresh.
func ClampTTL(ttl, refresh, min, max time.Duration) time.Duration {
	if ttl <= 0 {
		ttl = refresh
	}
	if refresh > 0 && ttl > refresh {
		ttl = refresh
	}
	if min > 0 && ttl < min {
		ttl = min
	}
	if max > 0 && ttl > max {
		ttl = max
	}
	if ttl <= 0 {
		ttl = time.Second
	}
	return ttl
}
