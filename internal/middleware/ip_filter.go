package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"algoryn.io/relay/internal/httpx"
)

type IPFilterConfig struct {
	Allow []string
	Deny  []string
}

type ipSet struct {
	ips  []net.IP
	nets []*net.IPNet
}

func NewIPFilter(cfg IPFilterConfig) (Middleware, error) {
	allowSet, err := parseIPSet(cfg.Allow)
	if err != nil {
		return nil, fmt.Errorf("parse allow list: %w", err)
	}
	denySet, err := parseIPSet(cfg.Deny)
	if err != nil {
		return nil, fmt.Errorf("parse deny list: %w", err)
	}

	hasAllow := len(allowSet.ips) > 0 || len(allowSet.nets) > 0
	hasDeny := len(denySet.ips) > 0 || len(denySet.nets) > 0
	if !hasAllow && !hasDeny {
		return nil, fmt.Errorf("at least one of allow or deny must be provided")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			client := net.ParseIP(httpx.ClientIP(r))
			if client == nil {
				if hasAllow {
					writeJSONError(w, http.StatusForbidden, "forbidden")
					return
				}
				// Nil client IP is treated as non-matching; deny-only configs allow it.
				next.ServeHTTP(w, r)
				return
			}

			if hasAllow && !allowSet.contains(client) {
				writeJSONError(w, http.StatusForbidden, "forbidden")
				return
			}
			if hasDeny && denySet.contains(client) {
				writeJSONError(w, http.StatusForbidden, "forbidden")
				return
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

func parseIPSet(entries []string) (ipSet, error) {
	set := ipSet{
		ips:  make([]net.IP, 0, len(entries)),
		nets: make([]*net.IPNet, 0, len(entries)),
	}
	for i, entry := range entries {
		value := strings.TrimSpace(entry)
		if value == "" {
			return ipSet{}, fmt.Errorf("entry %d is empty", i)
		}
		if ip := net.ParseIP(value); ip != nil {
			set.ips = append(set.ips, ip)
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return ipSet{}, fmt.Errorf("entry %q is not a valid IP or CIDR", value)
		}
		set.nets = append(set.nets, network)
	}
	return set, nil
}

func (s ipSet) contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, exact := range s.ips {
		if exact.Equal(ip) {
			return true
		}
	}
	for _, network := range s.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
