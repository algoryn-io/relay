package httpx

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type clientIPKey struct{}

// WithResolvedClientIP resolves the real client IP once and stores it in the request context.
// When trustedNets is non-empty and the direct peer (RemoteAddr) is in the trusted list,
// the leftmost IP from X-Forwarded-For is used instead of RemoteAddr.
func WithResolvedClientIP(r *http.Request, trustedNets []*net.IPNet) *http.Request {
	ip := resolveClientIP(r, trustedNets)
	return r.WithContext(context.WithValue(r.Context(), clientIPKey{}, ip))
}

// ClientIP returns the resolved client IP. If WithResolvedClientIP was called upstream,
// the stored value is returned; otherwise falls back to RemoteAddr.
func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey{}).(string); ok && ip != "" {
		return ip
	}
	return remoteAddrIP(r)
}

// PeerIP returns the IP of the immediate TCP peer (RemoteAddr), ignoring any
// forwarding headers. Unlike ClientIP it cannot be spoofed via X-Forwarded-For,
// so it must be used for trust decisions that gate privileged endpoints (admin,
// metrics).
func PeerIP(r *http.Request) string {
	return remoteAddrIP(r)
}

// PeerTrusted reports whether the immediate TCP peer is within one of the
// trusted networks. With no trusted networks configured, no peer is trusted.
func PeerTrusted(r *http.Request, trustedNets []*net.IPNet) bool {
	if len(trustedNets) == 0 {
		return false
	}
	ip := net.ParseIP(remoteAddrIP(r))
	return ip != nil && isTrustedNet(ip, trustedNets)
}

// ParseTrustedNets parses IP or CIDR strings into networks.
// Invalid entries are silently skipped; they should have been caught by config validation.
func ParseTrustedNets(entries []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{
				IP:   ip.Mask(net.CIDRMask(bits, bits)),
				Mask: net.CIDRMask(bits, bits),
			})
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, network)
		}
	}
	return nets
}

func resolveClientIP(r *http.Request, trustedNets []*net.IPNet) string {
	remoteIP := remoteAddrIP(r)
	if len(trustedNets) == 0 {
		return remoteIP
	}
	remote := net.ParseIP(remoteIP)
	if remote == nil || !isTrustedNet(remote, trustedNets) {
		return remoteIP
	}
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff == "" {
		return remoteIP
	}
	// The immediate peer is a trusted proxy. Proxies APPEND to X-Forwarded-For,
	// so the real client is the right-most entry that is not itself a trusted
	// proxy. Walking right-to-left and skipping trusted addresses is the only
	// spoof-resistant choice: the left-most entry is fully attacker-controlled
	// (a client can pre-seed X-Forwarded-For), so it must never be trusted.
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			continue
		}
		if isTrustedNet(ip, trustedNets) {
			continue // another trusted hop; keep walking left
		}
		return ip.String() // first untrusted address = the real client
	}
	// Every forwarded entry is a trusted proxy (or unparseable): fall back to the
	// real TCP peer rather than trusting any client-supplied value.
	return remoteIP
}

func isTrustedNet(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteAddrIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
