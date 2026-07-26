package httpx

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
)

type clientIPKey struct{}
type forwardingKey struct{}

type forwardingInfo struct {
	chain         []string
	emitForwarded bool
}

// WithResolvedClientIP resolves the real client IP once and stores it in the
// request context. For a trusted peer, it walks X-Forwarded-For right-to-left
// and skips trusted hops; an untrusted peer's chain is ignored.
func WithResolvedClientIP(r *http.Request, trustedNets []*net.IPNet) *http.Request {
	return WithForwarding(r, trustedNets, false)
}

// WithForwarding resolves the anti-spoofed client IP and records the normalized
// X-Forwarded-For chain that Relay may send upstream. An untrusted peer's
// inbound chain is discarded in full.
func WithForwarding(r *http.Request, trustedNets []*net.IPNet, emitForwarded bool) *http.Request {
	peer := normalizeIP(remoteAddrIP(r))
	trusted := PeerTrusted(r, trustedNets)
	chain := make([]string, 0, 4)
	if trusted {
		chain = parseForwardedFor(r.Header.Values("X-Forwarded-For"))
	}
	if peer != "" && (len(chain) == 0 || chain[len(chain)-1] != peer) {
		chain = append(chain, peer)
	}
	ip := resolveClientIPFromChain(peer, chain, trusted, trustedNets)
	ctx := context.WithValue(r.Context(), clientIPKey{}, ip)
	ctx = context.WithValue(ctx, forwardingKey{}, forwardingInfo{
		chain:         append([]string(nil), chain...),
		emitForwarded: emitForwarded,
	})
	return r.WithContext(ctx)
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

// ForwardedFor returns Relay's normalized outbound X-Forwarded-For value.
func ForwardedFor(r *http.Request) string {
	if info, ok := r.Context().Value(forwardingKey{}).(forwardingInfo); ok {
		return strings.Join(info.chain, ", ")
	}
	if peer := normalizeIP(remoteAddrIP(r)); peer != "" {
		return peer
	}
	return ""
}

// EmitForwarded reports whether Relay should generate the RFC 7239 Forwarded
// header. Inbound Forwarded values are never reused.
func EmitForwarded(r *http.Request) bool {
	info, _ := r.Context().Value(forwardingKey{}).(forwardingInfo)
	return info.emitForwarded
}

// FormatForwardedFor formats a normalized IP as an RFC 7239 for= parameter.
func FormatForwardedFor(raw string) string {
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "for=" + ip.String()
	}
	return "for=" + strconv.Quote("["+ip.String()+"]")
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

func resolveClientIPFromChain(remoteIP string, chain []string, peerTrusted bool, trustedNets []*net.IPNet) string {
	if !peerTrusted {
		return remoteIP
	}
	// The immediate peer is a trusted proxy. Proxies APPEND to X-Forwarded-For,
	// so the real client is the right-most entry that is not itself a trusted
	// proxy. Walking right-to-left and skipping trusted addresses is the only
	// spoof-resistant choice: the left-most entry is fully attacker-controlled
	// (a client can pre-seed X-Forwarded-For), so it must never be trusted.
	for i := len(chain) - 1; i >= 0; i-- {
		ip := net.ParseIP(chain[i])
		if isTrustedNet(ip, trustedNets) {
			continue // another trusted hop; keep walking left
		}
		return ip.String() // first untrusted address = the real client
	}
	// Every forwarded entry is a trusted proxy (or unparseable): fall back to the
	// real TCP peer rather than trusting any client-supplied value.
	return remoteIP
}

func parseForwardedFor(values []string) []string {
	var out []string
	seenAdjacent := ""
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			ip := normalizeIP(strings.TrimSpace(part))
			if ip == "" {
				continue
			}
			// Duplicate adjacent hops are a common result of proxies appending
			// an address already present at the end of the chain.
			if ip == seenAdjacent {
				continue
			}
			out = append(out, ip)
			seenAdjacent = ip
		}
	}
	return out
}

func normalizeIP(raw string) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return ""
	}
	return ip.String()
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
