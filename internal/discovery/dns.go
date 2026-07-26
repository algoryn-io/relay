package discovery

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	defaultDNSPort    = "53"
	dnsQueryTimeout   = 3 * time.Second
	maxUDPResponse    = 1232
	defaultResolvPath = "/etc/resolv.conf"
)

// DNSResolver performs A/AAAA/SRV lookups against configured nameservers (or
// /etc/resolv.conf) and returns answer TTLs so pools can refresh atomically.
type DNSResolver struct {
	// Nameservers are host:port addresses. Empty loads /etc/resolv.conf.
	Nameservers []string
	// ResolvPath overrides the resolv.conf path (tests). Defaults to /etc/resolv.conf.
	ResolvPath string
	// Dial optionally overrides the UDP dialer used to reach nameservers.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolve implements Resolver.
func (r *DNSResolver) Resolve(ctx context.Context, q Query) (Result, error) {
	name := strings.TrimSpace(q.Name)
	if name == "" {
		return Result{}, fmt.Errorf("dns discovery: name is required")
	}
	recordType, err := NormalizeRecordType(q.RecordType)
	if err != nil {
		return Result{}, err
	}

	servers, err := r.nameservers()
	if err != nil {
		return Result{}, err
	}
	if len(servers) == 0 {
		return Result{}, fmt.Errorf("dns discovery: no nameservers configured")
	}

	var lastErr error
	for _, server := range servers {
		res, err := r.queryServer(ctx, server, name, recordType)
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dns discovery: lookup failed for %s %s", recordType, name)
	}
	return Result{}, lastErr
}

func (r *DNSResolver) nameservers() ([]string, error) {
	if len(r.Nameservers) > 0 {
		out := make([]string, 0, len(r.Nameservers))
		for _, ns := range r.Nameservers {
			ns = strings.TrimSpace(ns)
			if ns == "" {
				continue
			}
			out = append(out, ensureDNSPort(ns))
		}
		return out, nil
	}
	path := r.ResolvPath
	if path == "" {
		path = defaultResolvPath
	}
	return parseResolvConf(path)
}

func (r *DNSResolver) queryServer(ctx context.Context, server, name, recordType string) (Result, error) {
	qtype, err := dnsType(recordType)
	if err != nil {
		return Result{}, err
	}
	fqdn := ensureFQDN(name)

	var msg dnsmessage.Message
	msg.Header.ID = randomDNSID()
	msg.Header.RecursionDesired = true
	msg.Questions = []dnsmessage.Question{{
		Name:  mustDNSName(fqdn),
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}}

	packed, err := msg.Pack()
	if err != nil {
		return Result{}, fmt.Errorf("dns pack: %w", err)
	}

	dial := r.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	queryCtx, cancel := context.WithTimeout(ctx, dnsQueryTimeout)
	defer cancel()

	conn, err := dial(queryCtx, "udp", server)
	if err != nil {
		return Result{}, fmt.Errorf("dns dial %s: %w", server, err)
	}
	defer conn.Close()

	if deadline, ok := queryCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(packed); err != nil {
		return Result{}, fmt.Errorf("dns write: %w", err)
	}

	buf := make([]byte, maxUDPResponse)
	n, err := conn.Read(buf)
	if err != nil {
		return Result{}, fmt.Errorf("dns read: %w", err)
	}

	var parsed dnsmessage.Message
	if err := parsed.Unpack(buf[:n]); err != nil {
		return Result{}, fmt.Errorf("dns unpack: %w", err)
	}
	if parsed.Header.ID != msg.Header.ID {
		return Result{}, fmt.Errorf("dns response id mismatch")
	}
	if parsed.Header.RCode != dnsmessage.RCodeSuccess {
		return Result{}, fmt.Errorf("dns rcode %v for %s %s", parsed.Header.RCode, recordType, name)
	}

	return collectAnswers(parsed.Answers, recordType)
}

func collectAnswers(answers []dnsmessage.Resource, recordType string) (Result, error) {
	var (
		endpoints []Endpoint
		minTTL    uint32
		haveTTL   bool
	)
	noteTTL := func(ttl uint32) {
		if !haveTTL || ttl < minTTL {
			minTTL = ttl
			haveTTL = true
		}
	}

	for _, ans := range answers {
		switch recordType {
		case RecordTypeA:
			body, ok := ans.Body.(*dnsmessage.AResource)
			if !ok {
				continue
			}
			noteTTL(ans.Header.TTL)
			endpoints = append(endpoints, Endpoint{
				Host:   net.IP(body.A[:]).String(),
				Weight: 1,
			})
		case RecordTypeAAAA:
			body, ok := ans.Body.(*dnsmessage.AAAAResource)
			if !ok {
				continue
			}
			noteTTL(ans.Header.TTL)
			endpoints = append(endpoints, Endpoint{
				Host:   net.IP(body.AAAA[:]).String(),
				Weight: 1,
			})
		case RecordTypeSRV:
			body, ok := ans.Body.(*dnsmessage.SRVResource)
			if !ok {
				continue
			}
			target := strings.TrimSuffix(body.Target.String(), ".")
			if target == "" || target == "." {
				continue
			}
			noteTTL(ans.Header.TTL)
			weight := int(body.Weight)
			if weight <= 0 {
				weight = 1
			}
			endpoints = append(endpoints, Endpoint{
				Host:   target,
				Port:   int(body.Port),
				Weight: weight,
			})
		}
	}

	if len(endpoints) == 0 {
		return Result{}, fmt.Errorf("dns discovery: no %s records", recordType)
	}

	var ttl time.Duration
	if haveTTL {
		ttl = time.Duration(minTTL) * time.Second
	}
	return Result{Endpoints: endpoints, TTL: ttl}, nil
}

func dnsType(recordType string) (dnsmessage.Type, error) {
	switch recordType {
	case RecordTypeA:
		return dnsmessage.TypeA, nil
	case RecordTypeAAAA:
		return dnsmessage.TypeAAAA, nil
	case RecordTypeSRV:
		return dnsmessage.TypeSRV, nil
	default:
		return 0, fmt.Errorf("unsupported DNS record type %q", recordType)
	}
}

func mustDNSName(name string) dnsmessage.Name {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		// NewName only fails on excessive length; callers validate hostnames.
		return dnsmessage.Name{}
	}
	return n
}

func ensureFQDN(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return name
	}
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

func ensureDNSPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, defaultDNSPort)
}

func randomDNSID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano() & 0xffff) // #nosec G115 -- fallback only
	}
	return binary.BigEndian.Uint16(b[:])
}

func parseResolvConf(path string) ([]string, error) {
	// #nosec G304 -- path is /etc/resolv.conf or an explicit test override.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dns discovery: read %s: %w", path, err)
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		servers = append(servers, ensureDNSPort(fields[1]))
	}
	return servers, nil
}
