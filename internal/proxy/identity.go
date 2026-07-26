package proxy

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
)

var clientIdentityHeaders = []string{
	"X-Relay-Client-Cert-Subject",
	"X-Relay-Client-Cert-San-Dns",
	"X-Relay-Client-Cert-San-Email",
	"X-Relay-Client-Cert-San-Ip",
	"X-Relay-Client-Cert-San-Uri",
	"X-Relay-Client-Cert-Fingerprint-Sha256",
}

func applyRelayOwnedHeaders(
	out http.Header,
	in *http.Request,
	route *config.RouteRuntime,
	backend config.BackendRuntime,
	target *url.URL,
	clientIP, proto, host string,
) {
	out.Del("X-Internal-Auth")
	out.Del("X-Real-IP")
	out.Del("X-Admin")
	for _, name := range clientIdentityHeaders {
		out.Del(name)
	}

	out.Set("X-Forwarded-Host", host)
	out.Set("X-Forwarded-Proto", proto)
	if chain := httpx.ForwardedFor(in); chain != "" {
		out.Set("X-Forwarded-For", chain)
	} else {
		out.Del("X-Forwarded-For")
	}
	if clientIP != "" {
		out.Set("X-Real-IP", clientIP)
	}
	out.Del("Forwarded")
	if httpx.EmitForwarded(in) {
		if value := generatedForwarded(clientIP, proto, host); value != "" {
			out.Set("Forwarded", value)
		}
	}

	if route == nil || !identityPropagationSafe(route.PropagateClientIdentity, backend, target) {
		return
	}
	cert := verifiedClientCertificate(in)
	if cert == nil {
		return
	}
	propagateClientCertificate(out, cert, route.PropagateClientIdentity.Fields)
}

func identityPropagationSafe(policy config.ClientIdentityPropagationConfig, backend config.BackendRuntime, target *url.URL) bool {
	if !policy.Enabled || target == nil || !strings.EqualFold(target.Scheme, "https") || backend.TLS.InsecureSkipVerify {
		return false
	}
	mtls := strings.TrimSpace(backend.TLS.CertFile) != "" && strings.TrimSpace(backend.TLS.KeyFile) != ""
	return mtls || policy.AcknowledgeVerifiedHTTPS
}

func verifiedClientCertificate(r *http.Request) *x509.Certificate {
	if r == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	return r.TLS.VerifiedChains[0][0]
}

func propagateClientCertificate(out http.Header, cert *x509.Certificate, fields []string) {
	for _, raw := range fields {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "subject":
			setSanitized(out, "X-Relay-Client-Cert-Subject", cert.Subject.String())
		case "san_dns":
			addSanitized(out, "X-Relay-Client-Cert-San-Dns", cert.DNSNames)
		case "san_email":
			addSanitized(out, "X-Relay-Client-Cert-San-Email", cert.EmailAddresses)
		case "san_ip":
			values := make([]string, 0, len(cert.IPAddresses))
			for _, ip := range cert.IPAddresses {
				values = append(values, ip.String())
			}
			addSanitized(out, "X-Relay-Client-Cert-San-Ip", values)
		case "san_uri":
			values := make([]string, 0, len(cert.URIs))
			for _, uri := range cert.URIs {
				values = append(values, uri.String())
			}
			addSanitized(out, "X-Relay-Client-Cert-San-Uri", values)
		case "fingerprint_sha256":
			sum := sha256.Sum256(cert.Raw)
			out.Set("X-Relay-Client-Cert-Fingerprint-Sha256", hex.EncodeToString(sum[:]))
		}
	}
}

func setSanitized(header http.Header, name, value string) {
	if clean := sanitizeIdentityValue(value); clean != "" {
		header.Set(name, clean)
	}
}

func addSanitized(header http.Header, name string, values []string) {
	for _, value := range values {
		if clean := sanitizeIdentityValue(value); clean != "" {
			header.Add(name, clean)
		}
	}
}

func sanitizeIdentityValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 1024 {
		return ""
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return value
}

func generatedForwarded(clientIP, proto, host string) string {
	forParam := httpx.FormatForwardedFor(clientIP)
	if forParam == "" {
		return ""
	}
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto != "http" && proto != "https" {
		return ""
	}
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 255 || strings.ContainsFunc(host, unicode.IsControl) {
		return ""
	}
	for _, r := range host {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune(".-:[]", r)) {
			return ""
		}
	}
	return forParam + ";proto=" + proto + ";host=" + strconv.Quote(host)
}
