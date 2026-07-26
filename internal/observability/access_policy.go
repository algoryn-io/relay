package observability

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
)

var defaultAccessFields = []string{
	"method", "path", "status", "duration", "route", "backend", "client_ip", "request_id",
}

type accessPolicy struct {
	fields   []string
	policies map[string]string
	headers  []config.AccessLogSelection
	query    []config.AccessLogSelection
	hash     config.AccessLogHashConfig
}

func compileAccessPolicy(cfg config.AccessLogConfig) accessPolicy {
	fields := append([]string(nil), cfg.Fields...)
	if len(fields) == 0 {
		fields = append([]string(nil), defaultAccessFields...)
	}
	policies := make(map[string]string, len(cfg.FieldPolicies))
	for name, policy := range cfg.FieldPolicies {
		policies[strings.ToLower(strings.TrimSpace(name))] = normalizedPolicy(policy, false)
	}
	return accessPolicy{fields: fields, policies: policies, headers: cfg.Headers, query: cfg.Query, hash: cfg.Hash}
}

func (p accessPolicy) attrs(r *http.Request, rec *statusRecorder, duration time.Duration, route, backend string) []slog.Attr {
	attrs := make([]slog.Attr, 0, len(p.fields)+len(p.headers)+len(p.query))
	spanContext := trace.SpanContextFromContext(r.Context())
	for _, rawField := range p.fields {
		field := strings.ToLower(strings.TrimSpace(rawField))
		policy := p.policies[field]
		if policy == "omit" {
			continue
		}
		switch field {
		case "method":
			attrs = p.appendString(attrs, field, r.Method, policy)
		case "path":
			attrs = p.appendString(attrs, field, r.URL.Path, policy)
		case "route":
			attrs = p.appendString(attrs, field, route, policy)
		case "backend":
			attrs = p.appendString(attrs, field, backend, policy)
		case "status":
			if policy == "hash" {
				attrs = p.appendString(attrs, field, strconv.Itoa(rec.Status()), policy)
			} else {
				attrs = append(attrs, slog.Int(field, rec.Status()))
			}
		case "duration":
			if policy == "hash" {
				attrs = p.appendString(attrs, "duration_ms", strconv.FormatInt(duration.Milliseconds(), 10), policy)
			} else {
				attrs = append(attrs, slog.Int64("duration_ms", duration.Milliseconds()))
			}
		case "bytes":
			if policy == "hash" {
				attrs = p.appendString(attrs, field, strconv.FormatInt(rec.Bytes(), 10), policy)
			} else {
				attrs = append(attrs, slog.Int64(field, rec.Bytes()))
			}
		case "client_ip":
			attrs = p.appendString(attrs, field, httpx.ClientIP(r), policy)
		case "request_id":
			attrs = p.appendString(attrs, field, httpx.GetRequestID(r), policy)
		case "trace_id":
			if spanContext.IsValid() {
				attrs = p.appendString(attrs, field, spanContext.TraceID().String(), policy)
			}
		case "span_id":
			if spanContext.IsValid() {
				attrs = p.appendString(attrs, field, spanContext.SpanID().String(), policy)
			}
		case "host":
			attrs = p.appendString(attrs, field, r.Host, policy)
		case "user_agent":
			attrs = p.appendString(attrs, field, r.UserAgent(), policy)
		}
	}
	for _, selection := range p.headers {
		name := strings.TrimSpace(selection.Name)
		policy := normalizedPolicy(selection.Policy, config.SensitiveAccessLogName(name))
		attrs = p.appendSelected(attrs, "header."+strings.ToLower(name), r.Header.Values(name), policy)
	}
	for _, selection := range p.query {
		name := strings.TrimSpace(selection.Name)
		policy := normalizedPolicy(selection.Policy, config.SensitiveAccessLogName(name))
		attrs = p.appendSelected(attrs, "query."+name, r.URL.Query()[name], policy)
	}
	return attrs
}

func (p accessPolicy) appendSelected(attrs []slog.Attr, key string, values []string, policy string) []slog.Attr {
	if policy == "omit" {
		return attrs
	}
	value := strings.Join(values, ",")
	if policy == "redact" {
		value = "[REDACTED]"
	}
	return p.appendString(attrs, key, value, policy)
}

func (p accessPolicy) appendString(attrs []slog.Attr, key, value, policy string) []slog.Attr {
	if policy == "hash" {
		value = p.hashValue(value)
	}
	return append(attrs, slog.String(key, value))
}

func (p accessPolicy) hashValue(value string) string {
	secret := []byte(p.hash.ResolvedSecret)
	if strings.EqualFold(strings.TrimSpace(p.hash.Algorithm), "sha256") {
		sum := sha256.Sum256(append(append([]byte(nil), secret...), []byte(value)...))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(value))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

func normalizedPolicy(policy string, sensitive bool) string {
	policy = strings.ToLower(strings.TrimSpace(policy))
	if policy == "" {
		if sensitive {
			return "redact"
		}
		return "plain"
	}
	return policy
}
