package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace"

	"algoryn.io/relay/internal/config"
)

func TestAccessLogPolicyRedactsHashesAndUsesTraceContext(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	cfg := config.AccessLogConfig{
		Fields: []string{"method", "bytes", "trace_id", "span_id", "host"},
		Headers: []config.AccessLogSelection{
			{Name: "Authorization"},
			{Name: "X-Tenant", Policy: "plain"},
		},
		Query: []config.AccessLogSelection{
			{Name: "access_token"},
			{Name: "account", Policy: "hash"},
		},
		Hash: config.AccessLogHashConfig{
			Algorithm:      "hmac_sha256",
			ResolvedSecret: "correlation-secret",
		},
	}
	handler := NewLoggingMiddlewareWithConfig(logger, "orders", "api", cfg)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("hello"))
		}),
	)
	traceID := trace.TraceID{1, 2, 3}
	spanID := trace.SpanID{4, 5, 6}
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	}))
	req := httptest.NewRequest(http.MethodPost, "https://api.example/orders?access_token=top-secret&account=alice", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer complete-token")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var got map[string]any
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["header.authorization"] != "[REDACTED]" || got["query.access_token"] != "[REDACTED]" {
		t.Fatalf("sensitive values were not redacted: %v", got)
	}
	if got["header.x-tenant"] != "acme" || got["bytes"] != float64(5) {
		t.Fatalf("selected fields missing: %v", got)
	}
	hash, _ := got["query.account"].(string)
	if !strings.HasPrefix(hash, "hmac-sha256:") || strings.Contains(hash, "alice") {
		t.Fatalf("query hash = %q", hash)
	}
	if got["trace_id"] != traceID.String() || got["span_id"] != spanID.String() {
		t.Fatalf("trace correlation missing: %v", got)
	}
	if strings.Contains(output.String(), "complete-token") || strings.Contains(output.String(), "top-secret") {
		t.Fatalf("raw credential leaked: %s", output.String())
	}
}

func TestAccessLogPolicyOmit(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	cfg := config.AccessLogConfig{
		Fields:        []string{"method", "client_ip"},
		FieldPolicies: map[string]string{"client_ip": "omit"},
	}
	handler := NewLoggingMiddlewareWithConfig(logger, "route", "backend", cfg)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
	)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(output.String(), "client_ip") {
		t.Fatalf("omitted field present: %s", output.String())
	}
}
