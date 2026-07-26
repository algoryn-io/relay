package middleware

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"

	"algoryn.io/relay/internal/config"
)

func largeJSONBody() string {
	return `{"data":"` + strings.Repeat("x", 2048) + `"}`
}

func TestCompressionNegotiatesBrotliOverGzip(t *testing.T) {
	t.Parallel()

	mw, err := NewCompression(CompressionConfig{MinBytes: 1})
	if err != nil {
		t.Fatalf("NewCompression() error = %v", err)
	}
	body := largeJSONBody()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "br" {
		t.Fatalf("Content-Encoding = %q, want br", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
	plain, err := io.ReadAll(brotli.NewReader(rec.Body))
	if err != nil {
		t.Fatalf("brotli decode: %v", err)
	}
	if string(plain) != body {
		t.Fatalf("decoded body mismatch")
	}
}

func TestCompressionFallsBackToGzip(t *testing.T) {
	t.Parallel()

	mw, err := NewCompression(CompressionConfig{MinBytes: 1, Encodings: []string{"br", "gzip"}})
	if err != nil {
		t.Fatalf("NewCompression() error = %v", err)
	}
	body := largeJSONBody()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	gr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gr.Close()
	plain, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("gzip decode: %v", err)
	}
	if string(plain) != body {
		t.Fatalf("decoded body mismatch")
	}
}

func TestCompressionHonorsQualityValues(t *testing.T) {
	t.Parallel()

	mw, err := NewCompression(CompressionConfig{MinBytes: 1})
	if err != nil {
		t.Fatalf("NewCompression() error = %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(strings.Repeat("a", 2048)))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "br;q=0, gzip;q=1.0")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
}

func TestCompressionSkipsExistingContentEncoding(t *testing.T) {
	t.Parallel()

	mw, err := NewCompression(CompressionConfig{MinBytes: 1})
	if err != nil {
		t.Fatalf("NewCompression() error = %v", err)
	}
	upstream := []byte(strings.Repeat("z", 2048))
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(upstream)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want original gzip", got)
	}
	if !bytes.Equal(rec.Body.Bytes(), upstream) {
		t.Fatalf("body was recompressed or altered")
	}
}

func TestCompressionSkipsRangeRequestsAndPartialContent(t *testing.T) {
	t.Parallel()

	mw, err := NewCompression(CompressionConfig{MinBytes: 1})
	if err != nil {
		t.Fatalf("NewCompression() error = %v", err)
	}
	body := []byte(strings.Repeat("r", 2048))

	t.Run("request range", func(t *testing.T) {
		t.Parallel()
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(body)
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		req.Header.Set("Range", "bytes=0-100")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("Content-Encoding = %q, want none", got)
		}
	})

	t.Run("status 206", func(t *testing.T) {
		t.Parallel()
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Range", "bytes 0-100/2048")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(body[:101])
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("Content-Encoding = %q, want none", got)
		}
	})
}

func TestCompressionSkipsExcludedContentTypeAndSmallBodies(t *testing.T) {
	t.Parallel()

	mw, err := NewCompression(CompressionConfig{MinBytes: 1024})
	if err != nil {
		t.Fatalf("NewCompression() error = %v", err)
	}

	t.Run("binary type", func(t *testing.T) {
		t.Parallel()
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte(strings.Repeat("b", 2048)))
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("Content-Encoding = %q, want none", got)
		}
	})

	t.Run("below min_bytes", func(t *testing.T) {
		t.Parallel()
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("tiny"))
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("Content-Encoding = %q, want none", got)
		}
		if got := rec.Body.String(); got != "tiny" {
			t.Fatalf("body = %q", got)
		}
	})
}

func TestCompressionSkipsNoTransformAndExcludedStatus(t *testing.T) {
	t.Parallel()

	mw, err := NewCompression(CompressionConfig{MinBytes: 1})
	if err != nil {
		t.Fatalf("NewCompression() error = %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-transform")
		_, _ = w.Write([]byte(strings.Repeat("n", 2048)))
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "br")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none for no-transform", got)
	}
}

func TestCompressionEncodingPreferenceOrder(t *testing.T) {
	t.Parallel()

	mw, err := NewCompression(CompressionConfig{
		MinBytes:  1,
		Encodings: []string{"gzip", "br"},
	})
	if err != nil {
		t.Fatalf("NewCompression() error = %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(strings.Repeat("h", 2048)))
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip from configured preference", got)
	}
}

func TestFactoryBuildsCompression(t *testing.T) {
	t.Parallel()

	mw, closer, err := Build(config.MiddlewareRuntime{
		Name: "edge-compress",
		Type: "compression",
		Config: config.MiddlewareSettingsConfig{
			CompressionEncodings: []string{"gzip"},
			CompressionMinBytes:  1,
		},
	}, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if closer != nil {
		t.Fatal("compression unexpectedly returned a closer")
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(largeJSONBody()))
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
}

func TestParseAcceptEncoding(t *testing.T) {
	t.Parallel()

	got := parseAcceptEncoding(" gzip;q=0.5, BR, identity;q=0 ")
	if got["gzip"] != 0.5 {
		t.Fatalf("gzip q = %v", got["gzip"])
	}
	if got["br"] != 1 {
		t.Fatalf("br q = %v", got["br"])
	}
	if got["identity"] != 0 {
		t.Fatalf("identity q = %v", got["identity"])
	}
}
