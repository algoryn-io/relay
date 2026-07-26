package middleware

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
)

const (
	defaultCompressionMinBytes = 1024
	defaultBrotliQuality       = 5
	encodingGzip               = "gzip"
	encodingBrotli             = "br"
)

// CompressionConfig configures edge response compression.
type CompressionConfig struct {
	// Encodings lists allowed response encodings in preference order.
	// Supported values: br, gzip. Defaults to [br, gzip].
	Encodings []string
	// MinBytes is the minimum uncompressed body size before compression.
	// Zero (unset) defaults to 1024. Use 1 to compress nearly all bodies.
	MinBytes int
	// GzipLevel is the gzip compression level. Zero defaults to
	// gzip.DefaultCompression.
	GzipLevel int
	// BrotliQuality is the brotli quality (1–11). Zero defaults to 5.
	BrotliQuality int
	// ContentTypes is an allowlist of Content-Type prefixes/exact types.
	// Empty uses the built-in compressible defaults.
	ContentTypes []string
	// ExcludeContentTypes is a denylist checked after the allowlist.
	// Empty keeps the built-in non-compressible defaults.
	ExcludeContentTypes []string
	// ExcludeStatus lists response statuses that must not be compressed.
	// Empty defaults to 204, 206, 304.
	ExcludeStatus []int
}

type compressionMiddleware struct {
	encodings     []string
	minBytes      int
	gzipLevel     int
	brotliQuality int
	allowTypes    []string
	denyTypes     []string
	excludeStatus map[int]struct{}
}

var defaultCompressibleTypes = []string{
	"text/",
	"application/json",
	"application/javascript",
	"application/xml",
	"application/xhtml+xml",
	"application/rss+xml",
	"application/atom+xml",
	"application/wasm",
	"image/svg+xml",
}

var defaultExcludeCompressibleTypes = []string{
	"application/octet-stream",
	"application/zip",
	"application/gzip",
	"application/x-gzip",
	"application/x-brotli",
	"application/grpc",
}

// NewCompression builds the edge compression middleware.
func NewCompression(cfg CompressionConfig) (Middleware, error) {
	encodings, err := normalizeCompressionEncodings(cfg.Encodings)
	if err != nil {
		return nil, err
	}
	minBytes := cfg.MinBytes
	if minBytes < 0 {
		return nil, fmt.Errorf("compression: min_bytes must be >= 0")
	}
	if minBytes == 0 {
		minBytes = defaultCompressionMinBytes
	}
	gzipLevel := cfg.GzipLevel
	if gzipLevel == 0 {
		gzipLevel = gzip.DefaultCompression
	}
	if gzipLevel < gzip.HuffmanOnly || gzipLevel > gzip.BestCompression {
		return nil, fmt.Errorf("compression: gzip_level must be between %d and %d", gzip.HuffmanOnly, gzip.BestCompression)
	}
	brotliQuality := cfg.BrotliQuality
	if brotliQuality == 0 {
		brotliQuality = defaultBrotliQuality
	}
	if brotliQuality < 1 || brotliQuality > 11 {
		return nil, fmt.Errorf("compression: brotli_quality must be between 1 and 11")
	}

	allowTypes := normalizeContentTypeMatchers(cfg.ContentTypes)
	if len(allowTypes) == 0 {
		allowTypes = append([]string(nil), defaultCompressibleTypes...)
	}
	denyTypes := normalizeContentTypeMatchers(cfg.ExcludeContentTypes)
	if len(cfg.ExcludeContentTypes) == 0 {
		denyTypes = append([]string(nil), defaultExcludeCompressibleTypes...)
	}

	excludeStatus := make(map[int]struct{})
	if len(cfg.ExcludeStatus) == 0 {
		for _, code := range []int{http.StatusNoContent, http.StatusPartialContent, http.StatusNotModified} {
			excludeStatus[code] = struct{}{}
		}
	} else {
		for _, code := range cfg.ExcludeStatus {
			excludeStatus[code] = struct{}{}
		}
	}

	mw := &compressionMiddleware{
		encodings:     encodings,
		minBytes:      minBytes,
		gzipLevel:     gzipLevel,
		brotliQuality: brotliQuality,
		allowTypes:    allowTypes,
		denyTypes:     denyTypes,
		excludeStatus: excludeStatus,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			encoding := mw.negotiate(r.Header.Get("Accept-Encoding"))
			if encoding == "" || r.Header.Get("Range") != "" || isUpgradeRequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			cw := newCompressWriter(w, mw, encoding)
			defer cw.close()
			next.ServeHTTP(cw, r)
		})
	}, nil
}

func normalizeCompressionEncodings(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return []string{encodingBrotli, encodingGzip}, nil
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		enc := strings.ToLower(strings.TrimSpace(item))
		switch enc {
		case encodingBrotli, encodingGzip:
			if _, ok := seen[enc]; ok {
				continue
			}
			seen[enc] = struct{}{}
			out = append(out, enc)
		case "":
			return nil, fmt.Errorf("compression: encodings must not contain empty values")
		default:
			return nil, fmt.Errorf("compression: unsupported encoding %q", item)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("compression: encodings must include br or gzip")
	}
	return out, nil
}

func normalizeContentTypeMatchers(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func (m *compressionMiddleware) negotiate(acceptEncoding string) string {
	accepted := parseAcceptEncoding(acceptEncoding)
	if len(accepted) == 0 {
		return ""
	}
	starQ, starOK := accepted["*"]
	for _, enc := range m.encodings {
		if q, ok := accepted[enc]; ok {
			if q > 0 {
				return enc
			}
			continue
		}
		if starOK && starQ > 0 {
			return enc
		}
	}
	return ""
}

func parseAcceptEncoding(header string) map[string]float64 {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	out := make(map[string]float64)
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, params, _ := strings.Cut(part, ";")
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		q := 1.0
		for _, param := range strings.Split(params, ";") {
			param = strings.TrimSpace(param)
			if param == "" {
				continue
			}
			key, value, ok := strings.Cut(param, "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil {
				q = 0
				break
			}
			if parsed < 0 {
				parsed = 0
			}
			if parsed > 1 {
				parsed = 1
			}
			q = parsed
		}
		out[name] = q
	}
	return out
}

type compressWriter struct {
	http.ResponseWriter
	mw       *compressionMiddleware
	encoding string

	buf         bytes.Buffer
	compressor  io.WriteCloser
	status      int
	handlerHdr  bool // handler called WriteHeader
	statusSent  bool // underlying status line flushed
	decided     bool
	compressing bool
	bypass      bool
}

func newCompressWriter(w http.ResponseWriter, mw *compressionMiddleware, encoding string) *compressWriter {
	return &compressWriter{
		ResponseWriter: w,
		mw:             mw,
		encoding:       encoding,
		status:         http.StatusOK,
	}
}

func (w *compressWriter) WriteHeader(code int) {
	if w.handlerHdr || w.statusSent {
		return
	}
	w.status = code
	w.handlerHdr = true

	// Hard rejects that do not depend on body size can flush immediately.
	if reason := w.rejectReason(nil); reason != "" && reason != "min-bytes" {
		w.decided = true
		w.bypass = true
		w.flushStatus()
		return
	}
	if cl := w.ResponseWriter.Header().Get("Content-Length"); cl != "" {
		if n, err := strconv.Atoi(cl); err == nil {
			w.decide(n)
			if w.compressing {
				w.applyCompressionHeaders()
			}
			w.flushStatus()
		}
	}
}

func (w *compressWriter) Write(p []byte) (int, error) {
	if !w.handlerHdr && !w.statusSent {
		w.handlerHdr = true
		w.status = http.StatusOK
	}
	if w.bypass {
		w.flushStatus()
		return w.ResponseWriter.Write(p)
	}
	if w.compressing {
		w.applyCompressionHeaders()
		w.flushStatus()
		return w.compressor.Write(p)
	}

	if _, err := w.buf.Write(p); err != nil {
		return 0, err
	}
	if w.buf.Len() < w.mw.minBytes {
		return len(p), nil
	}
	w.decide(w.buf.Len())
	if err := w.flushPending(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *compressWriter) Flush() {
	if !w.decided {
		if w.buf.Len() > 0 {
			w.decide(w.buf.Len())
		} else {
			w.decided = true
			w.bypass = true
		}
		_ = w.flushPending()
	}
	if w.compressing {
		if f, ok := w.compressor.(interface{ Flush() error }); ok {
			_ = f.Flush()
		}
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *compressWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *compressWriter) close() {
	if !w.decided {
		w.decide(w.buf.Len())
	}
	_ = w.flushPending()
	if w.compressor != nil {
		_ = w.compressor.Close()
		w.compressor = nil
	}
	// Ensure status is sent even for empty bodies (e.g. 204 already bypassed).
	if w.handlerHdr && !w.statusSent {
		w.flushStatus()
	}
}

func (w *compressWriter) flushStatus() {
	if w.statusSent {
		return
	}
	w.statusSent = true
	w.ResponseWriter.WriteHeader(w.status)
}

func (w *compressWriter) flushPending() error {
	if w.compressing {
		w.applyCompressionHeaders()
		w.flushStatus()
		if w.buf.Len() > 0 {
			if _, err := w.compressor.Write(w.buf.Bytes()); err != nil {
				w.buf.Reset()
				return err
			}
			w.buf.Reset()
		}
		return nil
	}
	w.bypass = true
	w.flushStatus()
	if w.buf.Len() == 0 {
		return nil
	}
	_, err := w.ResponseWriter.Write(w.buf.Bytes()) // #nosec G705 -- proxied/upstream response body, not reflected HTML
	w.buf.Reset()
	return err
}

func (w *compressWriter) decide(size int) {
	if w.decided {
		return
	}
	w.decided = true
	if reason := w.rejectReason(&size); reason != "" {
		w.bypass = true
		return
	}
	comp, err := w.newCompressor()
	if err != nil {
		w.bypass = true
		return
	}
	w.compressor = comp
	w.compressing = true
}

func (w *compressWriter) rejectReason(size *int) string {
	if _, excluded := w.mw.excludeStatus[w.status]; excluded {
		return "status"
	}
	header := w.ResponseWriter.Header()
	if ce := strings.TrimSpace(header.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		return "content-encoding"
	}
	if header.Get("Content-Range") != "" {
		return "content-range"
	}
	if hasNoTransform(header.Get("Cache-Control")) {
		return "no-transform"
	}
	if !contentTypeAllowed(header.Get("Content-Type"), w.mw.allowTypes, w.mw.denyTypes) {
		return "content-type"
	}
	if size != nil && *size < w.mw.minBytes {
		return "min-bytes"
	}
	if size == nil {
		if cl := header.Get("Content-Length"); cl != "" {
			if n, err := strconv.Atoi(cl); err == nil && n < w.mw.minBytes {
				return "min-bytes"
			}
		}
	}
	return ""
}

func (w *compressWriter) applyCompressionHeaders() {
	header := w.ResponseWriter.Header()
	header.Del("Content-Length")
	header.Set("Content-Encoding", w.encoding)
	appendVary(header, "Accept-Encoding")
}

func (w *compressWriter) newCompressor() (io.WriteCloser, error) {
	switch w.encoding {
	case encodingGzip:
		return gzip.NewWriterLevel(w.ResponseWriter, w.mw.gzipLevel)
	case encodingBrotli:
		return brotli.NewWriterLevel(w.ResponseWriter, w.mw.brotliQuality), nil
	default:
		return nil, fmt.Errorf("unsupported encoding %q", w.encoding)
	}
}

func contentTypeAllowed(contentType string, allow, deny []string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(contentType))
	if mediaType == "" {
		return false
	}
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = strings.TrimSpace(mediaType[:i])
	}
	if matchesContentType(mediaType, deny) {
		return false
	}
	return matchesContentType(mediaType, allow)
}

func matchesContentType(mediaType string, matchers []string) bool {
	for _, matcher := range matchers {
		if matcher == "" {
			continue
		}
		if strings.HasSuffix(matcher, "/") {
			if strings.HasPrefix(mediaType, matcher) {
				return true
			}
			continue
		}
		if mediaType == matcher {
			return true
		}
	}
	return false
}

func hasNoTransform(cacheControl string) bool {
	for _, part := range strings.Split(cacheControl, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "no-transform") {
			return true
		}
	}
	return false
}
