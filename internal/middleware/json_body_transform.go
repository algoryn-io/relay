package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"algoryn.io/relay/internal/httpx"
)

// JSONBodyOps is a top-level JSON object transform (rename / add / remove).
type JSONBodyOps struct {
	Rename map[string]string
	Add    map[string]any
	Remove []string
}

// JSONBodyTransformConfig configures declarative JSON body transforms.
// ContentTypes and MaxBytes are required: the middleware never buffers
// without an explicit allowlist and size bound.
type JSONBodyTransformConfig struct {
	MaxBytes     int64
	ContentTypes []string
	Request      JSONBodyOps
	Response     JSONBodyOps
}

type jsonBodyTransformMiddleware struct {
	maxBytes     int64
	contentTypes []string
	request      JSONBodyOps
	response     JSONBodyOps
	hasRequest   bool
	hasResponse  bool
}

// NewJSONBodyTransform builds the JSON body transform middleware.
func NewJSONBodyTransform(cfg JSONBodyTransformConfig) (Middleware, error) {
	if cfg.MaxBytes <= 0 {
		return nil, fmt.Errorf("json_body_transform: max_bytes must be greater than 0")
	}
	contentTypes := normalizeContentTypes(cfg.ContentTypes)
	if len(contentTypes) == 0 {
		return nil, fmt.Errorf("json_body_transform: content_types must not be empty")
	}
	request := normalizeJSONBodyOps(cfg.Request)
	response := normalizeJSONBodyOps(cfg.Response)
	hasRequest := jsonBodyOpsActive(request)
	hasResponse := jsonBodyOpsActive(response)
	if !hasRequest && !hasResponse {
		return nil, fmt.Errorf("json_body_transform: at least one of request or response transforms is required")
	}

	mw := &jsonBodyTransformMiddleware{
		maxBytes:     cfg.MaxBytes,
		contentTypes: contentTypes,
		request:      request,
		response:     response,
		hasRequest:   hasRequest,
		hasResponse:  hasResponse,
	}
	return mw.wrap, nil
}

func (m *jsonBodyTransformMiddleware) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.hasRequest {
			if err := m.transformRequest(r); err != nil {
				httpx.WriteError(w, http.StatusBadRequest, "json_body_invalid")
				return
			}
		}

		if !m.hasResponse {
			next.ServeHTTP(w, r)
			return
		}
		rw := newJSONBodyTransformWriter(w, m)
		defer rw.close()
		next.ServeHTTP(rw, r)
	})
}

func (m *jsonBodyTransformMiddleware) transformRequest(r *http.Request) error {
	if !m.contentTypeMatches(r.Header.Get("Content-Type")) {
		return nil
	}
	if shouldSkipBodyBuffer(r) {
		return nil
	}
	if r.ContentLength == 0 {
		return nil
	}
	if r.ContentLength < 0 || r.ContentLength > m.maxBytes {
		return nil
	}
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, m.maxBytes+1))
	_ = r.Body.Close()
	if err != nil {
		return err
	}
	if int64(len(body)) > m.maxBytes {
		// Oversize: restore original bytes and leave untransformed.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		return nil
	}

	transformed, ok, err := applyJSONBodyOps(body, m.request)
	if err != nil {
		return err
	}
	if !ok {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
		return nil
	}

	r.Body = io.NopCloser(bytes.NewReader(transformed))
	r.ContentLength = int64(len(transformed))
	r.Header.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(transformed)), nil
	}
	return nil
}

func (m *jsonBodyTransformMiddleware) contentTypeMatches(contentType string) bool {
	mediaType := mediaTypeOnly(contentType)
	if mediaType == "" {
		return false
	}
	return matchesContentType(mediaType, m.contentTypes)
}

func shouldSkipBodyBuffer(r *http.Request) bool {
	if isUpgradeRequest(r) {
		return true
	}
	if len(r.TransferEncoding) > 0 {
		return true
	}
	return false
}

func normalizeContentTypes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, ct := range in {
		ct = strings.ToLower(strings.TrimSpace(ct))
		if ct == "" {
			continue
		}
		out = append(out, ct)
	}
	return out
}

func normalizeJSONBodyOps(ops JSONBodyOps) JSONBodyOps {
	out := JSONBodyOps{}
	if len(ops.Rename) > 0 {
		out.Rename = make(map[string]string, len(ops.Rename))
		for from, to := range ops.Rename {
			from = strings.TrimSpace(from)
			to = strings.TrimSpace(to)
			if from == "" || to == "" {
				continue
			}
			out.Rename[from] = to
		}
	}
	if len(ops.Add) > 0 {
		out.Add = make(map[string]any, len(ops.Add))
		for key, value := range ops.Add {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			out.Add[key] = value
		}
	}
	if len(ops.Remove) > 0 {
		out.Remove = make([]string, 0, len(ops.Remove))
		for _, key := range ops.Remove {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			out.Remove = append(out.Remove, key)
		}
	}
	return out
}

func jsonBodyOpsActive(ops JSONBodyOps) bool {
	return len(ops.Rename) > 0 || len(ops.Add) > 0 || len(ops.Remove) > 0
}

// applyJSONBodyOps transforms a JSON object body. ok is false when the root is
// not a JSON object (arrays/scalars are left untouched). err is set only for
// invalid JSON.
func applyJSONBodyOps(body []byte, ops JSONBodyOps) (transformed []byte, ok bool, err error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return body, false, nil
	}
	var root any
	if err := json.Unmarshal(trimmed, &root); err != nil {
		return nil, false, err
	}
	obj, isObject := root.(map[string]any)
	if !isObject {
		return body, false, nil
	}

	for from, to := range ops.Rename {
		if value, exists := obj[from]; exists {
			obj[to] = value
			if from != to {
				delete(obj, from)
			}
		}
	}
	for _, key := range ops.Remove {
		delete(obj, key)
	}
	for key, value := range ops.Add {
		obj[key] = value
	}

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func mediaTypeOnly(contentType string) string {
	mediaType := strings.ToLower(strings.TrimSpace(contentType))
	if mediaType == "" {
		return ""
	}
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = strings.TrimSpace(mediaType[:i])
	}
	return mediaType
}

type jsonBodyTransformWriter struct {
	http.ResponseWriter
	mw *jsonBodyTransformMiddleware

	buf          bytes.Buffer
	status       int
	handlerHdr   bool
	statusSent   bool
	decided      bool
	bypass       bool
	transforming bool
}

func newJSONBodyTransformWriter(w http.ResponseWriter, mw *jsonBodyTransformMiddleware) *jsonBodyTransformWriter {
	return &jsonBodyTransformWriter{
		ResponseWriter: w,
		mw:             mw,
		status:         http.StatusOK,
	}
}

func (w *jsonBodyTransformWriter) WriteHeader(code int) {
	if w.handlerHdr || w.statusSent {
		return
	}
	w.status = code
	w.handlerHdr = true
	w.decideFromHeaders()
	if w.bypass {
		w.flushStatus()
	}
}

func (w *jsonBodyTransformWriter) Write(p []byte) (int, error) {
	if !w.handlerHdr && !w.statusSent {
		w.handlerHdr = true
		w.status = http.StatusOK
		w.decideFromHeaders()
	}
	if w.bypass {
		w.flushStatus()
		return w.ResponseWriter.Write(p) // #nosec G705 -- proxied response body
	}
	if !w.decided {
		// Streaming / unknown length: never buffer.
		w.decided = true
		w.bypass = true
		w.flushStatus()
		return w.ResponseWriter.Write(p) // #nosec G705 -- proxied response body
	}
	if _, err := w.buf.Write(p); err != nil {
		return 0, err
	}
	if int64(w.buf.Len()) > w.mw.maxBytes {
		w.bypass = true
		w.transforming = false
		w.flushStatus()
		_, err := w.ResponseWriter.Write(w.buf.Bytes()) // #nosec G705 -- proxied response body
		w.buf.Reset()
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return len(p), nil
}

func (w *jsonBodyTransformWriter) Flush() {
	if w.transforming && !w.bypass {
		// Mid-body flush means the handler is streaming; stop buffering.
		w.bypass = true
		w.transforming = false
	}
	if !w.decided {
		w.decided = true
		w.bypass = true
	}
	if w.bypass && w.buf.Len() > 0 {
		w.flushStatus()
		_, _ = w.ResponseWriter.Write(w.buf.Bytes()) // #nosec G705 -- proxied response body
		w.buf.Reset()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *jsonBodyTransformWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *jsonBodyTransformWriter) close() {
	if w.bypass {
		if w.buf.Len() > 0 {
			w.flushStatus()
			_, _ = w.ResponseWriter.Write(w.buf.Bytes()) // #nosec G705 -- proxied response body
			w.buf.Reset()
		} else if w.handlerHdr && !w.statusSent {
			w.flushStatus()
		}
		return
	}
	if !w.decided {
		// Empty body with headers that allowed transform, or no writes.
		if w.handlerHdr && !w.statusSent {
			w.flushStatus()
		}
		return
	}
	if !w.transforming {
		w.flushStatus()
		if w.buf.Len() > 0 {
			_, _ = w.ResponseWriter.Write(w.buf.Bytes()) // #nosec G705 -- proxied response body
			w.buf.Reset()
		}
		return
	}

	body := w.buf.Bytes()
	transformed, ok, err := applyJSONBodyOps(body, w.mw.response)
	if err != nil || !ok {
		w.flushStatus()
		if len(body) > 0 {
			_, _ = w.ResponseWriter.Write(body) // #nosec G705 -- proxied response body
		}
		w.buf.Reset()
		return
	}

	header := w.ResponseWriter.Header()
	header.Set("Content-Length", strconv.Itoa(len(transformed)))
	w.flushStatus()
	_, _ = w.ResponseWriter.Write(transformed) // #nosec G705 -- proxied response body
	w.buf.Reset()
}

func (w *jsonBodyTransformWriter) decideFromHeaders() {
	if w.decided {
		return
	}
	header := w.ResponseWriter.Header()
	if ce := strings.TrimSpace(header.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		w.decided = true
		w.bypass = true
		return
	}
	if !w.mw.contentTypeMatches(header.Get("Content-Type")) {
		w.decided = true
		w.bypass = true
		return
	}
	cl := strings.TrimSpace(header.Get("Content-Length"))
	if cl == "" {
		// Unknown length / streaming: do not buffer.
		w.decided = true
		w.bypass = true
		return
	}
	n, err := strconv.ParseInt(cl, 10, 64)
	if err != nil || n < 0 || n > w.mw.maxBytes {
		w.decided = true
		w.bypass = true
		return
	}
	w.decided = true
	w.transforming = true
	w.buf.Grow(int(n))
}

func (w *jsonBodyTransformWriter) flushStatus() {
	if w.statusSent {
		return
	}
	w.statusSent = true
	w.ResponseWriter.WriteHeader(w.status)
}
