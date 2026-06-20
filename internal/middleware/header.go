package middleware

import "net/http"

type HeaderConfig struct {
	RequestSet  map[string]string
	RequestDel  []string
	ResponseSet map[string]string
	ResponseDel []string
}

type headerModifyingWriter struct {
	http.ResponseWriter
	set         map[string]string
	del         []string
	wroteHeader bool
}

func (w *headerModifyingWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		for _, k := range w.del {
			w.ResponseWriter.Header().Del(k)
		}
		for k, v := range w.set {
			w.ResponseWriter.Header().Set(k, v)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *headerModifyingWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func NewHeader(cfg HeaderConfig) (Middleware, error) {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, k := range cfg.RequestDel {
				r.Header.Del(k)
			}
			for k, v := range cfg.RequestSet {
				r.Header.Set(k, v)
			}

			if len(cfg.ResponseSet) > 0 || len(cfg.ResponseDel) > 0 {
				next.ServeHTTP(&headerModifyingWriter{
					ResponseWriter: w,
					set:            cfg.ResponseSet,
					del:            cfg.ResponseDel,
				}, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}
