package middleware

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestChainPreservesOrder(t *testing.T) {
	t.Parallel()

	var order []string
	mwA := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "a:before")
			next.ServeHTTP(w, r)
			order = append(order, "a:after")
		})
	}
	mwB := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "b:before")
			next.ServeHTTP(w, r)
			order = append(order, "b:after")
		})
	}
	final := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		order = append(order, "final")
	})

	handler := Chain(final, mwA, mwB)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"a:before", "b:before", "final", "b:after", "a:after"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

func TestChainShortCircuitStopsDownstream(t *testing.T) {
	t.Parallel()

	calledFinal := false
	reject := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = next
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	final := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calledFinal = true
	})

	handler := Chain(final, reject)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if calledFinal {
		t.Fatal("final handler should not be called when middleware short-circuits")
	}
}

func TestResolveSuccess(t *testing.T) {
	t.Parallel()

	called := 0
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called++
			next.ServeHTTP(w, r)
		})
	}

	resolved, err := Resolve([]string{"jwt-auth"}, map[string]Middleware{
		"jwt-auth": mw,
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(resolved) != 1 {
		t.Fatalf("len(resolved) = %d, want 1", len(resolved))
	}

	handler := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), resolved...)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if called != 1 {
		t.Fatalf("called = %d, want 1", called)
	}
}

func TestResolveMissingMiddlewareReturnsError(t *testing.T) {
	t.Parallel()

	resolved, err := Resolve([]string{"jwt-auth"}, map[string]Middleware{})
	if err == nil {
		t.Fatal("Resolve() error = nil, want error")
	}
	if resolved != nil {
		t.Fatalf("resolved = %v, want nil", resolved)
	}
}
