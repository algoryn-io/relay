package config

import "testing"

func TestCompilePathGlob(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{pattern: "/api/*/orders", path: "/api/v1/orders", want: true},
		{pattern: "/api/*/orders", path: "/api/v1/v2/orders", want: false},
		{pattern: "/api/**/orders", path: "/api/v1/v2/orders", want: true},
		{pattern: "/api/**/orders", path: "/api/orders", want: true},
		{pattern: "/files/?.txt", path: "/files/a.txt", want: true},
		{pattern: "/files/?.txt", path: "/files/ab.txt", want: false},
		{pattern: "/literal+dot.txt", path: "/literal+dot.txt", want: true},
		{pattern: "/literal+dot.txt", path: "/literalXdot.txt", want: false},
	}

	for _, tt := range tests {
		re, err := CompilePathGlob(tt.pattern)
		if err != nil {
			t.Fatalf("CompilePathGlob(%q) error = %v", tt.pattern, err)
		}
		if got := re.MatchString(tt.path); got != tt.want {
			t.Fatalf("CompilePathGlob(%q).MatchString(%q) = %v, want %v (re=%s)", tt.pattern, tt.path, got, tt.want, re.String())
		}
	}
}

func TestCompilePathGlobRejectsInvalid(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{"", "api/*", "relative"} {
		if _, err := CompilePathGlob(pattern); err == nil {
			t.Fatalf("CompilePathGlob(%q) error = nil, want error", pattern)
		}
	}
}

func TestPathGlobLiteralLen(t *testing.T) {
	t.Parallel()

	// / a p i / * / x → 7 literals (wildcards excluded).
	if got := PathGlobLiteralLen("/api/*/x"); got != 7 {
		t.Fatalf("PathGlobLiteralLen = %d, want 7", got)
	}
	if got := PathGlobLiteralLen("/api/**/x"); got != 7 {
		t.Fatalf("PathGlobLiteralLen(**) = %d, want 7", got)
	}
}
