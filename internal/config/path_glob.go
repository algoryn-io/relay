package config

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// CompilePathGlob converts a path glob into a fully-anchored RE2 expression.
// Supported metacharacters:
//   - `*`  — zero or more non-slash characters (one path segment)
//   - `**` — zero or more characters including slashes (across segments)
//   - `?`  — exactly one non-slash character
//
// All other characters are matched literally. The resulting pattern always
// matches the entire path (`^…$`).
func CompilePathGlob(pattern string) (*regexp.Regexp, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, fmt.Errorf("empty path_glob")
	}
	if !strings.HasPrefix(pattern, "/") {
		return nil, fmt.Errorf("path_glob must start with /")
	}
	if strings.ContainsRune(pattern, 0) {
		return nil, fmt.Errorf("path_glob must not contain NUL")
	}

	var b strings.Builder
	b.Grow(len(pattern)*2 + 2)
	b.WriteByte('^')

	for i := 0; i < len(pattern); {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i += 2
				// `**/` may match zero segments (e.g. /api/**/orders → /api/orders).
				if i < len(pattern) && pattern[i] == '/' {
					b.WriteString("(?:.*/)?")
					i++
					continue
				}
				b.WriteString(".*")
				continue
			}
			b.WriteString("[^/]*")
			i++
		case '?':
			b.WriteString("[^/]")
			i++
		default:
			r, size := utf8.DecodeRuneInString(pattern[i:])
			if r == utf8.RuneError && size == 1 {
				return nil, fmt.Errorf("path_glob contains invalid UTF-8")
			}
			b.WriteString(regexp.QuoteMeta(string(r)))
			i += size
		}
	}
	b.WriteByte('$')

	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("compile path_glob: %w", err)
	}
	return re, nil
}

// PathGlobLiteralLen returns the number of non-wildcard runes in a glob pattern.
// Used to rank more-literal globs ahead of catch-alls when several match.
func PathGlobLiteralLen(pattern string) int {
	n := 0
	for i := 0; i < len(pattern); {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i += 2
				continue
			}
			i++
		case '?':
			i++
		default:
			_, size := utf8.DecodeRuneInString(pattern[i:])
			n++
			i += size
		}
	}
	return n
}
