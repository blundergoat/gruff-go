package pathfilter

import (
	"strings"
	"testing"
)

// TestValidateContract pins every accepted edge and rejected path form in the
// repository-relative path-pattern grammar.
func TestValidateContract(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr string
	}{
		{name: "empty", pattern: "", wantErr: "must not be empty"},
		{name: "POSIX absolute", pattern: "/tmp/*.go", wantErr: "must be relative"},
		{name: "Windows drive-qualified", pattern: "C:/repo/*.go", wantErr: "Windows drive qualifier"},
		{name: "backslash-containing", pattern: `pkg\*.go`, wantErr: "slash separators"},
		{name: "escaping repository", pattern: "safe/../../outside.go", wantErr: "must stay inside"},
		{name: "malformed class", pattern: "pkg/[abc.go", wantErr: "invalid path pattern"},
		{name: "mid-pattern recursive glob", pattern: "pkg/**/generated.go", wantErr: "one ** as a trailing recursive suffix"},
		{name: "multiple recursive globs", pattern: "pkg/**/**", wantErr: "one ** as a trailing recursive suffix"},
		{name: "segment glob", pattern: "pkg/*.go"},
		{name: "exact path", pattern: "cmd/gruff-go/main.go"},
		{name: "leading dot slash", pattern: "./cmd/*.go"},
		{name: "trailing slash", pattern: "internal/generated/"},
		{name: "trailing recursive suffix", pattern: "internal/generated/**"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.pattern)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate(%q) error = %v, want nil", tt.pattern, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate(%q) error = %v, want containing %q", tt.pattern, err, tt.wantErr)
			}
		})
	}
}

// TestMatchesContract pins segment boundaries, normalisation, exact matching,
// and the two equivalent recursive-directory spellings.
func TestMatchesContract(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		rel     string
		want    bool
	}{
		{name: "root segment glob", pattern: "*.go", rel: "main.go", want: true},
		{name: "root segment glob excludes nested", pattern: "*.go", rel: "pkg/main.go", want: false},
		{name: "nested segment glob", pattern: "pkg/*.go", rel: "pkg/main.go", want: true},
		{name: "nested segment glob stops at slash", pattern: "pkg/*.go", rel: "pkg/nested/main.go", want: false},
		{name: "exact path", pattern: "cmd/gruff-go/main.go", rel: "cmd/gruff-go/main.go", want: true},
		{name: "leading dot slash pattern and path", pattern: "./pkg/*.go", rel: "./pkg/main.go", want: true},
		{name: "cleaned exact fallback", pattern: "pkg/./main.go", rel: "pkg/main.go", want: true},
		{name: "wildcard extension boundary", pattern: "pkg/*.go", rel: "pkg/main.txt", want: false},
		{name: "trailing slash directory self", pattern: "ignored/", rel: "ignored", want: true},
		{name: "trailing slash direct child", pattern: "ignored/", rel: "ignored/main.go", want: true},
		{name: "trailing slash nested descendant", pattern: "ignored/", rel: "ignored/nested/main.go", want: true},
		{name: "trailing slash prefix boundary", pattern: "ignored/", rel: "ignoredness/main.go", want: false},
		{name: "recursive suffix directory self", pattern: "ignored/**", rel: "ignored", want: true},
		{name: "recursive suffix descendant", pattern: "ignored/**", rel: "ignored/nested/main.go", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Matches(tt.pattern, tt.rel); got != tt.want {
				t.Fatalf("Matches(%q, %q) = %t, want %t", tt.pattern, tt.rel, got, tt.want)
			}
		})
	}
}

// TestFirstMatchContract verifies ordering, verbatim return values, duplicate
// handling, empty inputs, and agreement with MatchesAny.
func TestFirstMatchContract(t *testing.T) {
	tests := []struct {
		name        string
		patterns    []string
		rel         string
		wantMatched bool
		wantPattern string
	}{
		{
			name:        "earliest match returned verbatim",
			patterns:    []string{"other/**", "./ignored/**", "ignored/**"},
			rel:         "ignored/main.go",
			wantMatched: true,
			wantPattern: "./ignored/**",
		},
		{
			name:        "duplicate patterns keep first result",
			patterns:    []string{"*.txt", "*.go", "*.go"},
			rel:         "main.go",
			wantMatched: true,
			wantPattern: "*.go",
		},
		{name: "empty list", patterns: nil, rel: "main.go"},
		{name: "no match", patterns: []string{"*.txt", "docs/**"}, rel: "main.go"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, pattern := FirstMatch(tt.patterns, tt.rel)
			if matched != tt.wantMatched || pattern != tt.wantPattern {
				t.Fatalf("FirstMatch(%#v, %q) = (%t, %q), want (%t, %q)", tt.patterns, tt.rel, matched, pattern, tt.wantMatched, tt.wantPattern)
			}
			if got := MatchesAny(tt.patterns, tt.rel); got != matched {
				t.Fatalf("MatchesAny(%#v, %q) = %t, want FirstMatch matched %t", tt.patterns, tt.rel, got, matched)
			}
		})
	}
}

// FuzzPathfilterNoPanic sends arbitrary patterns and paths through every public
// entry point; callers validate first, but invalid input must remain safe.
func FuzzPathfilterNoPanic(f *testing.F) {
	f.Add("ignored/", "ignored/main.go")
	f.Add("[", "./nested/file.go")
	f.Add(`C:\repo\**`, "anything")
	f.Fuzz(func(t *testing.T, pattern, rel string) {
		_ = Validate(pattern)
		_ = Matches(pattern, rel)
		patterns := []string{pattern, pattern}
		matched, _ := FirstMatch(patterns, rel)
		if got := MatchesAny(patterns, rel); got != matched {
			t.Fatalf("MatchesAny(%#v, %q) = %t, want FirstMatch matched %t", patterns, rel, got, matched)
		}
	})
}

// FuzzFirstMatchAgreement proves that valid candidate lists return the earliest
// matching pattern and that MatchesAny reports the same boolean.
func FuzzFirstMatchAgreement(f *testing.F) {
	f.Add("*.go", "docs/**", "main.go")
	f.Add("ignored/", "ignored/**", "ignored/nested/main.go")
	f.Add("pkg/*.go", "./pkg/main.go", "pkg/main.go")
	f.Fuzz(func(t *testing.T, first, second, rel string) {
		patterns := []string{first, second, first}
		for _, pattern := range patterns {
			if Validate(pattern) != nil {
				return
			}
		}

		wantMatched := false
		wantPattern := ""
		for _, pattern := range patterns {
			if Matches(pattern, rel) {
				wantMatched = true
				wantPattern = pattern
				break
			}
		}

		matched, pattern := FirstMatch(patterns, rel)
		if matched != wantMatched || pattern != wantPattern {
			t.Fatalf("FirstMatch(%#v, %q) = (%t, %q), want (%t, %q)", patterns, rel, matched, pattern, wantMatched, wantPattern)
		}
		if got := MatchesAny(patterns, rel); got != matched {
			t.Fatalf("MatchesAny(%#v, %q) = %t, want %t", patterns, rel, got, matched)
		}
	})
}
