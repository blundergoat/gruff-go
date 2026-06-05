// Package rule tests the parser-only path-traversal security rule.
package rule

import "testing"

// TestPathTraversalFileAccessRule covers request-controlled file paths and the
// containment carve-outs that should not fire.
func TestPathTraversalFileAccessRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "open form path",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"os"
)

func read(w http.ResponseWriter, r *http.Request) {
	_, _ = os.Open(r.FormValue("file"))
}
`,
			want: 1,
		},
		{
			name: "joined request path",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"os"
	"path/filepath"
)

func read(w http.ResponseWriter, r *http.Request) {
	full := filepath.Join("/srv", r.URL.Query().Get("name"))
	_, _ = os.ReadFile(full)
}
`,
			want: 1,
		},
		{
			name: "serve file from url path",
			code: `// Package handler is a test package.
package handler

import "net/http"

func serve(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "."+r.URL.Path)
}
`,
			want: 1,
		},
		{
			name: "clean alone still flags",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"os"
	"path/filepath"
)

func read(w http.ResponseWriter, r *http.Request) {
	clean := filepath.Clean(r.FormValue("file"))
	_, _ = os.Open(clean)
}
`,
			want: 1,
		},
		{
			name: "inline clean alone still flags",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"os"
	"path/filepath"
)

func read(w http.ResponseWriter, r *http.Request) {
	_, _ = os.Open(filepath.Clean(r.FormValue("file")))
}
`,
			want: 1,
		},
		{
			name: "clean plus containment helper",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"os"
	"path/filepath"
)

func isWithinBase(string) bool { return true }

func read(w http.ResponseWriter, r *http.Request) {
	clean := filepath.Clean(r.FormValue("file"))
	if !isWithinBase(clean) {
		return
	}
	_, _ = os.Open(clean)
}
`,
			want: 0,
		},
		{
			name: "basename only",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"os"
	"path/filepath"
)

func read(w http.ResponseWriter, r *http.Request) {
	_, _ = os.Open(filepath.Base(r.FormValue("file")))
}
`,
			want: 0,
		},
		{
			name: "fixed path literal",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"os"
)

func read(w http.ResponseWriter, r *http.Request) {
	_ = r
	_, _ = os.ReadFile("/etc/config.yaml")
}
`,
			want: 0,
		},
		{
			name: "containment helper on tainted path",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"os"
	"path/filepath"
)

func isWithinBase(string) bool { return true }

func read(w http.ResponseWriter, r *http.Request) {
	name := filepath.Join("/srv", r.FormValue("file"))
	if !isWithinBase(name) {
		return
	}
	_, _ = os.Open(name)
}
`,
			want: 0,
		},
		{
			name: "unsafe-named helper is not a sanitizer",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"os"
)

func unsafePath(s string) string { return s }

func read(w http.ResponseWriter, r *http.Request) {
	_, _ = os.Open(unsafePath(r.FormValue("file")))
}
`,
			want: 1,
		},
		{
			name: "safe-named helper still suppresses",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"os"
)

func safePath(s string) string { return s }

func read(w http.ResponseWriter, r *http.Request) {
	_, _ = os.Open(safePath(r.FormValue("file")))
}
`,
			want: 0,
		},
		{
			name: "containment helper after sink does not cleanse",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"os"
	"path/filepath"
)

func isWithinBase(string) bool { return true }

func read(w http.ResponseWriter, r *http.Request) {
	name := filepath.Join("/srv", r.FormValue("file"))
	_, _ = os.Open(name)
	_ = isWithinBase(name)
}
`,
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "handler.go", tt.code)
			findings := PathTraversalFileAccessRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}
