// Package rule tests parser-only request-driven URL security rules.
package rule

import "testing"

// TestRequestControlledURLRule covers SSRF sinks and validated/safe non-findings.
func TestRequestControlledURLRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "direct form value to http.Get",
			code: `// Package handler is a test package.
package handler

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	_, _ = http.Get(r.FormValue("url"))
}
`,
			want: 1,
		},
		{
			name: "tainted local to http.Get",
			code: `// Package handler is a test package.
package handler

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("u")
	_, _ = http.Get(target)
}
`,
			want: 1,
		},
		{
			name: "new request with request url",
			code: `// Package handler is a test package.
package handler

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	_, _ = http.NewRequest("GET", r.URL.Query().Get("u"), nil)
}
`,
			want: 1,
		},
		{
			name: "client method with request url",
			code: `// Package handler is a test package.
package handler

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 0}
	_, _ = client.Get(r.FormValue("u"))
}
`,
			want: 1,
		},
		{
			name: "concatenated request url",
			code: `// Package handler is a test package.
package handler

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	_, _ = http.Get("https://api.example.com/" + r.URL.Query().Get("p"))
}
`,
			want: 1,
		},
		{
			name: "fixed literal url",
			code: `// Package handler is a test package.
package handler

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	_ = r
	_, _ = http.Get("https://fixed.example.com/status")
}
`,
			want: 0,
		},
		{
			name: "validated before fetch",
			code: `// Package handler is a test package.
package handler

import "net/http"

func validateURL(string) bool { return true }

func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("u")
	if !validateURL(target) {
		return
	}
	_, _ = http.Get(target)
}
`,
			want: 0,
		},
		{
			name: "non request url helper",
			code: `// Package handler is a test package.
package handler

import "net/http"

func buildURL() string { return "https://internal" }

func fetch(w http.ResponseWriter, r *http.Request) {
	_ = r
	_, _ = http.Get(buildURL())
}
`,
			want: 0,
		},
		{
			name: "validated after fetch still flags",
			code: `// Package handler is a test package.
package handler

import "net/http"

func validateURL(string) bool { return true }

func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("u")
	_, _ = http.Get(target)
	_ = validateURL(target)
}
`,
			want: 1,
		},
		{
			name: "auth check on request does not suppress inline ssrf",
			code: `// Package handler is a test package.
package handler

import "net/http"

func validateSession(*http.Request) bool { return true }

func fetch(w http.ResponseWriter, r *http.Request) {
	if !validateSession(r) {
		return
	}
	_, _ = http.Get(r.FormValue("url"))
}
`,
			want: 1,
		},
		{
			name: "request value assigned after sink is not tainted at sink",
			code: `// Package handler is a test package.
package handler

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	target := "https://fixed.example.com/status"
	_, _ = http.Get(target)
	target = r.FormValue("u")
	_ = target
}
`,
			want: 0,
		},
		{
			name: "test file skipped",
			code: `// Package handler is a test package.
package handler

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	_, _ = http.Get(r.FormValue("url"))
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := "handler.go"
			if tt.name == "test file skipped" {
				path = "handler_test.go"
			}
			unit := parseOne(t, path, tt.code)
			findings := RequestControlledURLRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}

// TestOpenRedirectRule covers request-controlled redirect targets and safe ones.
func TestOpenRedirectRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "redirect to request value",
			code: `// Package handler is a test package.
package handler

import "net/http"

func redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.FormValue("next"), http.StatusFound)
}
`,
			want: 1,
		},
		{
			name: "redirect to tainted local",
			code: `// Package handler is a test package.
package handler

import "net/http"

func redirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	http.Redirect(w, r, target, 302)
}
`,
			want: 1,
		},
		{
			name: "location header from request",
			code: `// Package handler is a test package.
package handler

import "net/http"

func redirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", r.FormValue("u"))
	w.WriteHeader(302)
}
`,
			want: 1,
		},
		{
			name: "location set on request header is not a response sink",
			code: `// Package handler is a test package.
package handler

import "net/http"

func handle(w http.ResponseWriter, r *http.Request) {
	_ = w
	r.Header.Set("Location", r.FormValue("u"))
}
`,
			want: 0,
		},
		{
			name: "fixed relative path",
			code: `// Package handler is a test package.
package handler

import "net/http"

func redirect(w http.ResponseWriter, r *http.Request) {
	_ = r
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
`,
			want: 0,
		},
		{
			name: "relative path with request query",
			code: `// Package handler is a test package.
package handler

import "net/http"

func redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard?ref="+r.URL.Query().Get("ref"), 302)
}
`,
			want: 0,
		},
		{
			name: "validated redirect target",
			code: `// Package handler is a test package.
package handler

import "net/http"

func isLocalRedirect(string) bool { return true }

func redirect(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("next")
	if isLocalRedirect(target) {
		http.Redirect(w, r, target, 302)
	}
}
`,
			want: 0,
		},
		{
			name: "bare slash prefix with request suffix",
			code: `// Package handler is a test package.
package handler

import "net/http"

func redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/"+r.URL.Query().Get("next"), 302)
}
`,
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "handler.go", tt.code)
			findings := OpenRedirectRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}
