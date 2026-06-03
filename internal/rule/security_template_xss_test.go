// Package rule tests the parser-only template-injection/XSS security rule.
package rule

import "testing"

// TestTemplateInjectionXSSRule covers unescaped HTML response shapes and the
// auto-escaped or escaped cases that must not fire.
func TestTemplateInjectionXSSRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "text template to response",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"text/template"
)

func render(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.New("p").Parse("<b>{{.}}</b>"))
	_ = t.Execute(w, r.URL.Query().Get("name"))
}
`,
			want: 1,
		},
		{
			name: "html template unsafe conversion of request value",
			code: `// Package handler is a test package.
package handler

import (
	"html/template"
	"net/http"
)

func render(w http.ResponseWriter, r *http.Request) {
	_ = template.HTML(r.FormValue("bio"))
}
`,
			want: 1,
		},
		{
			name: "raw response write of request value on html",
			code: `// Package handler is a test package.
package handler

import (
	"fmt"
	"net/http"
)

func render(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<h1>%s</h1>", r.URL.Query().Get("q"))
}
`,
			want: 1,
		},
		{
			name: "content type set on request header is not the response type",
			code: `// Package handler is a test package.
package handler

import (
	"fmt"
	"net/http"
)

func render(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<h1>%s</h1>", r.URL.Query().Get("q"))
}
`,
			want: 0,
		},
		{
			name: "html template auto escaped is safe",
			code: `// Package handler is a test package.
package handler

import (
	"html/template"
	"net/http"
)

func render(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.New("p").Parse("<b>{{.}}</b>"))
	_ = t.Execute(w, r.URL.Query().Get("name"))
}
`,
			want: 0,
		},
		{
			name: "escaped request value conversion",
			code: `// Package handler is a test package.
package handler

import (
	"html"
	"html/template"
	"net/http"
)

func render(w http.ResponseWriter, r *http.Request) {
	_ = template.HTML(html.EscapeString(r.FormValue("bio")))
}
`,
			want: 0,
		},
		{
			name: "raw write of static html is safe",
			code: `// Package handler is a test package.
package handler

import (
	"fmt"
	"net/http"
)

func render(w http.ResponseWriter, r *http.Request) {
	_ = r
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<h1>%s</h1>", "welcome")
}
`,
			want: 0,
		},
		{
			name: "raw write of request value without html content type",
			code: `// Package handler is a test package.
package handler

import (
	"fmt"
	"net/http"
)

func render(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "%q", r.URL.Query().Get("q"))
}
`,
			want: 0,
		},
		{
			name: "text template with static data is not flagged",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"
	"text/template"
)

func render(w http.ResponseWriter, r *http.Request) {
	_ = r
	t := template.Must(template.New("p").Parse("<b>{{.}}</b>"))
	_ = t.Execute(w, "welcome")
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "handler.go", tt.code)
			findings := TemplateInjectionXSSRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}
