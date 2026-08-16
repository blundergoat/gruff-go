// Package rule tests that shadowed import names are not read as their packages.
package rule

import "testing"

// TestRequestControlledURLPackageShadowing pins that a local shadowing an import
// stops naming that package, while every genuine net/http sink still reports.
func TestRequestControlledURLPackageShadowing(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "local shadowing net/http is not the package helper",
			code: `// Package handler is a test package.
package handler

import "net/http"

type localHTTP struct{}

func (localHTTP) Get(name string) (int, error) { return len(name), nil }

func fetch(w http.ResponseWriter, r *http.Request) {
	http := localHTTP{}
	_, _ = http.Get(r.FormValue("url"))
}
`,
			want: 0,
		},
		{
			name: "local shadowing fmt does not carry taint",
			code: `// Package handler is a test package.
package handler

import (
	"fmt"
	"net/http"
)

type localFmt struct{}

func (localFmt) Sprintf(format string, args ...any) string { return format }

func describe() string { return fmt.Sprint("used") }

func fetch(w http.ResponseWriter, r *http.Request) {
	fmt := localFmt{}
	target := fmt.Sprintf("%s", r.FormValue("url"))
	_, _ = http.Get(target)
}
`,
			want: 0,
		},
		{
			name: "the real package helper still reports",
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
			name: "the real default client still reports",
			code: `// Package handler is a test package.
package handler

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	_, _ = http.DefaultClient.Get(r.FormValue("url"))
}
`,
			want: 1,
		},
		{
			name: "an aliased net/http import still reports",
			code: `// Package handler is a test package.
package handler

import nethttp "net/http"

func fetch(w nethttp.ResponseWriter, r *nethttp.Request) {
	_, _ = nethttp.Get(r.FormValue("url"))
}
`,
			want: 1,
		},
		{
			name: "the real fmt package still carries taint",
			code: `// Package handler is a test package.
package handler

import (
	"fmt"
	"net/http"
)

func fetch(w http.ResponseWriter, r *http.Request) {
	target := fmt.Sprintf("%s", r.FormValue("url"))
	_, _ = http.Get(target)
}
`,
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "handler.go", tt.code)
			findings := RequestControlledURLRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}
