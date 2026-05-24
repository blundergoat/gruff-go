// Package rule tests parser-only HTTP security rules.
package rule

import "testing"

// TestHTTPClientNoTimeoutRule covers client literals with and without Timeout.
func TestHTTPClientNoTimeoutRule(t *testing.T) {
	tests := []struct {
		name string
		file string
		code string
		want int
	}{
		{
			name: "empty client",
			file: "client.go",
			code: `// Package sample is a test package.
package sample

import "net/http"

func sample() *http.Client {
	return &http.Client{}
}
`,
			want: 1,
		},
		{
			name: "transport but no timeout",
			file: "client.go",
			code: `// Package sample is a test package.
package sample

import "net/http"

func sample(rt http.RoundTripper) http.Client {
	return http.Client{Transport: rt}
}
`,
			want: 1,
		},
		{
			name: "timeout set",
			file: "client.go",
			code: `// Package sample is a test package.
package sample

import (
	"net/http"
	"time"
)

func sample() http.Client {
	return http.Client{Timeout: 5 * time.Second}
}
`,
			want: 0,
		},
		{
			name: "test file skipped",
			file: "client_test.go",
			code: `package sample

import "net/http"

func sample() http.Client {
	return http.Client{}
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, tt.file, tt.code)
			findings := HTTPClientNoTimeoutRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}

// TestRequestBodyWithoutLimitRule covers unbounded request-body reads and obvious limiters.
func TestRequestBodyWithoutLimitRule(t *testing.T) {
	tests := []struct {
		name string
		file string
		code string
		want int
	}{
		{
			name: "direct readall body",
			file: "handler.go",
			code: `// Package sample is a test package.
package sample

import (
	"io"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	_, _ = io.ReadAll(r.Body)
	_ = w
}
`,
			want: 1,
		},
		{
			name: "max bytes reader assignment",
			file: "handler.go",
			code: `// Package sample is a test package.
package sample

import (
	"io"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	_, _ = io.ReadAll(r.Body)
}
`,
			want: 0,
		},
		{
			name: "limit reader direct",
			file: "handler.go",
			code: `// Package sample is a test package.
package sample

import (
	"io"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	_, _ = io.ReadAll(io.LimitReader(r.Body, 1024))
	_ = w
}
`,
			want: 0,
		},
		{
			name: "non request body",
			file: "reader.go",
			code: `// Package sample is a test package.
package sample

import "io"

func read(body io.Reader) {
	_, _ = io.ReadAll(body)
}
`,
			want: 0,
		},
		{
			name: "test file skipped",
			file: "handler_test.go",
			code: `package sample

import (
	"io"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	_, _ = io.ReadAll(r.Body)
	_ = w
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, tt.file, tt.code)
			findings := RequestBodyWithoutLimitRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}
