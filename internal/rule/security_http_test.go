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
		{
			name: "round tripper reads its own outgoing request",
			file: "client.go",
			code: `// Package sample is a test package.
package sample

import (
	"io"
	"net/http"
)

type recorder struct{ body []byte }

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	r.body = body
	return nil, err
}
`,
			want: 0,
		},
		{
			name: "helper taking a testing handle reads the request it sends",
			file: "testhelpers/request.go",
			code: `// Package sample is a test package.
package sample

import (
	"io"
	"net/http"
	"testing"
)

func executeRequest(t *testing.T, req *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
`,
			want: 0,
		},
		{
			name: "handler method named RoundTrip still reports",
			file: "handler.go",
			code: `// Package sample is a test package.
package sample

import (
	"io"
	"net/http"
)

type server struct{}

func (server) RoundTrip(w http.ResponseWriter, r *http.Request) {
	_, _ = io.ReadAll(r.Body)
	_ = w
}
`,
			want: 1,
		},
		{
			name: "parameter named t without a testing type still reports",
			file: "handler.go",
			code: `// Package sample is a test package.
package sample

import (
	"io"
	"net/http"
)

type T struct{}

func handle(t *T, r *http.Request) {
	_, _ = io.ReadAll(r.Body)
	_ = t
}
`,
			want: 1,
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
