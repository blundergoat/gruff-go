// Package rule tests the parser-only sensitive-data-logging security rule.
package rule

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestSensitiveDataLoggingRule covers credential-bearing log arguments and the
// static, non-secret, and redacted cases that must not fire.
func TestSensitiveDataLoggingRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "secret named identifier",
			code: `// Package svc is a test package.
package svc

import "log"

func login(password string) {
	log.Printf("attempt with %s", password)
}
`,
			want: 1,
		},
		{
			name: "env secret read",
			code: `// Package svc is a test package.
package svc

import (
	"log"
	"os"
)

func boot() {
	log.Println(os.Getenv("API_SECRET"))
}
`,
			want: 1,
		},
		{
			name: "request authorization header",
			code: `// Package svc is a test package.
package svc

import (
	"log"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	log.Printf("auth=%s", r.Header.Get("Authorization"))
}
`,
			want: 1,
		},
		{
			name: "request cookie",
			code: `// Package svc is a test package.
package svc

import (
	"log"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	log.Printf("cookie=%v", r.Cookie("session"))
}
`,
			want: 1,
		},
		{
			name: "structured logger secret",
			code: `// Package svc is a test package.
package svc

type Logger struct{}

func (Logger) Info(string, ...any) {}

func run(logger Logger, credential string) {
	logger.Info("issuing", credential)
}
`,
			want: 1,
		},
		{
			name: "static message only",
			code: `// Package svc is a test package.
package svc

import "log"

func boot() {
	log.Println("service started")
}
`,
			want: 0,
		},
		{
			name: "non secret value",
			code: `// Package svc is a test package.
package svc

import "log"

func tick(count int) {
	log.Printf("processed %d items", count)
}
`,
			want: 0,
		},
		{
			name: "redacted secret",
			code: `// Package svc is a test package.
package svc

import "log"

func redact(string) string { return "[redacted]" }

func login(password string) {
	log.Printf("attempt with %s", redact(password))
}
`,
			want: 0,
		},
		{
			name: "plain form value",
			code: `// Package svc is a test package.
package svc

import (
	"log"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	log.Printf("query=%s", r.FormValue("q"))
}
`,
			want: 0,
		},
		{
			name: "secret passed to non logging call",
			code: `// Package svc is a test package.
package svc

func store(string) {}

func save(password string) {
	store(password)
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "svc.go", tt.code)
			findings := SensitiveDataLoggingRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}

// TestSensitiveDataLoggingRuleRedactsMetadata proves a finding never carries the
// raw secret value, only the structural sink and reason.
func TestSensitiveDataLoggingRuleRedactsMetadata(t *testing.T) {
	const rawSecret = "hunter2-s3cret-literal-value"
	unit := parseOne(t, "svc.go", `// Package svc is a test package.
package svc

import "log"

func login() {
	password := "`+rawSecret+`"
	log.Printf("attempt with %s", password)
}
`)
	findings := SensitiveDataLoggingRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one logging finding", findings)
	}
	assertNoRawValue(t, findings[0], rawSecret)
}

// assertNoRawValue marshals a finding and fails if the raw value appears anywhere
// in its serialized form, guarding the no-raw-secrets contract for security rules.
func assertNoRawValue(t *testing.T, item finding.Finding, raw string) {
	t.Helper()
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	if strings.Contains(string(encoded), raw) {
		t.Fatalf("finding leaks raw value %q: %s", raw, encoded)
	}
}
