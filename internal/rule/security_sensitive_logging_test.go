// Package rule tests what users see when a Go scan checks logging calls.

// These fixtures separate a configured file path from the password stored in that file.
// They also keep request and environment credentials visible in scan results.
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
			name: "secret beside hashed sibling still fires",
			code: `// Package svc is a test package.
package svc

import (
	"crypto/sha256"
	"fmt"
	"log"
)

func login(password string, nonce []byte) {
	log.Print(fmt.Sprintf("%s %x", password, sha256.Sum256(nonce)))
}
`,
			want: 1,
		},
		{
			name: "secret wrapped by hash is suppressed",
			code: `// Package svc is a test package.
package svc

import (
	"crypto/sha256"
	"log"
)

func login(password string) {
	log.Printf("hash=%x", sha256.Sum256([]byte(password)))
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

// TestSensitiveDataLoggingRuleConfiguredFilePath keeps a configured password file path quiet.
// Password contents and unsafe path origins still produce a warning for the user.
func TestSensitiveDataLoggingRuleConfiguredFilePath(t *testing.T) {
	const source = `// Package svc models an auth method configured with a password file path.
package svc

import (
	"net/http"
	"os"
)

type logger struct{}
func (logger) Info(string, ...any) {}

type authConfig struct { Config map[string]any }
type ldapMethod struct {
	logger logger
	passwordFilePath string
}

func newAuth(conf authConfig, passwordContents string, request *http.Request) *ldapMethod {
	k := &ldapMethod{}
	passFilePathRaw, _ := conf.Config["password_file_path"]
	k.passwordFilePath, _ = passFilePathRaw.(string)
	k.logger.Info("created", "password_file_path", k.passwordFilePath)
	return k
}

func (k *ldapMethod) readPassword() {
	passwordContents, _ := os.ReadFile(k.passwordFilePath)
	_ = passwordContents
}
`
	tests := []struct {
		name        string
		old         string
		replacement string
		want        int
	}{
		{name: "configured file path", want: 0},
		{
			name:        "password contents beside path",
			old:         `k.logger.Info("created", "password_file_path", k.passwordFilePath)`,
			replacement: `k.logger.Info("created", "password_file_path", k.passwordFilePath, "password", passwordContents)`,
			want:        1,
		},
		{
			name:        "secret config origin",
			old:         `conf.Config["password_file_path"]`,
			replacement: `conf.Config["password"]`,
			want:        1,
		},
		{
			name:        "secret overwrites path",
			old:         `k.passwordFilePath, _ = passFilePathRaw.(string)`,
			replacement: "k.passwordFilePath, _ = passFilePathRaw.(string)\n\tk.passwordFilePath = passwordContents",
			want:        1,
		},
		{
			name: "secret remains when config assignment is conditional",
			old:  "k := &ldapMethod{}\n\tpassFilePathRaw, _ := conf.Config[\"password_file_path\"]\n\tk.passwordFilePath, _ = passFilePathRaw.(string)",
			replacement: "k := &ldapMethod{passwordFilePath: passwordContents}\n\tpassFilePathRaw, _ := conf.Config[\"password_file_path\"]\n" +
				"\tif len(conf.Config) > 0 { k.passwordFilePath, _ = passFilePathRaw.(string) }",
			want: 1,
		},
		{
			name:        "environment value assigned to path field",
			old:         `passFilePathRaw, _ := conf.Config["password_file_path"]`,
			replacement: `passFilePathRaw := any(os.Getenv("PASSWORD"))`,
			want:        1,
		},
		{
			name:        "no file-read role",
			old:         `os.ReadFile(k.passwordFilePath)`,
			replacement: `os.Stat(k.passwordFilePath)`,
			want:        1,
		},
		{
			name: "another receiver is read after the configured path",
			old: `func (k *ldapMethod) readPassword() {
	passwordContents, _ := os.ReadFile(k.passwordFilePath)
	_ = passwordContents
}`,
			replacement: `func (k *ldapMethod) readPassword(other *ldapMethod) {
	passwordContents, _ := os.ReadFile(k.passwordFilePath)
	_ = passwordContents
	_, _ = os.ReadFile(other.passwordFilePath)
}`,
			want: 0,
		},
		{
			name:        "request authorization beside path",
			old:         `k.logger.Info("created", "password_file_path", k.passwordFilePath)`,
			replacement: `k.logger.Info("created", "password_file_path", k.passwordFilePath, "authorization", request.Header.Get("Authorization"))`,
			want:        1,
		},
		{
			name:        "environment password beside path",
			old:         `k.logger.Info("created", "password_file_path", k.passwordFilePath)`,
			replacement: `k.logger.Info("created", "password_file_path", k.passwordFilePath, "password", os.Getenv("PASSWORD"))`,
			want:        1,
		},
	}
	// Each variant models one user change to an auth method before scanning the file.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code := source
			// An empty replacement leaves the observed benign source shape intact.
			if test.old != "" {
				// A missing mutation anchor would let an unsafe fixture pass as the unchanged source.
				if strings.Count(code, test.old) != 1 {
					t.Fatalf("mutation anchor %q must occur once", test.old)
				}
				code = strings.Replace(code, test.old, test.replacement, 1)
			}
			findings := SensitiveDataLoggingRule{}.AnalyzeUnit(parseOne(t, "svc.go", code), Context{})
			// A scan must report only the credential-bearing variant, at the expected count.
			if len(findings) != test.want {
				t.Fatalf("findings = %#v, want %d", findings, test.want)
			}
		})
	}
}

// TestSensitiveDataLoggingRuleShareThreshold keeps the required share count out of log warnings.
// Secret integers, changed sources and credentials beside that count must still warn.
func TestSensitiveDataLoggingRuleShareThreshold(t *testing.T) {
	const source = `// Package svc models a seal update that reports the required number of shares.
package svc

import (
	"context"
	"net/http"
	"os"
)

type SealConfig struct { SecretThreshold int }
func (config *SealConfig) SetThreshold(value int) { config.SecretThreshold = value }
type GenerateRootResult struct { Progress, Required int }
type sealStore struct{}
func (sealStore) RecoveryKeySupported() bool { return true }
func (sealStore) RecoveryConfig(context.Context) (*SealConfig, error) { return nil, nil }
func (sealStore) BarrierConfig(context.Context) (*SealConfig, error) { return nil, nil }
type logger struct{}
func (logger) Debug(string, ...any) {}
func (logger) IsDebug() bool { return true }
type Core struct {
	seal sealStore
	logger logger
	generateRootProgress [][]byte
}

func (c *Core) update(ctx context.Context, request *http.Request, key []byte, secretOTP int) *GenerateRootResult {
	var config *SealConfig
	var err error
	// The user's seal mode chooses the required number of shares.
	if c.seal.RecoveryKeySupported() {
		config, err = c.seal.RecoveryConfig(ctx)
	} else {
		config, err = c.seal.BarrierConfig(ctx)
	}
	_ = err
	c.generateRootProgress = append(c.generateRootProgress, key)
	progress := len(c.generateRootProgress)
	// The progress event appears while more shares are needed.
	if len(c.generateRootProgress) < config.SecretThreshold {
		// Only an enabled debug log shows the operator this count.
		if c.logger.IsDebug() {
			c.logger.Debug("need keys", "keys", progress, "threshold", config.SecretThreshold)
		}
		return &GenerateRootResult{Progress: progress, Required: config.SecretThreshold}
	}
	return nil
}
`
	tests := []struct {
		name        string
		old         string
		replacement string
		want        int
	}{
		{name: "share count", want: 0},
		{
			name: "secret integer under threshold key", old: `"threshold", config.SecretThreshold`,
			replacement: `"threshold", secretOTP`, want: 1,
		},
		{
			name: "secret integer beside count", old: `"threshold", config.SecretThreshold)`,
			replacement: `"threshold", config.SecretThreshold, "otp", secretOTP)`, want: 1,
		},
		{
			name: "request credential beside count", old: `"threshold", config.SecretThreshold)`,
			replacement: `"threshold", config.SecretThreshold, "authorization", request.Header.Get("Authorization"))`, want: 1,
		},
		{
			name: "environment credential beside count", old: `"threshold", config.SecretThreshold)`,
			replacement: `"threshold", config.SecretThreshold, "password", os.Getenv("API_SECRET"))`, want: 1,
		},
		{name: "secret assigned to threshold", old: `_ = err`, replacement: `_ = err
	config.SecretThreshold = secretOTP`, want: 1},
		{
			name: "missing count comparison", old: `if len(c.generateRootProgress) < config.SecretThreshold`,
			replacement: `if len(c.generateRootProgress) < secretOTP`, want: 1,
		},
		{name: "missing required count", old: `Required: config.SecretThreshold`, replacement: `Required: progress`, want: 1},
		{name: "changed seal source", old: `c.seal.BarrierConfig(ctx)`, replacement: `c.seal.SecretConfig(ctx)`, want: 1},
		{name: "overwritten progress", old: `progress := len(c.generateRootProgress)`, replacement: `progress := len(c.generateRootProgress)
	progress = secretOTP`, want: 1},
		{name: "threshold changed through alias", old: `_ = err`, replacement: `_ = err
	secretAlias := config
	secretAlias.SecretThreshold = secretOTP`, want: 1},
		{name: "threshold changed through var alias", old: `_ = err`, replacement: `_ = err
	var secretAlias = config
	secretAlias.SecretThreshold = secretOTP`, want: 1},
		{name: "threshold changed through collection alias", old: `_ = err`, replacement: `_ = err
	secretAliases := []*SealConfig{config}
	secretAliases[0].SecretThreshold = secretOTP`, want: 1},
		{name: "threshold address escapes", old: `_ = err`, replacement: `_ = err
	setSecret(&config.SecretThreshold)`, want: 1},
		{name: "threshold incremented", old: `_ = err`, replacement: `_ = err
	config.SecretThreshold++`, want: 1},
		{name: "threshold changed through pointer", old: `_ = err`, replacement: `_ = err
	*config = SealConfig{SecretThreshold: secretOTP}`, want: 1},
		{name: "threshold changed through dereference", old: `_ = err`, replacement: `_ = err
	(*config).SecretThreshold = secretOTP`, want: 1},
		{name: "threshold changed through method", old: `_ = err`, replacement: `_ = err
	config.SetThreshold(secretOTP)`, want: 1},
		{name: "progress address escapes", old: `progress := len(c.generateRootProgress)`, replacement: `progress := len(c.generateRootProgress)
	setSecret(&progress)`, want: 1},
	}
	// Each mutation models a change a user might make to a seal update before scanning it.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code := source
			// An empty mutation keeps the observed share-count shape for the benign case.
			if test.old != "" {
				// A missing anchor would silently turn an unsafe control into the benign source.
				if strings.Count(code, test.old) != 1 {
					t.Fatalf("mutation anchor %q must occur once", test.old)
				}
				code = strings.Replace(code, test.old, test.replacement, 1)
			}
			findings := SensitiveDataLoggingRule{}.AnalyzeUnit(parseOne(t, "svc.go", code), Context{})
			// The scan should only report the credential-bearing mutation.
			if len(findings) != test.want {
				t.Fatalf("findings = %#v, want %d", findings, test.want)
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
