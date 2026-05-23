package rule

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// Constants long enough that the redaction helper keeps its
// "<prefix>...<suffix>" form rather than collapsing the entire match to
// "[redacted]". The match must be at least 13 characters for that branch.
const (
	rawAWSKey            = "AKIAIOSFODNN7EXAMPLE"
	rawJWT               = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	rawPrivateKey        = "-----BEGIN RSA PRIVATE KEY-----"
	rawConnectionURL     = "postgres://app:supersecretpassword@db.internal:5432/orders"
	rawGitHubToken       = "ghp_0000000000000000000000000000000000ZZ"
	rawSlackToken        = "xoxb-1234567890123-9876543210987-AbCdEfGhIjKlMnOpQrSt"
	rawStripeKey         = "sk_live_0000000000000000000000ZZ"
	rawGoogleAPIKey      = "AIza00000000000000000000000000000000ZZZ"
	rawAnthropicAPIKey   = "sk-ant-00000000000000000000ZZ"
	rawGCPServiceAccount = `{
  "type": "service_account",
  "project_id": "example-project",
  "private_key_id": "0000000000000000000000000000000000000000",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...EXAMPLE...END\n-----END PRIVATE KEY-----\n",
  "client_email": "svc@example-project.iam.gserviceaccount.com"
}`
)

func TestPrivateKeyRuleDetectsPEMHeader(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "tls_key = \"" + rawPrivateKey + "\\n...\"\n",
	}
	findings := PrivateKeyRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawPrivateKey)
}

func TestAWSAccessKeyRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "aws_access_key_id = " + rawAWSKey + "\n",
	}
	findings := AWSAccessKeyRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawAWSKey)
}

func TestJWTTokenRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "session_token = \"" + rawJWT + "\"\n",
	}
	findings := JWTTokenRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawJWT)
}

func TestConnectionStringRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "DATABASE_URL=" + rawConnectionURL + "\n",
	}
	findings := ConnectionStringRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1; got %#v", len(findings), findings)
	}
	assertNoRawSecret(t, findings[0], "supersecretpassword")
}

func TestGitHubTokenRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "github_token = " + rawGitHubToken + "\n",
	}
	findings := GitHubTokenRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawGitHubToken)
}

func TestSlackTokenRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "slack_token = " + rawSlackToken + "\n",
	}
	findings := SlackTokenRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawSlackToken)
}

func TestStripeLiveKeyRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "stripe_key = " + rawStripeKey + "\n",
	}
	findings := StripeLiveKeyRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawStripeKey)
}

func TestGoogleAPIKeyRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "google_api_key = " + rawGoogleAPIKey + "\n",
	}
	findings := GoogleAPIKeyRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawGoogleAPIKey)
}

func TestAnthropicAPIKeyRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "anthropic_key = " + rawAnthropicAPIKey + "\n",
	}
	findings := AnthropicAPIKeyRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawAnthropicAPIKey)
}

// TestGoogleAPIKeyRuleRejectsShortPrefix asserts the regex's fixed-width
// suffix requirement prevents a bare AIza prefix from firing as a finding.
func TestGoogleAPIKeyRuleRejectsShortPrefix(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "google_api_key = AIzaSyShort\n",
	}
	if got := (GoogleAPIKeyRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("expected no findings for short prefix, got %#v", got)
	}
}

// TestSlackTokenRuleRejectsBarePrefix asserts a bare xox[bpar]- with no body
// is not matched as a token.
func TestSlackTokenRuleRejectsBarePrefix(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "slack_token = xoxp-\n",
	}
	if got := (SlackTokenRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("expected no findings for bare prefix, got %#v", got)
	}
}

// TestGCPServiceAccountRuleDetectsBothMarkers asserts a JSON file containing
// both the `"type": "service_account"` marker and a PEM private-key header
// produces exactly one finding, located at the type marker line, with both
// markers redacted in the preview metadata.
func TestGCPServiceAccountRuleDetectsBothMarkers(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "service-account.json", Type: source.FileTypeText},
		Source: rawGCPServiceAccount,
	}
	findings := GCPServiceAccountRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Location == nil || findings[0].Location.Line != 2 {
		t.Fatalf("finding should locate at the type marker line (2), got %#v", findings[0].Location)
	}
	assertNoRawSecret(t, findings[0], `"type": "service_account"`)
	secondaryPreview, _ := findings[0].Metadata["secondaryPreview"].(string)
	if secondaryPreview == "" {
		t.Errorf("secondary preview should be present in metadata, got empty")
	}
	if strings.Contains(secondaryPreview, "MIIE") {
		t.Errorf("secondary preview should not leak raw private-key body, got %q", secondaryPreview)
	}
	if secondaryLine, _ := findings[0].Metadata["secondaryLine"].(int); secondaryLine != 5 {
		t.Errorf("secondary marker line should be 5 (the private_key line), got %d", secondaryLine)
	}
}

// TestGCPServiceAccountRuleIgnoresTypeOnly asserts the type marker alone (a
// common documentation snippet) does not trigger a finding.
func TestGCPServiceAccountRuleIgnoresTypeOnly(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "docs.json", Type: source.FileTypeText},
		Source: `{"type": "service_account", "project_id": "demo"}` + "\n",
	}
	if got := (GCPServiceAccountRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("expected no findings on type marker alone, got %#v", got)
	}
}

// TestGCPServiceAccountRuleIgnoresPrivateKeyOnly asserts a PEM private key
// without the service-account type marker does not trigger a GCP finding.
// (sensitive-data.private-key will still fire on this input - tested elsewhere.)
func TestGCPServiceAccountRuleIgnoresPrivateKeyOnly(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "key.pem", Type: source.FileTypeText},
		Source: "-----BEGIN PRIVATE KEY-----\nMIIE...END\n-----END PRIVATE KEY-----\n",
	}
	if got := (GCPServiceAccountRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("expected no findings on PEM key alone, got %#v", got)
	}
}

// TestGCPServiceAccountRuleIgnoresCommentOnlyMarkers asserts both markers
// inside Go comments do not trigger a finding.
func TestGCPServiceAccountRuleIgnoresCommentOnlyMarkers(t *testing.T) {
	cases := map[string]string{
		"line comment":  "// Example: \"type\": \"service_account\"\n// -----BEGIN PRIVATE KEY-----\n",
		"block comment": "/*\n  \"type\": \"service_account\"\n  -----BEGIN PRIVATE KEY-----\n*/\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			unit := parser.Unit{
				File:   source.File{Path: "doc.go", Type: source.FileTypeGo},
				Source: src,
			}
			if got := (GCPServiceAccountRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
				t.Fatalf("expected no findings on comment-only source, got %#v", got)
			}
		})
	}
}

// TestGCPServiceAccountRuleHonorsNoSecAnnotation asserts a #nosec annotation
// on the type marker line silences the finding, mirroring the suppression
// contract of the other sensitive-data.* rules.
func TestGCPServiceAccountRuleHonorsNoSecAnnotation(t *testing.T) {
	src := `{
  "type": "service_account", // #nosec G101 -- fixture
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"
}`
	unit := parser.Unit{
		File:   source.File{Path: "fixture.json", Type: source.FileTypeText},
		Source: src,
	}
	if got := (GCPServiceAccountRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("expected #nosec to suppress finding, got %#v", got)
	}
}

func TestSensitiveDetectorsAreDefaultEnabled(t *testing.T) {
	for _, definition := range []Definition{
		PrivateKeyRule{}.Definition(),
		AWSAccessKeyRule{}.Definition(),
		JWTTokenRule{}.Definition(),
		ConnectionStringRule{}.Definition(),
		GitHubTokenRule{}.Definition(),
		SlackTokenRule{}.Definition(),
		StripeLiveKeyRule{}.Definition(),
		GoogleAPIKeyRule{}.Definition(),
		AnthropicAPIKeyRule{}.Definition(),
		GCPServiceAccountRule{}.Definition(),
	} {
		if !definition.DefaultEnabled {
			t.Errorf("rule %q must be default-enabled", definition.ID)
		}
	}
}

func TestSensitiveDetectorsAreCleanOnInnocuousInput(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "ok.env", Type: source.FileTypeText},
		Source: "greeting = \"hello world\"\nport = 5432\n",
	}
	for _, rule := range []UnitRule{
		PrivateKeyRule{},
		AWSAccessKeyRule{},
		JWTTokenRule{},
		ConnectionStringRule{},
		GitHubTokenRule{},
		SlackTokenRule{},
		StripeLiveKeyRule{},
		GoogleAPIKeyRule{},
		AnthropicAPIKeyRule{},
		GCPServiceAccountRule{},
	} {
		if got := rule.AnalyzeUnit(unit, Context{}); len(got) != 0 {
			t.Errorf("rule %q produced findings on clean input: %#v", rule.Definition().ID, got)
		}
	}
}

// TestScanLinesForSecretSkipsComments asserts comment-only lines do not trigger findings.
// This keeps "format: postgres://user:password@host" doc snippets from looking like leaks.
func TestScanLinesForSecretSkipsComments(t *testing.T) {
	cases := []struct {
		name   string
		source string
	}{
		{name: "line comment", source: "// Example: postgres://app:supersecretpassword@db.internal:5432/orders\n"},
		{name: "godoc tab indent", source: "//\tpostgres://app:supersecretpassword@db.internal:5432/orders\n"},
		{name: "block comment one line", source: "/* postgres://app:supersecretpassword@db.internal:5432/orders */\n"},
		{name: "block comment multi line", source: "/*\npostgres://app:supersecretpassword@db.internal:5432/orders\n*/\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unit := parser.Unit{
				File:   source.File{Path: "doc.go", Type: source.FileTypeGo},
				Source: tc.source,
			}
			if got := (ConnectionStringRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
				t.Fatalf("expected no findings on comment-only source, got %#v", got)
			}
		})
	}
}

// TestScanLinesForSecretHonoursSuppressions asserts inline annotations silence findings.
// gosec's `#nosec` and golangci-lint's `//nolint:gosec` / `//nolint:all` are both honored.
func TestScanLinesForSecretHonoursSuppressions(t *testing.T) {
	cases := []string{
		"DATABASE_URL=postgres://app:supersecretpassword@db.internal:5432/orders // #nosec G101 -- fixture",
		"DATABASE_URL=postgres://app:supersecretpassword@db.internal:5432/orders //nolint:gosec",
		"DATABASE_URL=postgres://app:supersecretpassword@db.internal:5432/orders //nolint:gosec,goconst",
		"DATABASE_URL=postgres://app:supersecretpassword@db.internal:5432/orders //nolint:all",
	}
	for _, line := range cases {
		t.Run(line[:20], func(t *testing.T) {
			unit := parser.Unit{
				File:   source.File{Path: "main.go", Type: source.FileTypeGo},
				Source: line + "\n",
			}
			if got := (ConnectionStringRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
				t.Fatalf("expected suppressed line to produce no findings, got %#v", got)
			}
		})
	}
}

// TestConnectionStringRuleSkipsPlaceholderCredentials asserts dev fixtures pointing at
// localhost-style hosts with obvious placeholder passwords are not flagged.
func TestConnectionStringRuleSkipsPlaceholderCredentials(t *testing.T) {
	cases := []string{
		`const u = "postgres://app:dev_password_change_me@localhost:5432/orders"`,
		`const u = "postgres://app:changeme@127.0.0.1:5432/orders"`,
		`const u = "postgres://app:your-password@db:5432/orders"`,
		`const u = "postgres://app:placeholder@localhost/orders"`,
	}
	for _, src := range cases {
		t.Run(src[:32], func(t *testing.T) {
			unit := parser.Unit{
				File:   source.File{Path: "fixture.go", Type: source.FileTypeGo},
				Source: src + "\n",
			}
			if got := (ConnectionStringRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
				t.Fatalf("expected placeholder credential to be skipped, got %#v", got)
			}
		})
	}
}

// TestConnectionStringRuleStillFlagsRealLookingSecrets asserts the placeholder
// heuristic does not swallow credentials that look like production: either the
// host is not local, or the password lacks a placeholder marker.
func TestConnectionStringRuleStillFlagsRealLookingSecrets(t *testing.T) {
	cases := []string{
		`u = "postgres://app:supersecretpassword@db.internal:5432/orders"`,   // non-local host
		`u = "postgres://app:Tr0ub4dor&3@localhost:5432/orders"`,             // local but real-looking pass
		`u = "postgres://service:9XmPq2VkL8wHb6Nz@localhost:5432/prod"`,      // local but high-entropy pass
		`u = "mongodb://admin:realPassword2024@10.0.0.5:27017/app?ssl=true"`, // private IP, real-looking
	}
	for _, src := range cases {
		t.Run(src[:32], func(t *testing.T) {
			unit := parser.Unit{
				File:   source.File{Path: "fixture.go", Type: source.FileTypeGo},
				Source: src + "\n",
			}
			if got := (ConnectionStringRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
				t.Fatalf("expected one finding on real-looking secret, got %#v", got)
			}
		})
	}
}

func assertNoRawSecret(t *testing.T, item finding.Finding, raw string) {
	t.Helper()
	if strings.Contains(item.Message, raw) {
		t.Errorf("rule message leaks raw secret: %q", item.Message)
	}
	if preview, ok := item.Metadata["preview"].(string); ok {
		if preview == raw || strings.Contains(preview, raw) {
			t.Errorf("rule preview leaks raw secret: %q", preview)
		}
	}
}
