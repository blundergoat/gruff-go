// Package rule tests how credential detectors turn source text into redacted findings for a developer's scan.
//
// This file covers private keys, provider tokens, GCP service-account files, connection strings and their sample or placeholder controls.
// The private-key cases exercise both text files and Go syntax so parser definitions do not hide embedded key material.
package rule

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// Detector fixtures are long enough to exercise realistic provider shapes; every value is a fake built for these tests.
//
// The tests run zero-value rules and check that no finding's message or preview carries the raw value.
const (
	rawAWSKey            = "AKIA" + "Q7R2M8N4P6T9V1X3"
	rawJWT               = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	rawPrivateKey        = "-----BEGIN RSA PRIVATE KEY-----"
	rawConnectionURL     = "postgres://app:supersecretpassword@db.internal:5432/orders"
	rawGitHubToken       = "ghp_0000000000000000000000000000000000ZZ"
	rawSlackToken        = "xoxb-1234567890123-9876543210987-AbCdEfGhIjKlMnOpQrSt"
	rawStripeKey         = "sk_live_0000000000000000000000ZZ"
	rawGoogleAPIKey      = "AIza00000000000000000000000000000000ZZZ"
	rawAnthropicAPIKey   = "sk-ant-00000000000000000000ZZ"
	rawNPMToken          = "npm_00000000000000000000ZZ"
	rawNPMPatToken       = "npm_pat_00000000000000000000ZZ"
	rawGitLabToken       = "glpat-aBcDeFgHiJkLmNoPqRsTuVwXyZ"
	rawGCPServiceAccount = `{
  "type": "service_account",
  "project_id": "example-project",
  "private_key_id": "0000000000000000000000000000000000000000",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...EXAMPLE...END\n-----END PRIVATE KEY-----\n",
  "client_email": "svc@example-project.iam.gserviceaccount.com"
}`
)

// TestPrivateKeyRuleDetectsPEMHeader keeps a text-file key header visible without exposing its bytes in a finding.
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

// TestPrivateKeyRuleSkipsPrefixProseButFlagsRawBlocks keeps documentation
// wording out of findings without accepting actual PEM-like key blocks.
func TestPrivateKeyRuleSkipsPrefixProseButFlagsRawBlocks(t *testing.T) {
	prose := parser.Unit{
		File:   source.File{Path: "README.txt", Type: source.FileTypeText},
		Source: "The private key begins with -----BEGIN RSA PRIVATE KEY-----.\nOnly PKCS1 format (starting with \"-----BEGIN RSA PRIVATE KEY-----\") is supported.\n",
	}
	if got := (PrivateKeyRule{}).AnalyzeUnit(prose, Context{}); len(got) != 0 {
		t.Fatalf("private-key prefix prose should not flag, got %#v", got)
	}

	raw := parser.Unit{
		File:   source.File{Path: "key.pem", Type: source.FileTypeText},
		Source: "-----BEGIN RSA PRIVATE KEY-----\nredacted-test-body-that-is-secret-shaped\n-----END RSA PRIVATE KEY-----\n",
	}
	if got := (PrivateKeyRule{}).AnalyzeUnit(raw, Context{}); len(got) != 1 {
		t.Fatalf("raw private-key block should still flag, got %#v", got)
	}
}

// TestPrivateKeyRuleSkipsGoDelimiterManipulation avoids flagging code that
// strips or re-wraps caller-provided PEM data without embedding key material.
func TestPrivateKeyRuleSkipsGoDelimiterManipulation(t *testing.T) {
	unit := parseOne(t, "pem.go", `package pem

import "strings"

func clean(privateKeyPEM string) []byte {
	privateKeyPEM = strings.ReplaceAll(privateKeyPEM, "-----BEGIN PRIVATE KEY-----", "")
	return []byte("-----BEGIN PRIVATE KEY-----\n" + privateKeyPEM + "\n-----END PRIVATE KEY-----")
}
`)
	if got := (PrivateKeyRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("PEM delimiter manipulation should not flag, got %#v", got)
	}
}

// TestPrivateKeyRuleFlagsInlinePEMLiteralInHelperCall ensures a PEM-shaped literal in a strings.ReplaceAll call still gives one finding.
//
// The unit has no parsed Go syntax, so this checks the key still reports when only the source text is scanned.
// The body is built at runtime so the complete fixture never appears in this file's source.
func TestPrivateKeyRuleFlagsInlinePEMLiteralInHelperCall(t *testing.T) {
	body := strings.Repeat("A", 64)
	unit := parser.Unit{
		File:   source.File{Path: "keys.go", Type: source.FileTypeGo},
		Source: `var key = strings.ReplaceAll("-----BEGIN PRIVATE KEY-----\n` + body + `", "\r", "")` + "\n",
	}
	if got := (PrivateKeyRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
		t.Fatalf("inline PEM literal inside ReplaceAll should still flag, got %#v", got)
	}
}

// TestPrivateKeyRuleFlagsMultilinePEMLiteralInHelperCall ensures a PEM-shaped multiline raw string in strings.ReplaceAll gives one finding.
//
// The body and the raw-string backtick are assembled at runtime so the complete fixture never appears in this file's source.
func TestPrivateKeyRuleFlagsMultilinePEMLiteralInHelperCall(t *testing.T) {
	body := strings.Repeat("A", 64)
	bt := "`"
	src := "package keys\n\nimport \"strings\"\n\nvar k = strings.ReplaceAll(" + bt +
		"-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----" + bt +
		", \"\\r\", \"\")\n"
	unit := parser.Unit{File: source.File{Path: "keys.go", Type: source.FileTypeGo}, Source: src}
	if got := (PrivateKeyRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
		t.Fatalf("multiline PEM literal inside ReplaceAll should still flag, got %#v", got)
	}
}

// TestAWSAccessKeyRuleDetectsAndRedacts verifies an AKIA key id gives one finding whose message and preview omit the raw key.
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

// TestAWSAccessKeyRuleDetectsASessionToken pins the ASIA half of the shape.
//
// AWS issues temporary session credentials under that prefix over the same fixed body.
// A temporary credential must get the same finding as a long-term AKIA key.
func TestAWSAccessKeyRuleDetectsASessionToken(t *testing.T) {
	sessionToken := "ASIA" + "IOSFODNN7" + "EXAMPLE"
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "aws_access_key_id = " + sessionToken + "\n",
	}
	findings := AWSAccessKeyRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings for a session token, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], sessionToken)
}

// TestAWSAccessKeyRuleReadsAnAllXBodyAsMasked pins FAMILY-CONTRACT.md section 5 for masked keys.
//
// A key whose sixteen body characters are all X names no credential and does not report.
// A real key that merely contains a run of X still reports, because a rule that hid it would hide a live credential.
func TestAWSAccessKeyRuleReadsAnAllXBodyAsMasked(t *testing.T) {
	masked := strings.Repeat("X", 16)
	partlyMasked := "IOSFODNN" + strings.Repeat("X", 8)
	unit := parser.Unit{
		File: source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "aws_access_key_id = " + "AKIA" + masked + "\n" +
			"aws_session_key_id = " + "ASIA" + masked + "\n" +
			"aws_partly_masked_id = " + "AKIA" + partlyMasked + "\n",
	}
	findings := AWSAccessKeyRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Location == nil || findings[0].Location.Line != 3 {
		t.Fatalf("got %d findings, want exactly the partly masked key on line 3: %+v", len(findings), findings)
	}
}

// TestJWTTokenRuleDetectsAndRedacts verifies a quoted JWT gives one finding whose message and preview omit the raw token.
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

// TestConnectionStringRuleDetectsAndRedacts verifies a postgres URL with a password gives one finding that never shows the password.
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

// TestGitHubTokenRuleDetectsAndRedacts verifies a ghp_ token gives one finding whose message and preview omit the raw token.
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

// TestSlackTokenRuleDetectsAndRedacts verifies an xoxb- bot token gives one finding whose message and preview omit the raw token.
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

// TestStripeLiveKeyRuleDetectsAndRedacts verifies an sk_live_ key gives one finding whose message and preview omit the raw key.
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

// TestGoogleAPIKeyRuleDetectsAndRedacts verifies an AIza key gives one finding whose message and preview omit the raw key.
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

// TestAnthropicAPIKeyRuleDetectsAndRedacts verifies an sk-ant- key gives one finding whose message and preview omit the raw key.
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

// TestNPMTokenRuleDetectsAndRedacts verifies npm_ and npm_pat_ tokens on two lines give two findings, neither showing its raw token.
func TestNPMTokenRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "npm_token = " + rawNPMToken + "\npat = " + rawNPMPatToken + "\n",
	}
	findings := NPMTokenRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawNPMToken)
	assertNoRawSecret(t, findings[1], rawNPMPatToken)
}

// TestGitLabTokenRuleDetectsAndRedacts verifies a glpat- token gives one finding whose message and preview omit the raw token.
func TestGitLabTokenRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "gitlab_token = " + rawGitLabToken + "\n",
	}
	findings := GitLabTokenRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawGitLabToken)
}

// TestGoogleAPIKeyRuleRejectsShortPrefix asserts AIza followed by a suffix too short for a key (AIzaSyShort) gives no finding.
func TestGoogleAPIKeyRuleRejectsShortPrefix(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "google_api_key = AIzaSyShort\n",
	}
	if got := (GoogleAPIKeyRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("expected no findings for short prefix, got %#v", got)
	}
}

// TestSlackTokenRuleRejectsBarePrefix asserts a bare Slack prefix such as xoxp- with no body is not matched as a token.
func TestSlackTokenRuleRejectsBarePrefix(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "slack_token = xoxp-\n",
	}
	if got := (SlackTokenRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("expected no findings for bare prefix, got %#v", got)
	}
}

// TestNPMTokenRuleRejectsBarePrefix asserts npm_ followed by a body too short for a token (npm_short) is not matched.
func TestNPMTokenRuleRejectsBarePrefix(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "npm_token = npm_short\n",
	}
	if got := (NPMTokenRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("expected no findings for bare npm prefix, got %#v", got)
	}
}

// TestGitLabTokenRuleRejectsShortPrefix asserts glpat- followed by a body too short for a token (glpat-short) is not matched.
func TestGitLabTokenRuleRejectsShortPrefix(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "gitlab_token = glpat-short\n",
	}
	if got := (GitLabTokenRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("expected no findings for short GitLab prefix, got %#v", got)
	}
}

// TestGCPServiceAccountRuleDetectsBothMarkers asserts a service-account JSON file with both markers gives exactly one finding.
//
// The markers are the type service_account line and a PEM private-key header; the finding sits on the type line (2).
// Both stay redacted: the preview omits the type marker, the secondary preview omits the key body, and secondaryLine is 5.
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

// TestGCPServiceAccountRuleIgnoresPrivateKeyOnly asserts a PEM private key without the service-account type marker gives no GCP finding.
//
// The sensitive-data.private-key rule still fires on this input; the PrivateKeyRule tests cover that.
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

// TestGCPServiceAccountRuleLeavesNoSecToTheInlineFilter asserts the rule still reports a key whose marker line carries a nosec comment.
//
// The inline filter then suppresses and counts it (FAMILY-CONTRACT.md section 13c) instead of the rule dropping it silently.
func TestGCPServiceAccountRuleLeavesNoSecToTheInlineFilter(t *testing.T) {
	src := `{
  "type": "service_account", // #nosec -- fixture
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"
}`
	unit := parser.Unit{
		File:   source.File{Path: "fixture.json", Type: source.FileTypeText},
		Source: src,
	}
	if got := (GCPServiceAccountRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
		t.Fatalf("expected one finding for the inline filter to judge, got %#v", got)
	}
}

// TestSensitiveDetectorsAreDefaultEnabled pins which credential rules a default gruff-go analyse run uses.
//
// The map lookup that sets wantEnabled names the five rules off by default under ADR-021; the other listed rules stay on.
// A failure means a DefaultEnabled flag changed, so default scans gain or lose that rule's findings.
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
		NPMTokenRule{}.Definition(),
		GitLabTokenRule{}.Definition(),
		GCPServiceAccountRule{}.Definition(),
	} {
		// Five provider rules are off by default since precision-floor M19 (ADR-021); the rest stay on.
		wantEnabled := !map[string]bool{
			"sensitive-data.aws-access-key":      true,
			"sensitive-data.connection-string":   true,
			"sensitive-data.gcp-service-account": true,
			"sensitive-data.github-token":        true,
			"sensitive-data.google-api-key":      true,
		}[definition.ID]
		if definition.DefaultEnabled != wantEnabled {
			t.Errorf("rule %q defaultEnabled = %v, want %v", definition.ID, definition.DefaultEnabled, wantEnabled)
		}
	}
}

// TestSensitiveDetectorsAreCleanOnInnocuousInput verifies the listed credential detectors stay quiet on a plain greeting and a port number.
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
		NPMTokenRule{},
		GitLabTokenRule{},
		GCPServiceAccountRule{},
	} {
		if got := rule.AnalyzeUnit(unit, Context{}); len(got) != 0 {
			t.Errorf("rule %q produced findings on clean input: %#v", rule.Definition().ID, got)
		}
	}
}

// TestScanLinesForSecretSkipsComments asserts a connection string on a comment-only line gives no finding.
//
// It covers a line comment, a tab-indented godoc line, and one-line and multi-line block comments.
// This keeps doc snippets like format: postgres://user:password@host from looking like leaks.
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

// TestScanLinesForSecretLeavesSuppressionsToTheInlineFilter asserts a line carrying a nosec or nolint comment still reports at rule level.
//
// analysis.ApplyInlineSuppressions then applies matching directives and counts the suppressed findings (FAMILY-CONTRACT.md section 13c).
// The rule must not drop them uncounted.
func TestScanLinesForSecretLeavesSuppressionsToTheInlineFilter(t *testing.T) {
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
			if got := (ConnectionStringRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
				t.Fatalf("expected one finding for the inline filter to judge, got %#v", got)
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

// TestConnectionStringRuleStillFlagsRealLookingSecrets asserts the placeholder heuristic does not swallow production-looking credentials.
//
// Each case uses a host that is not local or a password with no placeholder marker, and must give one finding.
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

// assertNoRawSecret marks the test failed when the message or preview metadata of item contains raw, the unredacted fixture value.
//
// The test keeps running after a leak; a finding with no preview is checked on its message only.
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
