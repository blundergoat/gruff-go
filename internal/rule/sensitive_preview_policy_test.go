// Package rule tests the deny-by-default preview policy across every
// sensitive-data detector route and category.
package rule

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// sensitivePreviewFixture describes one detector/category output without
// storing a reusable credential literal contiguously in this source file.
type sensitivePreviewFixture struct {
	name            string
	ruleID          string
	path            string
	source          string
	category        string
	secret          string
	allowedPreview  string
	secondarySecret string
	secondary       string
}

// TestSensitivePreviewPolicyMatrix pins empty, nonmatching, and matching path
// policy for every sensitive-data rule plus every PII/PHI category.
func TestSensitivePreviewPolicyMatrix(t *testing.T) {
	states := []struct {
		name      string
		allowlist []string
		allowed   bool
	}{
		{name: "empty"},
		{name: "nonmatching", allowlist: []string{"other/**"}},
		{name: "matching", allowlist: []string{"secrets/**"}, allowed: true},
	}

	for _, state := range states {
		t.Run(state.name, func(t *testing.T) {
			registry := sensitivePreviewRegistry(t, state.allowlist)
			for _, fixture := range sensitivePreviewFixtures() {
				t.Run(fixture.name, func(t *testing.T) {
					findings := registry.Analyze([]parser.Unit{sensitivePreviewUnit(fixture)}, Context{})
					item, ok := sensitivePreviewFinding(findings, fixture.ruleID, fixture.category)
					if !ok {
						t.Fatalf("missing %s finding for category %q", fixture.ruleID, fixture.category)
					}
					want := "[redacted]"
					if state.allowed {
						want = fixture.allowedPreview
					}
					if got, _ := item.Metadata["preview"].(string); got != want {
						t.Fatalf("preview does not match the approved marker for %s policy", state.name)
					}
					if fixture.secondary != "" {
						secondaryWant := "[redacted]"
						if state.allowed {
							secondaryWant = fixture.secondary
						}
						if got, _ := item.Metadata["secondaryPreview"].(string); got != secondaryWant {
							t.Fatalf("secondary preview does not match the approved marker for %s policy", state.name)
						}
					}
					assertSensitivePreviewHasNoReusableBytes(t, item, fixture.secret, fixture.secondarySecret)
				})
			}
		})
	}
}

// sensitivePreviewRegistry enables the three opt-in sensitive detectors while
// applying one project preview allowlist to the complete default rule family.
func sensitivePreviewRegistry(t *testing.T, allowlist []string) Registry {
	t.Helper()
	registry, err := DefaultsConfigured(Config{
		Enabled: map[string]bool{
			"sensitive-data.high-entropy-string": true,
			"sensitive-data.pii-pattern":         true,
			"sensitive-data.phi-pattern":         true,
		},
		SensitiveDataPreviewAllowlist: allowlist,
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

// sensitivePreviewUnit converts a fixture into the text unit used by every
// line-oriented sensitive detector.
func sensitivePreviewUnit(fixture sensitivePreviewFixture) parser.Unit {
	return parser.Unit{
		File:   source.File{Path: fixture.path, Type: source.FileTypeText},
		Source: fixture.source,
	}
}

// sensitivePreviewFinding selects a rule/category pair from a registry run.
func sensitivePreviewFinding(items []finding.Finding, ruleID, category string) (finding.Finding, bool) {
	for _, item := range items {
		if item.RuleID != ruleID {
			continue
		}
		if category != "" && item.Metadata["category"] != category {
			continue
		}
		return item, true
	}
	return finding.Finding{}, false
}

// assertSensitivePreviewHasNoReusableBytes rejects complete values and the
// legacy first-six/last-four fragments without printing those bytes on failure.
func assertSensitivePreviewHasNoReusableBytes(t *testing.T, item finding.Finding, secrets ...string) {
	t.Helper()
	payload, err := json.Marshal(item.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	for secretIndex, secret := range secrets {
		if secret == "" {
			continue
		}
		for fragmentIndex, forbidden := range sensitiveReusableFragments(secret) {
			if strings.Contains(string(payload), forbidden) {
				t.Fatalf("finding metadata contains reusable fragment %d for secret %d", fragmentIndex, secretIndex)
			}
		}
	}
}

// sensitiveReusableFragments returns the whole value and the fragments exposed
// by the legacy redact helper.
func sensitiveReusableFragments(secret string) []string {
	fragments := []string{secret}
	if len(secret) >= 6 {
		fragments = append(fragments, secret[:6])
	}
	if len(secret) >= 4 {
		fragments = append(fragments, secret[len(secret)-4:])
	}
	return fragments
}

// sensitivePreviewFixtures inventories all 16 rules and expands the PII/PHI
// routes so each dynamic category has an exact approved marker.
func sensitivePreviewFixtures() []sensitivePreviewFixture {
	generic := "generic-" + strings.Repeat("Q7", 10)
	privateKey := "-----BEGIN " + "RSA PRIVATE KEY-----"
	aws := "AKIA" + strings.Repeat("Q", 16)
	jwt := "eyJ" + strings.Repeat("A", 10) + "." + strings.Repeat("B", 12) + "." + strings.Repeat("C", 14)
	password := "db-pass-" + strings.Repeat("R8", 8)
	connection := "postgres" + "://app:" + password + "@db.internal:5432/orders"
	github := "ghp_" + strings.Repeat("G", 36)
	slack := "xoxb-" + strings.Repeat("1", 12) + "-" + strings.Repeat("2", 12) + "-" + strings.Repeat("S", 20)
	stripe := "sk_live_" + strings.Repeat("T", 24)
	google := "AIza" + strings.Repeat("U", 35)
	anthropic := "sk-ant-" + strings.Repeat("V", 20)
	npm := "npm_" + strings.Repeat("N", 20)
	gitlab := "glpat-" + strings.Repeat("L", 20)
	entropy := "Zx9KqW2mB7vN4pL8dT3r" + "YcF1gHjS0aQwE4tU7iO5n"
	email := "audit.person" + "@" + "realcorp.co"
	phone := "+1 (415) 867-5309"
	card := "4242 4242 4242 4242"
	ssn := "536-90-4399"
	medicare := "1EG4TE5MK73"
	mrn := "4827193"

	return []sensitivePreviewFixture{
		{name: "generic", ruleID: "sensitive-data.secret-pattern", path: "secrets/generic.env", source: "auth_token = \"" + generic + "\"\n", secret: generic, allowedPreview: "[redacted]"},
		{name: "private-key", ruleID: "sensitive-data.private-key", path: "secrets/key.env", source: "key = \"" + privateKey + "\"\n", secret: privateKey, allowedPreview: "[redacted:private-key]"},
		{name: "aws", ruleID: "sensitive-data.aws-access-key", path: "secrets/aws.env", source: "value = \"" + aws + "\"\n", secret: aws, allowedPreview: "[redacted:aws-access-key]"},
		{name: "jwt", ruleID: "sensitive-data.jwt-token", path: "secrets/jwt.env", source: "value = \"" + jwt + "\"\n", secret: jwt, allowedPreview: "[redacted:jwt]"},
		{name: "connection", ruleID: "sensitive-data.connection-string", path: "secrets/db.env", source: "value = \"" + connection + "\"\n", secret: password, allowedPreview: "[redacted:connection-string:postgres]"},
		{name: "github", ruleID: "sensitive-data.github-token", path: "secrets/github.env", source: "value = \"" + github + "\"\n", secret: github, allowedPreview: "[redacted:github-token]"},
		{name: "slack", ruleID: "sensitive-data.slack-token", path: "secrets/slack.env", source: "value = \"" + slack + "\"\n", secret: slack, allowedPreview: "[redacted:slack-token]"},
		{name: "stripe", ruleID: "sensitive-data.stripe-key", path: "secrets/stripe.env", source: "value = \"" + stripe + "\"\n", secret: stripe, allowedPreview: "[redacted:stripe-live-key]"},
		{name: "google", ruleID: "sensitive-data.google-api-key", path: "secrets/google.env", source: "value = \"" + google + "\"\n", secret: google, allowedPreview: "[redacted:google-api-key]"},
		{name: "anthropic", ruleID: "sensitive-data.anthropic-api-key", path: "secrets/anthropic.env", source: "value = \"" + anthropic + "\"\n", secret: anthropic, allowedPreview: "[redacted:anthropic-api-key]"},
		{name: "npm", ruleID: "sensitive-data.npm-token", path: "secrets/npm.env", source: "value = \"" + npm + "\"\n", secret: npm, allowedPreview: "[redacted:npm-token]"},
		{name: "gitlab", ruleID: "sensitive-data.gitlab-token", path: "secrets/gitlab.env", source: "value = \"" + gitlab + "\"\n", secret: gitlab, allowedPreview: "[redacted:gitlab-token]"},
		{name: "gcp", ruleID: "sensitive-data.gcp-service-account", path: "secrets/gcp.json", source: "{\n  \"type\": \"service_account\",\n  \"private_key\": \"" + privateKey + "\"\n}\n", secret: "\"type\": \"service_account\"", allowedPreview: "[redacted:gcp-service-account]", secondarySecret: privateKey, secondary: "[redacted:private-key]"},
		{name: "entropy", ruleID: "sensitive-data.high-entropy-string", path: "secrets/entropy.env", source: "value = \"" + entropy + "\"\n", secret: entropy, allowedPreview: "[redacted]"},
		{name: "email", ruleID: "sensitive-data.pii-pattern", category: "email", path: "secrets/pii-email.env", source: "value = \"" + email + "\"\n", secret: email, allowedPreview: "[redacted:email]"},
		{name: "phone", ruleID: "sensitive-data.pii-pattern", category: "phone", path: "secrets/pii-phone.env", source: "value = \"" + phone + "\"\n", secret: phone, allowedPreview: "[redacted:phone]"},
		{name: "payment-card", ruleID: "sensitive-data.pii-pattern", category: "payment-card", path: "secrets/pii-card.env", source: "value = \"" + card + "\"\n", secret: card, allowedPreview: "[redacted:payment-card]"},
		{name: "ssn", ruleID: "sensitive-data.phi-pattern", category: "ssn", path: "secrets/phi-ssn.env", source: "value = \"" + ssn + "\"\n", secret: ssn, allowedPreview: "[redacted:ssn]"},
		{name: "medicare", ruleID: "sensitive-data.phi-pattern", category: "medicare", path: "secrets/phi-medicare.env", source: "value = \"" + medicare + "\"\n", secret: medicare, allowedPreview: "[redacted:medicare]"},
		{name: "mrn", ruleID: "sensitive-data.phi-pattern", category: "mrn", path: "secrets/phi-mrn.env", source: "record = \"MRN: " + mrn + "\"\n", secret: mrn, allowedPreview: "[redacted:mrn]"},
	}
}
