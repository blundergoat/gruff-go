// Package report tests sensitive preview safety from raw source through every
// persisted and rendered artifact surface.
package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/baseline"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestSensitiveRedactionPolicyAcrossRealArtifacts exercises empty,
// nonmatching, and matching allowlists from raw source through every renderer.
func TestSensitiveRedactionPolicyAcrossRealArtifacts(t *testing.T) {
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
			fixture := sensitiveArtifactFixtureData()
			reportData := analyzeSensitiveArtifactFixture(t, fixture.source, state.allowlist)
			assertSensitiveArtifactMarkers(t, reportData.Findings, state.allowed)
			artifacts := renderSensitiveArtifacts(t, reportData)
			for name, artifact := range artifacts {
				t.Run(name, func(t *testing.T) {
					for index, forbidden := range fixture.forbidden {
						if strings.Contains(artifact, forbidden) {
							t.Fatalf("artifact contains reusable fragment index %d", index)
						}
					}
				})
			}
		})
	}
}

// sensitiveArtifactFixture holds runtime-built source plus leak substrings.
type sensitiveArtifactFixture struct {
	source    string
	forbidden []string
}

// sensitiveArtifactFixtureData builds one file that trips all 16 sensitive
// rules without storing a complete reusable credential in this test source.
func sensitiveArtifactFixtureData() sensitiveArtifactFixture {
	generic := "abcabcabcabc-" + "defdefdefdef-QZUX"
	privateKey := "-----BEGIN " + "RSA PRIVATE KEY-----"
	keyBody := "MIIE" + strings.Repeat("K7", 32)
	aws := "AKIA" + "Q7W9E2R4T6Y8U1I3"
	jwt := "eyJ" + strings.Repeat("A7", 5) + "." + strings.Repeat("B8", 6) + "." + strings.Repeat("C9", 7)
	password := "db-pass-" + strings.Repeat("R8", 8)
	connection := "postgres" + "://app:" + password + "@db.internal:5432/orders"
	github := "ghp_" + strings.Repeat("G7h9", 9)
	slack := "xoxb-" + strings.Repeat("1", 12) + "-" + strings.Repeat("2", 12) + "-" + strings.Repeat("S8", 10)
	stripe := "sk_live_" + strings.Repeat("T6", 12)
	google := "AIza" + strings.Repeat("U5", 17) + "Z"
	anthropic := "sk-ant-" + strings.Repeat("V4", 10)
	npm := "npm_" + strings.Repeat("N3", 10)
	gitlab := "glpat-" + strings.Repeat("L2", 10)
	entropy := "Zx9KqW2mB7vN4pL8dT3r" + "YcF1gHjS0aQwE4tU7iO5n"
	email := "audit.person" + "@" + "realcorp.co"
	phone := "+1 (415) 867-9026"
	card := "4000 0000 0000 0002"
	ssn := "536-90-9821"
	medicare := "1EG4TE5MK73"
	mrn := "8642057"

	lines := []string{
		"auth_token = \"" + generic + "\"",
		"private = \"" + privateKey + "\\n" + keyBody + "\"",
		"aws = \"" + aws + "\"", "jwt = \"" + jwt + "\"",
		"database = \"" + connection + "\"", "github = \"" + github + "\"",
		"slack = \"" + slack + "\"", "stripe = \"" + stripe + "\"",
		"google = \"" + google + "\"", "anthropic = \"" + anthropic + "\"",
		"npm = \"" + npm + "\"", "gitlab = \"" + gitlab + "\"",
		"\"type\": \"service_account\"", "\"private_key\": \"" + privateKey + "\"",
		"entropy = \"" + entropy + "\"", "email = \"" + email + "\"",
		"phone = \"" + phone + "\"", "card = \"" + card + "\"",
		"ssn = \"" + ssn + "\"", "mbi = \"" + medicare + "\"",
		"record = \"MRN: " + mrn + "\"",
	}
	forbidden := []string{privateKey, privateKey[:6]}
	secrets := [][2]string{
		{generic, generic}, {aws, aws[4:]}, {jwt, jwt}, {password, password},
		{github, github[4:]}, {slack, slack[5:]}, {stripe, stripe[8:]},
		{google, google[4:]}, {anthropic, anthropic[7:]}, {npm, npm[4:]},
		{gitlab, gitlab[6:]}, {entropy, entropy}, {email, email}, {phone, phone},
		{card, card}, {ssn, ssn}, {medicare, medicare}, {mrn, mrn}, {keyBody, keyBody},
	}
	for _, secret := range secrets {
		forbidden = append(forbidden, sensitiveArtifactFragments(secret[0], secret[1])...)
	}
	return sensitiveArtifactFixture{source: strings.Join(lines, "\n") + "\n", forbidden: forbidden}
}

// sensitiveArtifactFragments returns the raw value and legacy preview chunks.
func sensitiveArtifactFragments(raw, payload string) []string {
	return []string{raw, payload, payload[:6], payload[len(payload)-4:]}
}

// analyzeSensitiveArtifactFixture scans the runtime fixture with all three
// opt-in sensitive detectors enabled.
func analyzeSensitiveArtifactFixture(t *testing.T, sourceBody string, allowlist []string) analysis.Report {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "secrets", "all.env")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(sourceBody), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := rule.DefaultsConfigured(rule.Config{
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
	reportData, err := analysis.Analyze(analysis.Options{
		Root: root, Paths: []string{"secrets/all.env"}, Format: "json",
		FailOn: finding.FailThresholdNone, Registry: registry,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reportData
}

// assertSensitiveArtifactMarkers checks route coverage and exact marker values.
func assertSensitiveArtifactMarkers(t *testing.T, findings []finding.Finding, allowed bool) {
	t.Helper()
	wantRules := map[string]bool{
		"sensitive-data.secret-pattern": false, "sensitive-data.private-key": false,
		"sensitive-data.aws-access-key": false, "sensitive-data.jwt-token": false,
		"sensitive-data.connection-string": false, "sensitive-data.github-token": false,
		"sensitive-data.slack-token": false, "sensitive-data.stripe-key": false,
		"sensitive-data.google-api-key": false, "sensitive-data.anthropic-api-key": false,
		"sensitive-data.npm-token": false, "sensitive-data.gitlab-token": false,
		"sensitive-data.gcp-service-account": false, "sensitive-data.high-entropy-string": false,
		"sensitive-data.pii-pattern": false, "sensitive-data.phi-pattern": false,
	}
	for _, item := range findings {
		if _, tracked := wantRules[item.RuleID]; !tracked {
			continue
		}
		wantRules[item.RuleID] = true
		want := "[redacted]"
		if allowed {
			want = sensitiveArtifactAllowedMarker(item)
		}
		if got, _ := item.Metadata["preview"].(string); got != want {
			t.Fatalf("%s preview does not match approved marker", item.RuleID)
		}
		if item.RuleID == "sensitive-data.gcp-service-account" {
			secondaryWant := "[redacted]"
			if allowed {
				secondaryWant = "[redacted:private-key]"
			}
			if got, _ := item.Metadata["secondaryPreview"].(string); got != secondaryWant {
				t.Fatal("GCP secondary preview does not match approved marker")
			}
		}
	}
	for ruleID, found := range wantRules {
		if !found {
			t.Fatalf("fixture did not exercise %s", ruleID)
		}
	}
}

// sensitiveArtifactAllowedMarker maps rule/category metadata to the approved
// matching-path marker vocabulary.
func sensitiveArtifactAllowedMarker(item finding.Finding) string {
	markers := map[string]string{
		"sensitive-data.secret-pattern": "[redacted]", "sensitive-data.private-key": "[redacted:private-key]",
		"sensitive-data.aws-access-key": "[redacted:aws-access-key]", "sensitive-data.jwt-token": "[redacted:jwt]",
		"sensitive-data.connection-string": "[redacted:connection-string:postgres]", "sensitive-data.github-token": "[redacted:github-token]",
		"sensitive-data.slack-token": "[redacted:slack-token]", "sensitive-data.stripe-key": "[redacted:stripe-live-key]",
		"sensitive-data.google-api-key": "[redacted:google-api-key]", "sensitive-data.anthropic-api-key": "[redacted:anthropic-api-key]",
		"sensitive-data.npm-token": "[redacted:npm-token]", "sensitive-data.gitlab-token": "[redacted:gitlab-token]",
		"sensitive-data.gcp-service-account": "[redacted:gcp-service-account]", "sensitive-data.high-entropy-string": "[redacted]",
	}
	if marker, ok := markers[item.RuleID]; ok {
		return marker
	}
	if category, _ := item.Metadata["category"].(string); category != "" {
		return "[redacted:" + category + "]"
	}
	return "[redacted]"
}

// renderSensitiveArtifacts serializes every report/baseline/dashboard surface.
func renderSensitiveArtifacts(t *testing.T, reportData analysis.Report) map[string]string {
	t.Helper()
	artifacts := map[string]string{}
	findingJSON, err := json.Marshal(reportData.Findings)
	if err != nil {
		t.Fatal(err)
	}
	artifacts["analysis-findings"] = string(findingJSON)
	baselineJSON, err := baseline.Marshal(baseline.FromFindings(reportData.Findings))
	if err != nil {
		t.Fatal(err)
	}
	artifacts["baseline"] = string(baselineJSON)
	formats := []struct {
		name string
		emit func(*bytes.Buffer) error
	}{
		{name: "text", emit: func(buf *bytes.Buffer) error { return WriteText(buf, reportData) }},
		{name: "json", emit: func(buf *bytes.Buffer) error { return WriteJSON(buf, reportData) }},
		{name: "summary-json", emit: func(buf *bytes.Buffer) error { return WriteSummaryJSON(buf, reportData) }},
		{name: "sarif", emit: func(buf *bytes.Buffer) error { return WriteSARIF(buf, reportData) }},
		{name: "github", emit: func(buf *bytes.Buffer) error { return WriteGitHub(buf, reportData) }},
		{name: "html", emit: func(buf *bytes.Buffer) error { return WriteHTML(buf, reportData, HTMLOptions{Interactive: true}) }},
		{name: "markdown", emit: func(buf *bytes.Buffer) error { return WriteMarkdown(buf, reportData) }},
	}
	for _, format := range formats {
		var buf bytes.Buffer
		if err := format.emit(&buf); err != nil {
			t.Fatalf("emit %s: %v", format.name, err)
		}
		artifacts[format.name] = buf.String()
	}
	artifacts["dashboard-html"] = InjectScanMetadata(artifacts["html"], ScanMetadata{
		ExitCode: reportData.Summary.ExitCode, DurationMs: 12,
		ProjectRoot: reportData.Run.WorkingDirectory, Command: "gruff-go analyse secrets/all.env",
	})
	return artifacts
}
