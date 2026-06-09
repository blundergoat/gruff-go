// Package rule defines gruff-go's rule registry and analysers.
// This file tests the M30 sensitive-data expansion detectors (entropy, PII, PHI):
// that they fire on real-looking values, stay quiet on placeholders and the
// shapes they must defer on, and never leak a raw value into a preview.
package rule

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// randomSecretToken is a 41-char base64url string with no provider prefix - a
// stand-in for a rotated or vendor-less credential. Its mixed alphabet pushes
// Shannon entropy well above the 4.5 bits/char default, so the entropy tests key
// on the detector's logic rather than on a borderline score.
const randomSecretToken = "Zx9KqW2mB7vN4pL8dT3rYcF1gHjS0aQwE4tU7iO5n"

// sensitiveTextUnit builds a text-file unit from a source body. The expansion
// detectors are line scanners over unit.Source, so a text unit (no Go parse
// needed) is the most direct fixture and matches the style of sensitive_test.go.
func sensitiveTextUnit(path, body string) parser.Unit {
	return parser.Unit{
		File:   source.File{Path: path, Type: source.FileTypeText},
		Source: body,
	}
}

// assertNoRawLeak fails when any finding's preview metadata contains the raw
// value. Every M30 detector must emit only a redacted preview, so the positive
// tests run this after asserting a hit.
func assertNoRawLeak(t *testing.T, findings []finding.Finding, raw string) {
	t.Helper()
	for _, f := range findings {
		preview, _ := f.Metadata["preview"].(string)
		if preview != "" && strings.Contains(preview, raw) {
			t.Fatalf("preview %q leaked raw value %q", preview, raw)
		}
	}
}

// TestHighEntropyStringFlagsRandomToken verifies the entropy detector fires on a
// long random token and redacts it.
func TestHighEntropyStringFlagsRandomToken(t *testing.T) {
	unit := sensitiveTextUnit("x.env", "secret = \""+randomSecretToken+"\"\n")
	findings := HighEntropyStringRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want 1", findings)
	}
	assertNoRawLeak(t, findings, randomSecretToken)
}

// TestHighEntropyStringSkipsNonSecretShapes verifies the detector stays quiet on
// the identifier and structural shapes that look random but are not secrets.
func TestHighEntropyStringSkipsNonSecretShapes(t *testing.T) {
	cases := map[string]string{
		"hex digest":  "d41d8cd98f00b204e9800998ecf8427ed41d8cd9",
		"uuid":        "550e8400-e29b-41d4-a716-446655440000",
		"sri hash":    "sha256-47DEQpj8HBSaTImW1OD2tz6O5Kz9SzaQ1bln",
		"import path": "github.com/blundergoat/gruff-go/internal/rule/sensitive",
		"short token": "abc123def456",
		"repetitive":  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			unit := sensitiveTextUnit("x.env", "v = \""+value+"\"\n")
			if got := (HighEntropyStringRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
				t.Fatalf("findings = %#v, want 0 for %s", got, name)
			}
		})
	}
}

// TestHighEntropyStringDefersToProviderRules verifies precedence: a token a
// provider-specific rule already owns (here a high-entropy GitHub token) is not
// also reported as a generic high-entropy string, so one secret yields one finding.
func TestHighEntropyStringDefersToProviderRules(t *testing.T) {
	// randomSecretToken is 41 alphanumeric chars, clearing githubTokenPattern's
	// 36-char body floor so the provider rule claims it.
	token := "ghp_" + randomSecretToken
	unit := sensitiveTextUnit("x.env", "token = \""+token+"\"\n")
	if got := (HighEntropyStringRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("entropy findings = %#v, want 0 (GitHubTokenRule owns this token)", got)
	}
	if got := (GitHubTokenRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
		t.Fatalf("github findings = %#v, want 1 (provider rule should own it)", got)
	}
}

// TestHighEntropyThresholdIsConfigurable verifies the minLength knob takes effect
// both as a struct field and when wired through DefaultsConfigured: raising
// minLength above the token length silences the finding.
func TestHighEntropyThresholdIsConfigurable(t *testing.T) {
	unit := sensitiveTextUnit("x.env", "secret = \""+randomSecretToken+"\"\n")
	if got := (HighEntropyStringRule{MinLength: 200}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("findings = %#v, want 0 with minLength 200", got)
	}
	registry, err := DefaultsConfigured(Config{
		Enabled: map[string]bool{"sensitive-data.high-entropy-string": true},
		Thresholds: map[string]map[string]float64{
			"sensitive-data.high-entropy-string": {"minLength": 200},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range registry.Analyze([]parser.Unit{unit}, Context{}) {
		if f.RuleID == "sensitive-data.high-entropy-string" {
			t.Fatalf("entropy finding fired despite configured minLength 200: %#v", f)
		}
	}
}

// TestPIIPatternFlagsRealValues verifies email, punctuated phone, and a Luhn-valid
// payment card are each detected and redacted.
func TestPIIPatternFlagsRealValues(t *testing.T) {
	cases := []struct {
		name string
		body string
		raw  string
	}{
		{"email", "contact = \"jane.roe@acmecorp.co\"\n", "jane.roe@acmecorp.co"},
		{"phone", "phone = \"+1 (415) 555-0137\"\n", "(415) 555-0137"},
		{"card", "card = \"4242 4242 4242 4242\"\n", "4242 4242 4242 4242"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := PIIPatternRule{}.AnalyzeUnit(sensitiveTextUnit("x.env", tc.body), Context{})
			if len(findings) != 1 {
				t.Fatalf("findings = %#v, want 1", findings)
			}
			assertNoRawLeak(t, findings, tc.raw)
		})
	}
}

// TestPIIPatternSkipsPlaceholdersAndBareNumbers verifies the FP guards: example
// domains, generic local-parts, a bare phone-length digit run without phone
// punctuation, and a Luhn-invalid card-shaped number all stay quiet.
func TestPIIPatternSkipsPlaceholdersAndBareNumbers(t *testing.T) {
	cases := map[string]string{
		"example domain": "e = \"you@example.com\"\n",
		"generic local":  "e = \"user@acmecorp.co\"\n",
		"bare phone run": "n = \"4155550137\"\n",
		"luhn-invalid":   "c = \"1234 5678 9012 3456\"\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := (PIIPatternRule{}).AnalyzeUnit(sensitiveTextUnit("x.env", body), Context{}); len(got) != 0 {
				t.Fatalf("findings = %#v, want 0 for %s", got, name)
			}
		})
	}
}

// TestPHIPatternFlagsHealthIdentifiers verifies a valid SSN, a Medicare MBI, and a
// label-anchored MRN are each detected and redacted.
func TestPHIPatternFlagsHealthIdentifiers(t *testing.T) {
	cases := []struct {
		name string
		body string
		raw  string
	}{
		{"ssn", "ssn = \"536-90-4399\"\n", "536-90-4399"},
		{"medicare", "mbi = \"1EG4TE5MK73\"\n", "1EG4TE5MK73"},
		{"mrn", "record = \"MRN: 4827193\"\n", "4827193"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := PHIPatternRule{}.AnalyzeUnit(sensitiveTextUnit("x.env", tc.body), Context{})
			if len(findings) != 1 {
				t.Fatalf("findings = %#v, want 1", findings)
			}
			assertNoRawLeak(t, findings, tc.raw)
		})
	}
}

// TestPHIPatternSkipsInvalidAndPlaceholderSSNs verifies the SSN FP guards:
// unissuable number spaces (000/666/9xx areas, 00 group, 0000 serial) and a
// well-known placeholder SSN are not flagged.
func TestPHIPatternSkipsInvalidAndPlaceholderSSNs(t *testing.T) {
	for _, ssn := range []string{"000-12-3456", "666-12-3456", "900-12-3456", "536-00-4399", "536-90-0000", "123-45-6789"} {
		t.Run(ssn, func(t *testing.T) {
			if got := (PHIPatternRule{}).AnalyzeUnit(sensitiveTextUnit("x.env", "s = \""+ssn+"\"\n"), Context{}); len(got) != 0 {
				t.Fatalf("findings = %#v, want 0 for %s", got, ssn)
			}
		})
	}
}

// TestPHIOwnsSSNNotPII documents the PII/PHI precedence: a Social Security number
// is reported by the PHI rule only, never the PII rule, so an SSN is not counted
// twice when both rules are enabled.
func TestPHIOwnsSSNNotPII(t *testing.T) {
	unit := sensitiveTextUnit("x.env", "s = \"536-90-4399\"\n")
	if got := (PIIPatternRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("PII findings = %#v, want 0 (SSN belongs to PHI)", got)
	}
	if got := (PHIPatternRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
		t.Fatalf("PHI findings = %#v, want 1", got)
	}
}
