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
	// The sha256, sha384 and sha512 rows are the digest lengths the 2026-08-29 downstream report
	// actually produced. The 40-character row already covered sha1; nothing covered the lengths
	// the report complained about, so the claim that go handles them was untested.
	cases := map[string]string{
		"hex digest":  "d41d8cd98f00b204e9800998ecf8427ed41d8cd9",
		"sha256":      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"sha384":      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		"sha512":      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
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

// TestHighEntropyStringDigestsSurviveALoweredThreshold asserts the other direction of the
// contract: a content digest stays quiet even when the entropy bar is dropped below hex's
// arithmetic ceiling.
//
// This matters because the family's shared answer to digest false positives is the 4.2 bar
// itself, and a project may lower it. go does not rely on the bar alone: entropyHexPattern
// excludes all-hex tokens outright, so the guarantee holds at any threshold. That is the part
// M19 cites when deciding whether php needs the same shape guard.
func TestHighEntropyStringDigestsSurviveALoweredThreshold(t *testing.T) {
	// Construct the rule the way the registry does, with the entropy bar lowered below hex's
	// arithmetic ceiling of 4.0.
	rule := HighEntropyStringRule{MinLength: highEntropyMinLength, Entropy: 3.5}

	digests := map[string]string{
		"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"sha384": "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		"sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
	}
	for name, value := range digests {
		t.Run(name, func(t *testing.T) {
			unit := sensitiveTextUnit("x.env", "v = \""+value+"\"\n")
			if got := rule.AnalyzeUnit(unit, Context{}); len(got) != 0 {
				t.Fatalf("findings = %#v, want 0 for %s at a lowered bar", got, name)
			}
		})
	}

	// The control: a genuinely random token still fires at both bars, so the guard above is a
	// shape exclusion rather than the rule going quiet. randomSecretToken is used rather than an
	// AWS-shaped key, because the entropy rule defers to the provider rules that own such a
	// prefix and would report nothing for a reason unrelated to the threshold.
	unit := sensitiveTextUnit("x.env", "v = \""+randomSecretToken+"\"\n")
	if got := rule.AnalyzeUnit(unit, Context{}); len(got) != 1 {
		t.Fatalf("findings = %#v, want 1 at the lowered bar", got)
	}
	if got := (HighEntropyStringRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
		t.Fatalf("findings = %#v, want 1 at the default bar", got)
	}
}

// TestHighEntropyStringContract pins the four axes the operator ratified on 2026-09-02 as one
// contract for all five ports, plus the threshold pair that proves both bounds are honoured.
//
// Every axis is asserted because the defect this replaces was one rule id carrying five
// different contracts: go alone shipped opt-in at 20 and 4.5 while php and rs shipped 32 and
// 4.2, and three ports could not honour a configured entropy at all.
func TestHighEntropyStringContract(t *testing.T) {
	definition := HighEntropyStringRule{}.Definition()

	if definition.Severity != finding.SeverityWarning {
		t.Errorf("severity = %q, want warning", definition.Severity)
	}
	if definition.Confidence != finding.ConfidenceMedium {
		t.Errorf("confidence = %q, want medium", definition.Confidence)
	}
	if !definition.DefaultEnabled {
		t.Error("DefaultEnabled = false, want true: a secret scanner that is off by default finds no secrets")
	}
	if got := definition.Thresholds["minLength"]; got != 32 {
		t.Errorf("minLength = %v, want 32", got)
	}
	if got := definition.Thresholds["entropy"]; got != 4.2 {
		t.Errorf("entropy = %v, want 4.2", got)
	}

	// Both thresholds must be honoured, not merely published. A token below the length bar is
	// silent at the default and reports once the bar is lowered to admit it.
	short := "aB3dE6gH9jK2mN5pQ8sT1vW4xY7zC0eF"[:24]
	unit := sensitiveTextUnit("x.env", "v = \""+short+"\"\n")
	if got := (HighEntropyStringRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("findings = %#v, want 0 below the ratified minLength", got)
	}
	admitted := HighEntropyStringRule{MinLength: 20, Entropy: highEntropyMinBitsPerChar}
	if got := admitted.AnalyzeUnit(unit, Context{}); len(got) != 1 {
		t.Fatalf("findings = %#v, want 1 once minLength admits the token", got)
	}
}
