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

// TestDocumentedSamplesAreNotReported verifies AWS's example key id, the jwt.io token and a published test card never report.
//
// A key of the same shape and a value that merely contains the sample still report (FAMILY-CONTRACT.md section 5).
// Every value is assembled from parts, so this file holds none of them whole.
func TestDocumentedSamplesAreNotReported(t *testing.T) {
	example := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	live := "AKIA" + "Q7R2M8N4" + "P6T9V1X3"
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	card := "4111" + " 1111 1111 " + "1111"
	cases := []struct {
		name    string
		rule    UnitRule
		source  string
		reports int
	}{
		{name: "aws example", rule: AWSAccessKeyRule{}, source: "key = " + example + "\n", reports: 0},
		{name: "aws live-shaped", rule: AWSAccessKeyRule{}, source: "key = " + live + "\n", reports: 1},
		{name: "jwt sample", rule: JWTTokenRule{}, source: "token = " + jwt + "\n", reports: 0},
		{name: "jwt sample with a suffix", rule: JWTTokenRule{}, source: "token = " + jwt + "x\n", reports: 1},
		{name: "test card", rule: PIIPatternRule{}, source: "card = " + card + "\n", reports: 0},
	}
	for _, testCase := range cases {
		unit := sensitiveTextUnit("x.env", testCase.source)
		findings := testCase.rule.AnalyzeUnit(unit, Context{})
		if len(findings) != testCase.reports {
			t.Fatalf("%s: findings = %d, want %d", testCase.name, len(findings), testCase.reports)
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
		{"card", "card = \"4539 5787 6362 1486\"\n", "4539 5787 6362 1486"},
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

// TestDocumentedCardDoesNotHideARealCard verifies a published test card first on a line leaves the real card after it reported.
func TestDocumentedCardDoesNotHideARealCard(t *testing.T) {
	source := "cards = " + "4111" + " 1111 1111 " + "1111" + " / " + "4539 5787 " + "6362 1486\n"
	findings := PIIPatternRule{}.AnalyzeUnit(sensitiveTextUnit("x.env", source), Context{})
	if len(findings) != 1 || findings[0].Metadata["category"] != "payment-card" {
		t.Fatalf("findings = %+v, want one payment-card finding", findings)
	}
}
