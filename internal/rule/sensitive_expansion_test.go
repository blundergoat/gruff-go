// Package rule defines gruff-go's rule registry and analysers.
//
// This file tests the PII and PHI sensitive-data detectors and the documented-sample controls on config and text files.
// The tests check positive matches, the email, phone, card and SSN false-positive guards, documented samples, and redacted previews.
package rule

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// randomSecretToken is a 41-char base64url string with no provider prefix, a stand-in for a rotated or vendor-less credential.
//
// No test in this file uses it; its mixed alphabet gives it high Shannon entropy.
const randomSecretToken = "Zx9KqW2mB7vN4pL8dT3rYcF1gHjS0aQwE4tU7iO5n"

// sensitiveTextUnit builds a text-file unit at path whose source is body, so a test can run a line-scanning detector with no Go parse.
//
// It returns a parser.Unit typed as a text file, matching the fixture style of sensitive_test.go.
func sensitiveTextUnit(path, body string) parser.Unit {
	return parser.Unit{
		File:   source.File{Path: path, Type: source.FileTypeText},
		Source: body,
	}
}

// assertNoRawLeak fails the test when any of findings has a preview in its metadata that contains raw, the unredacted fixture value.
//
// Each PII and PHI detector must emit only a redacted preview, so positive tests call this after a hit; a finding with no preview passes.
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

// TestPIIPatternFlagsRealValues checks that each email, punctuated phone, and Luhn-valid card fixture yields one finding.
// Any non-empty string preview must omit the corresponding raw fixture value.
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

// TestPIIPatternSkipsPlaceholdersAndBareNumbers verifies the PII false-positive guards stay quiet.
//
// It covers example domains, generic local-parts, a phone-length digit run with no phone punctuation, and a Luhn-invalid card number.
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

// TestPHIPatternFlagsHealthIdentifiers checks that each SSN, Medicare MBI, and label-anchored MRN fixture yields one finding.
// Any non-empty string preview must omit the corresponding raw fixture value.
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

// TestPHIPatternSkipsInvalidAndPlaceholderSSNs verifies the SSN false-positive guards stay quiet.
//
// It covers unissuable number spaces (000, 666 and 9xx areas, a 00 group, a 0000 serial) and the well-known placeholder 123-45-6789.
func TestPHIPatternSkipsInvalidAndPlaceholderSSNs(t *testing.T) {
	for _, ssn := range []string{"000-12-3456", "666-12-3456", "900-12-3456", "536-00-4399", "536-90-0000", "123-45-6789"} {
		t.Run(ssn, func(t *testing.T) {
			if got := (PHIPatternRule{}).AnalyzeUnit(sensitiveTextUnit("x.env", "s = \""+ssn+"\"\n"), Context{}); len(got) != 0 {
				t.Fatalf("findings = %#v, want 0 for %s", got, ssn)
			}
		})
	}
}

// TestPHIOwnsSSNNotPII pins the PII/PHI precedence: a Social Security number is reported by the PHI rule only, never the PII rule.
//
// Separate direct calls yield zero PII findings and one PHI finding for the same SSN fixture.
func TestPHIOwnsSSNNotPII(t *testing.T) {
	unit := sensitiveTextUnit("x.env", "s = \"536-90-4399\"\n")
	if got := (PIIPatternRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("PII findings = %#v, want 0 (SSN belongs to PHI)", got)
	}
	if got := (PHIPatternRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
		t.Fatalf("PHI findings = %#v, want 1", got)
	}
}

// TestDocumentedCardDoesNotHideARealCard checks for exactly one payment-card finding on a line with a test card followed by another card.
func TestDocumentedCardDoesNotHideARealCard(t *testing.T) {
	source := "cards = " + "4111" + " 1111 1111 " + "1111" + " / " + "4539 5787 " + "6362 1486\n"
	findings := PIIPatternRule{}.AnalyzeUnit(sensitiveTextUnit("x.env", source), Context{})
	if len(findings) != 1 || findings[0].Metadata["category"] != "payment-card" {
		t.Fatalf("findings = %+v, want one payment-card finding", findings)
	}
}
