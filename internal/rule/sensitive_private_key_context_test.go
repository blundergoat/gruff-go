// Package rule tests when a Go developer names a PEM marker to parse or re-wrap a caller's key.
// The confirmed gosec declarations are checked with their real syntax, while nearby source shapes must still warn.
// These tests keep each header independent when several appear on one line.
// Parser-free units model deep-scan fallback, where the developer must still see the warning.
package rule

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// privateKeyTestSource expands PEM marker placeholders when a test parses Go code for a developer's scan.
// Keeping complete marker bytes out of this test file lets candidate redaction bind the actual regression source safely.
func privateKeyTestSource(template string) string {
	return strings.NewReplacer(
		"{{PRIVATE}}", "-----BEGIN "+"PRIVATE KEY-----",
		"{{RSA}}", "-----BEGIN "+"RSA PRIVATE KEY-----",
		"{{DSA}}", "-----BEGIN "+"DSA PRIVATE KEY-----",
		"{{EC}}", "-----BEGIN "+"EC PRIVATE KEY-----",
		"{{END_PRIVATE}}", "-----END "+"PRIVATE KEY-----",
	).Replace(template)
}

// TestPrivateKeyRuleRecognizesObservedRegexpMarkers confirms the gosec RSA, DSA and EC parser patterns carry no key body.
// Only DSA and EC are adjudicated false-positive cases; RSA is checked because the same predicate reaches it.
func TestPrivateKeyRuleRecognizesObservedRegexpMarkers(t *testing.T) {
	unit := parseOne(t, "patterns.go", privateKeyTestSource(`package patterns
import "regexp"
var secretsPatterns = []any{
	regexp.MustCompile(`+"`"+`{{RSA}}`+"`"+`),
	regexp.MustCompile(`+"`"+`{{DSA}}`+"`"+`),
	regexp.MustCompile(`+"`"+`{{EC}}`+"`"+`),
}
`))
	// A scan of these parser definitions must leave the developer with no private-key warning.
	if findings := (PrivateKeyRule{}).AnalyzeUnit(unit, Context{}); len(findings) != 0 {
		t.Fatalf("parser marker findings = %#v, want none", findings)
	}
}

// TestPrivateKeyRuleAcceptsResolvedNativeMarkerUses covers both regexp spellings and the supported string delimiter calls.
// Aliases remain safe only when they still name the imported standard-library package.
func TestPrivateKeyRuleAcceptsResolvedNativeMarkerUses(t *testing.T) {
	unit := parseOne(t, "parser.go", privateKeyTestSource(`package parser
import (
	rx "regexp"
	text "strings"
)
var a, _ = rx.Compile("{{DSA}}")
var b = rx.MustCompile("{{EC}}\\n")
func clean(value string) string {
	value = text.ReplaceAll(value, "{{PRIVATE}}", "")
	value = text.TrimPrefix(value, "{{RSA}}")
	return text.TrimSuffix(value, "{{EC}}")
}
`))
	// Parser and delimiter calls should not interrupt a user's scan with marker-only findings.
	if findings := (PrivateKeyRule{}).AnalyzeUnit(unit, Context{}); len(findings) != 0 {
		t.Fatalf("resolved marker findings = %#v, want none", findings)
	}
}

// TestPrivateKeyRuleKeepsUnprovenGoHeadersVisible covers source contexts that do not prove a matched marker is only a parser delimiter.
// A developer reviewing any of these forms needs the private-key warning.
func TestPrivateKeyRuleKeepsUnprovenGoHeadersVisible(t *testing.T) {
	cases := []struct {
		name   string
		source string
	}{
		{
			name:   "bare header",
			source: "package keys\nvar key = \"{{PRIVATE}}\"\n",
		},
		{
			name:   "unrelated regexp on the same line",
			source: "package keys\nimport \"regexp\"\nvar pattern, key = regexp.MustCompile(\"ordinary\"), \"{{EC}}\"\n",
		},
		{
			name: "one safe and one bare header on the same line",
			source: "package keys\nimport \"regexp\"\n" +
				"var pattern, key = regexp.MustCompile(\"{{EC}}\"), \"{{DSA}}\"\n",
		},
		{
			name:   "missing regexp import",
			source: "package keys\nvar pattern = regexp.MustCompile(\"{{EC}}\")\n",
		},
		{
			name: "shadowed regexp import",
			source: "package keys\nimport \"regexp\"\n" +
				"func makePattern(regexp struct{ MustCompile func(string) string }) { _ = regexp.MustCompile(\"{{EC}}\") }\n",
		},
		{
			name: "marker is the input, not the delimiter",
			source: "package keys\nimport \"strings\"\n" +
				"var key = strings.ReplaceAll(\"{{PRIVATE}}\", \"x\", \"\")\n",
		},
		{
			name: "shadowed strings import",
			source: "package keys\nimport \"strings\"\n" +
				"func trim(strings struct{ TrimPrefix func(string, string) string }, value string) string {" +
				" return strings.TrimPrefix(value, \"{{PRIVATE}}\") }\n",
		},
		{
			name: "regexp argument joins authored material",
			source: "package keys\nimport \"regexp\"\n" +
				"var pattern = regexp.MustCompile(\"{{PRIVATE}}\\n\" + \"authored-key-body\")\n",
		},
	}
	// Each nearby source shape must retain the warning even when it resembles the confirmed parser cases.
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			unit := parseOne(t, "keys.go", privateKeyTestSource(testCase.source))
			// A single visible warning means the unproven header was not hidden by another call or header.
			if findings := (PrivateKeyRule{}).AnalyzeUnit(unit, Context{}); len(findings) != 1 {
				t.Fatalf("private-key findings = %#v, want one", findings)
			}
		})
	}
}

// TestPrivateKeyRuleKeepsEmbeddedBodyVisible makes full, escaped and truncated authored key text report even near native calls.
// The body is assembled in the test so the test file itself never carries a reusable PEM block.
func TestPrivateKeyRuleKeepsEmbeddedBodyVisible(t *testing.T) {
	body := strings.Repeat("A", 64)
	cases := []struct {
		name   string
		source string
	}{
		{
			name:   "escaped body in regexp",
			source: "package keys\nimport \"regexp\"\nvar pattern = regexp.MustCompile(\"{{PRIVATE}}\\n" + body + "\")\n",
		},
		{
			name: "closed body in raw literal",
			source: "package keys\nimport \"regexp\"\nvar pattern = regexp.MustCompile(`{{PRIVATE}}\n" + body +
				"\n{{END_PRIVATE}}`)\n",
		},
		{
			name:   "truncated body in raw literal",
			source: "package keys\nimport \"regexp\"\nvar pattern = regexp.MustCompile(`{{PRIVATE}}\n" + body + "`)\n",
		},
		{
			name: "authored body assigned to wrapper parameter",
			source: "package keys\nfunc wrap(payload string) []byte { payload = \"" + body +
				"\"; return []byte(\"{{PRIVATE}}\\n\" + payload + \"\\n{{END_PRIVATE}}\") }\n",
		},
	}
	// Authored body text means the developer still needs a warning, even when code calls regexp.MustCompile.
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			unit := parseOne(t, "keys.go", privateKeyTestSource(testCase.source))
			// The matched header belongs to a body-bearing literal and cannot be exempted as a parser marker.
			if findings := (PrivateKeyRule{}).AnalyzeUnit(unit, Context{}); len(findings) != 1 {
				t.Fatalf("embedded-key findings = %#v, want one", findings)
			}
		})
	}
}

// TestPrivateKeyRuleKeepsWarningWithoutGoSyntax models an over-budget Go scan with source text but no AST.
// A developer still gets the warning because the scanner cannot establish what the regexp-like text means.
func TestPrivateKeyRuleKeepsWarningWithoutGoSyntax(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "patterns.go", Type: source.FileTypeGo},
		Source: privateKeyTestSource("package keys\nimport \"regexp\"\nvar pattern = regexp.MustCompile(\"{{EC}}\")\n"),
	}
	// Fallback text scanning cannot grant an AST-based exemption.
	if findings := (PrivateKeyRule{}).AnalyzeUnit(unit, Context{}); len(findings) != 1 {
		t.Fatalf("parser-free findings = %#v, want one", findings)
	}
}
