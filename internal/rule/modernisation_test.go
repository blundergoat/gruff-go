// Package rule tests parser-only modernisation rules.
//
// The test parses a Go fixture that imports io/ioutil under an alias; failed rule checks print the findings or the first finding's metadata.
package rule

import "testing"

// TestIoutilDeprecatedRule checks the total finding count for an aliased io/ioutil fixture using ReadFile, TempFile and Discard.
//
// It expects three findings and a first finding whose replacement metadata is not the empty string; an absent replacement key also passes.
func TestIoutilDeprecatedRule(t *testing.T) {
	unit := parseOne(t, "modern.go", `// Package sample is a test package.
package sample

import oldio "io/ioutil"

func sample(path string) {
	_, _ = oldio.ReadFile(path)
	_, _ = oldio.TempFile("", "sample")
	_ = oldio.Discard
}
`)
	findings := IoutilDeprecatedRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 3 {
		t.Fatalf("findings = %#v, want three ioutil findings", findings)
	}
	if findings[0].Metadata["replacement"] == "" {
		t.Fatalf("metadata = %#v, want replacement", findings[0].Metadata)
	}
}
