// Package rule tests parser-only modernisation rules.
package rule

import "testing"

// TestIoutilDeprecatedRule covers deprecated ioutil selectors and modern replacements.
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
