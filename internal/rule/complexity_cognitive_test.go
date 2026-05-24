// Package rule tests parser-only cognitive complexity.
package rule

import "testing"

// TestCognitiveComplexityRule verifies thresholding and metadata for nested decisions.
func TestCognitiveComplexityRule(t *testing.T) {
	unit := parseOne(t, "complex.go", `// Package sample is a test package.
package sample

func Complex(a, b, c bool, values []int) {
	if a && b {
		for _, value := range values {
			if value > 0 || c {
				switch value {
				case 1:
					if c {
						println(value)
					}
				}
			}
		}
	}
}
`)
	findings := CognitiveComplexityRule{MaxComplexity: 5}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "Complex" {
		t.Fatalf("findings = %#v, want one finding on Complex", findings)
	}
	if findings[0].Metadata["threshold"] != 5 {
		t.Fatalf("metadata = %#v, want threshold=5", findings[0].Metadata)
	}
}
