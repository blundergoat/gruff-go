// Package rule tests size findings shown for Go test files.
// Fixtures prove defaults soften test noise without overriding project choices.
// Users therefore see the severity they configured when intent is explicit.
package rule

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// TestSizeRulesCalibrateTestFiles ensures warning-size findings on _test.go
// files get softened while already-advisory defaults keep their confidence.
func TestSizeRulesCalibrateTestFiles(t *testing.T) {
	unit := parser.Unit{
		File:      source.File{Path: "long_test.go", Type: source.FileTypeGo},
		LineCount: fileLengthThreshold + 1,
		Source:    strings.Repeat("line\n", fileLengthThreshold+1),
		Functions: []parser.Function{{
			Name:    "TestLong",
			Line:    1,
			EndLine: functionLengthThreshold + 2,
		}},
	}

	defaults := Defaults()
	findings := defaults.Analyze([]parser.Unit{unit}, Context{})
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want file and function length findings", findings)
	}
	byRule := map[string]finding.Finding{}
	for _, item := range findings {
		byRule[item.RuleID] = item
	}
	// file-length now defaults to error, so test files soften it exactly like function-length.
	assertCalibratedTestSizeFinding(t, "size.file-length", byRule["size.file-length"])
	assertCalibratedTestSizeFinding(t, "size.function-length", byRule["size.function-length"])
}

// TestSizeRuleConfiguredSeverityOverridesTestCalibration verifies configured severity wins over calibration.
func TestSizeRuleConfiguredSeverityOverridesTestCalibration(t *testing.T) {
	registry, err := DefaultsConfigured(Config{
		Severities: map[string]finding.Severity{"size.file-length": finding.SeverityError},
	})
	if err != nil {
		t.Fatal(err)
	}
	unit := parser.Unit{
		File:      source.File{Path: "long_test.go", Type: source.FileTypeGo},
		LineCount: fileLengthThreshold + 1,
		Source:    strings.Repeat("line\n", fileLengthThreshold+1),
	}

	findings := registry.Analyze([]parser.Unit{unit}, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one", findings)
	}
	if findings[0].Severity != finding.SeverityError || findings[0].Confidence != finding.ConfidenceHigh {
		t.Fatalf("severity/confidence = %s/%s, want error/high", findings[0].Severity, findings[0].Confidence)
	}
}

// assertCalibratedTestSizeFinding asserts the given finding was calibrated as expected for test files.
func assertCalibratedTestSizeFinding(t *testing.T, ruleID string, item finding.Finding) {
	t.Helper()
	if item.RuleID == "" {
		t.Fatalf("missing %s finding", ruleID)
	}
	if item.Severity != finding.SeverityAdvisory || item.Confidence != finding.ConfidenceMedium {
		t.Fatalf("%s severity/confidence = %s/%s, want advisory/medium", ruleID, item.Severity, item.Confidence)
	}
	if item.Metadata["testFile"] != true {
		t.Fatalf("%s missing testFile metadata: %#v", ruleID, item.Metadata)
	}
}
