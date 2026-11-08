// Package rule tests size findings shown for Go test files.
//
// Fixtures prove default file and function length findings on a _test.go file soften to advisory with medium confidence.
// The upper-band fixture verifies that an explicitly configured severity is preserved.
package rule

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// TestSizeRulesCalibrateTestFiles checks that default file and function length findings on a _test.go file are softened for test code.
//
// Each must come out advisory with medium confidence and carry true testFile metadata.
// A failure means test-file calibration changed, or the fixture no longer yields exactly those two findings.
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

// TestSizeRuleConfiguredSeverityOverridesTestCalibration verifies a configured severity beats test-file calibration for an upper-band finding.
// A user who sets size.file-length to error in the config file sees error with high confidence on a _test.go file twice the length limit.
func TestSizeRuleConfiguredSeverityOverridesTestCalibration(t *testing.T) {
	registry, err := DefaultsConfigured(Config{
		Severities: map[string]finding.Severity{"size.file-length": finding.SeverityError},
	})
	if err != nil {
		t.Fatal(err)
	}
	unit := parser.Unit{
		File: source.File{Path: "long_test.go", Type: source.FileTypeGo},
		// Twice the limit keeps the finding in the upper band, where the configured severity applies.
		LineCount: 2 * fileLengthThreshold,
		Source:    strings.Repeat("line\n", 2*fileLengthThreshold),
	}

	findings := registry.Analyze([]parser.Unit{unit}, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one", findings)
	}
	if findings[0].Severity != finding.SeverityError || findings[0].Confidence != finding.ConfidenceHigh {
		t.Fatalf("severity/confidence = %s/%s, want error/high", findings[0].Severity, findings[0].Confidence)
	}
}

// assertCalibratedTestSizeFinding checks item for the fields expected from test-file size calibration.
//
// It fails when item has an empty RuleID, is not advisory severity with medium confidence, or lacks true testFile metadata.
// An empty RuleID means the rule never fired on the fixture.
// ruleID only labels the failure messages; it is not compared with item.RuleID.
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
