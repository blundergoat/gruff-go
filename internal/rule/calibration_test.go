package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

func TestSizeRulesCalibrateTestFiles(t *testing.T) {
	unit := parser.Unit{
		File:      source.File{Path: "long_test.go", Type: source.FileTypeGo},
		LineCount: fileLengthThreshold + 1,
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
	for _, ruleID := range []string{"size.file-length", "size.function-length"} {
		assertCalibratedTestSizeFinding(t, ruleID, byRule[ruleID])
	}
}

func TestSizeRuleConfiguredSeverityOverridesTestCalibration(t *testing.T) {
	registry, err := DefaultsConfigured(Config{
		Severities: map[string]finding.Severity{"size.file-length": finding.SeverityHigh},
	})
	if err != nil {
		t.Fatal(err)
	}
	unit := parser.Unit{
		File:      source.File{Path: "long_test.go", Type: source.FileTypeGo},
		LineCount: fileLengthThreshold + 1,
	}

	findings := registry.Analyze([]parser.Unit{unit}, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one", findings)
	}
	if findings[0].Severity != finding.SeverityHigh || findings[0].Confidence != finding.ConfidenceHigh {
		t.Fatalf("severity/confidence = %s/%s, want high/high", findings[0].Severity, findings[0].Confidence)
	}
}

func assertCalibratedTestSizeFinding(t *testing.T, ruleID string, item finding.Finding) {
	t.Helper()
	if item.RuleID == "" {
		t.Fatalf("missing %s finding", ruleID)
	}
	if item.Severity != finding.SeverityLow || item.Confidence != finding.ConfidenceMedium {
		t.Fatalf("%s severity/confidence = %s/%s, want low/medium", ruleID, item.Severity, item.Confidence)
	}
	if item.Metadata["testFile"] != true {
		t.Fatalf("%s missing testFile metadata: %#v", ruleID, item.Metadata)
	}
}
