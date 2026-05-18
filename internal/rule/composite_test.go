package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

func TestDesignGodFunctionRule(t *testing.T) {
	evidence := []finding.Finding{
		baseFinding("size.function-length", finding.PillarSize, "hot.go", "Hot", 10),
		baseFinding("size.parameter-count", finding.PillarSize, "hot.go", "Hot", 10),
		baseFinding("complexity.cyclomatic", finding.PillarComplexity, "hot.go", "Hot", 10),
		baseFinding("complexity.cyclomatic", finding.PillarComplexity, "other.go", "OnlyComplex", 4),
		baseFinding("size.function-length", finding.PillarSize, "hot.go", "OnlySize", 30),
		baseFinding("complexity.nesting-depth", finding.PillarComplexity, "hot.go", "", 40),
	}

	findings := DesignGodFunctionRule{}.AnalyzeFindings(evidence, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one god-function composite", findings)
	}
	got := findings[0]
	if got.File != "hot.go" || got.Symbol != "Hot" {
		t.Fatalf("finding = %#v, want hot.go Hot", got)
	}
	if got.Location != nil {
		t.Fatalf("location = %#v, want nil for line-stable fingerprint", got.Location)
	}
	if got.Metadata["sizeFindings"] != 2 || got.Metadata["complexityFindings"] != 1 {
		t.Fatalf("metadata = %#v, want evidence counts", got.Metadata)
	}
}

func TestDesignGodFunctionFingerprintIgnoresUnderlyingLineShifts(t *testing.T) {
	rule := DesignGodFunctionRule{}
	firstEvidence := []finding.Finding{
		baseFinding("size.function-length", finding.PillarSize, "hot.go", "Hot", 10),
		baseFinding("complexity.cyclomatic", finding.PillarComplexity, "hot.go", "Hot", 12),
	}
	secondEvidence := []finding.Finding{
		baseFinding("size.function-length", finding.PillarSize, "hot.go", "Hot", 20),
		baseFinding("complexity.cyclomatic", finding.PillarComplexity, "hot.go", "Hot", 22),
	}

	first := applyDefinition(rule.AnalyzeFindings(firstEvidence, Context{})[0], rule.Definition())
	second := applyDefinition(rule.AnalyzeFindings(secondEvidence, Context{})[0], rule.Definition())
	if first.Fingerprint == "" || first.Fingerprint != second.Fingerprint {
		t.Fatalf("fingerprints = %q and %q, want stable non-empty fingerprint", first.Fingerprint, second.Fingerprint)
	}
}

func TestDesignHotspotFileRule(t *testing.T) {
	evidence := []finding.Finding{
		baseFinding("size.function-length", finding.PillarSize, "hot.go", "Hot", 10),
		baseFinding("complexity.cyclomatic", finding.PillarComplexity, "hot.go", "Hot", 10),
		baseFinding("docs.package-comment", finding.PillarDocumentation, "hot.go", "", 1),
		baseFinding("size.file-length", finding.PillarSize, "only-size.go", "", 100),
		baseFinding("size.function-length", finding.PillarSize, "only-size.go", "Long", 30),
		baseFinding("design.god-function", finding.PillarDesign, "hot.go", "Hot", 0),
	}

	findings := (DesignHotspotFileRule{MinFindings: 3, MinPillars: 2}).AnalyzeFindings(evidence, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one hotspot composite", findings)
	}
	got := findings[0]
	if got.File != "hot.go" || got.Symbol != "" {
		t.Fatalf("finding = %#v, want file-level hotspot", got)
	}
	if got.Location != nil {
		t.Fatalf("location = %#v, want nil for line-stable fingerprint", got.Location)
	}
	if got.Metadata["findings"] != 3 {
		t.Fatalf("metadata = %#v, want base finding count only", got.Metadata)
	}
	pillars, ok := got.Metadata["pillars"].([]string)
	if !ok || len(pillars) != 3 || pillars[0] != "complexity" || pillars[1] != "documentation" || pillars[2] != "size" {
		t.Fatalf("pillars metadata = %#v, want sorted base pillars", got.Metadata["pillars"])
	}
}

func TestCompositeRulesFireByDefault(t *testing.T) {
	unit := parseOne(t, "hot.go", `// Package sample is a test package.
package sample

func Hot(a bool, b bool) {
	if a {
		_ = a
	}
	if b {
		_ = b
	}
}
`)
	defaults, err := DefaultsConfigured(Config{
		Thresholds: map[string]map[string]float64{
			"size.function-length":  {"maxLines": 4},
			"complexity.cyclomatic": {"maxComplexity": 2},
			"design.hotspot-file":   {"minFindings": 2, "minPillars": 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings := defaults.Analyze([]parser.Unit{unit}, Context{})
	if !containsRuleID(findings, "design.god-function") || !containsRuleID(findings, "design.hotspot-file") {
		t.Fatalf("default findings = %#v, want composite rules to fire", findings)
	}

	disabled, err := DefaultsConfigured(Config{
		Enabled: map[string]bool{
			"design.god-function": false,
			"design.hotspot-file": false,
		},
		Thresholds: map[string]map[string]float64{
			"size.function-length":  {"maxLines": 4},
			"complexity.cyclomatic": {"maxComplexity": 2},
			"design.hotspot-file":   {"minFindings": 2, "minPillars": 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	disabledFindings := disabled.Analyze([]parser.Unit{unit}, Context{})
	if containsRuleID(disabledFindings, "design.god-function") || containsRuleID(disabledFindings, "design.hotspot-file") {
		t.Fatalf("disabled findings = %#v, want composite rules silenced", disabledFindings)
	}
}

func baseFinding(ruleID string, pillar finding.Pillar, file string, symbol string, line int) finding.Finding {
	item := finding.Finding{
		RuleID:     ruleID,
		File:       file,
		Symbol:     symbol,
		Severity:   finding.SeverityMedium,
		Confidence: finding.ConfidenceHigh,
		Pillar:     pillar,
	}
	if line > 0 {
		item.Location = &finding.Location{Line: line}
	}
	return item.WithFingerprint()
}
