// Package rule defines gruff-go's rule registry and analysers.
//
// This file exercises the design composite rule and shared finding builders.
// The hotspot composite turns several findings in one file, spread over enough pillars, into one file-level design.hotspot-file finding.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestDesignHotspotFileRule verifies the hotspot composite groups findings per file.
//
// hot.go has three base findings in three pillars and must yield one file-level hotspot; only-size.go has two size findings and yields none.
// A failure means the composite missed or over-reported a hotspot, or its Location, findings count or sorted pillars metadata changed.
func TestDesignHotspotFileRule(t *testing.T) {
	evidence := []finding.Finding{
		baseFinding("size.function-length", finding.PillarSize, "hot.go", "Hot", 10),
		baseFinding("complexity.cyclomatic", finding.PillarComplexity, "hot.go", "Hot", 10),
		baseFinding("docs.package-comment", finding.PillarDocumentation, "hot.go", "", 1),
		baseFinding("size.file-length", finding.PillarSize, "only-size.go", "", 100),
		baseFinding("size.function-length", finding.PillarSize, "only-size.go", "Long", 30),
		// A design-pillar finding must not count as its own evidence: composites
		// do not feed other composites, so the hotspot rule skips the design pillar.
		baseFinding("design.hotspot-file", finding.PillarDesign, "hot.go", "Hot", 0),
	}

	findings := (DesignHotspotFileRule{MinFindings: 3, MinPillars: 2}).AnalyzeFindings(evidence, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one hotspot composite", findings)
	}
	got := findings[0]
	if got.File != "hot.go" || got.Symbol != "" {
		t.Fatalf("finding = %#v, want file-level hotspot", got)
	}
	// A file-level hotspot carries no Location, so its fingerprint stays the same when edits move lines in hot.go.
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

// TestCompositeRulesFireByDefault confirms the hotspot composite participates in the default registry.
//
// Hot in hot.go trips the tightened size.function-length limit; one more default finding in another pillar meets the lowered hotspot thresholds.
// The second registry turns design.hotspot-file off through Config.Enabled, and the composite must then stay silent.
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
	if !containsRuleID(findings, "design.hotspot-file") {
		t.Fatalf("default findings = %#v, want hotspot composite to fire", findings)
	}

	disabled, err := DefaultsConfigured(Config{
		Enabled: map[string]bool{
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
	if containsRuleID(disabledFindings, "design.hotspot-file") {
		t.Fatalf("disabled findings = %#v, want hotspot composite silenced", disabledFindings)
	}
}

// baseFinding builds a minimal finding fixture used across composite tests.
//
// It returns a warning, high-confidence finding from rule ruleID, with a fingerprint from WithFingerprint.
// file is the source path the hotspot groups by; pillar counts toward its distinct pillars unless it is the design pillar.
//
// symbol names the flagged declaration; the fixtures pass an empty symbol for file-level findings.
// A positive line becomes the Location line; zero or a negative line leaves Location nil, as for a file-level finding.
func baseFinding(ruleID string, pillar finding.Pillar, file string, symbol string, line int) finding.Finding {
	item := finding.Finding{
		RuleID:     ruleID,
		File:       file,
		Symbol:     symbol,
		Severity:   finding.SeverityWarning,
		Confidence: finding.ConfidenceHigh,
		Pillar:     pillar,
	}
	if line > 0 {
		item.Location = &finding.Location{Line: line}
	}
	return item.WithFingerprint()
}
