// Package scoring tests cover composite scoring, file enrichment, and complexity bins.
// They drive Calculate with crafted findings and assert deterministic output.
package scoring

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestCalculateScoresFindings verifies pillar penalties and coverage caveats.
func TestCalculateScoresFindings(t *testing.T) {
	score := Calculate([]finding.Finding{{
		File:       "a.go",
		Severity:   finding.SeverityWarning,
		Confidence: finding.ConfidenceHigh,
		Pillar:     finding.PillarSize,
	}, {
		File:       "b.go",
		Severity:   finding.SeverityError,
		Confidence: finding.ConfidenceMedium,
		Pillar:     finding.PillarComplexity,
	}})

	if score.Composite <= 0 || score.Composite >= 100 {
		t.Fatalf("composite = %d, want penalized score", score.Composite)
	}
	if score.Grade == "" {
		t.Fatal("missing grade")
	}
	if len(score.Pillars) != 2 {
		t.Fatalf("pillars = %#v, want two pillars", score.Pillars)
	}
	if len(score.Coverage.ContributingPillars) != 2 || score.Coverage.ContributingPillars[0] != "complexity" || score.Coverage.ContributingPillars[1] != "size" {
		t.Fatalf("coverage = %#v, want sorted complexity and size pillars", score.Coverage)
	}
	if score.Coverage.Caveat == "" {
		t.Fatal("expected narrow score coverage caveat")
	}
	if len(score.TopOffender) != 2 || score.TopOffender[0].Penalty < score.TopOffender[1].Penalty {
		t.Fatalf("top offenders not sorted: %#v", score.TopOffender)
	}
}

// TestCalculateCleanScore confirms an all-clean run returns the perfect A grade.
func TestCalculateCleanScore(t *testing.T) {
	score := Calculate(nil)
	if score.Composite != 100 || score.Grade != "A" {
		t.Fatalf("score = %#v, want clean A", score)
	}
	if len(score.TopOffender) != 0 {
		t.Fatalf("top offenders = %#v, want none", score.TopOffender)
	}
	if score.ComplexityDistribution == nil {
		t.Fatal("complexity distribution should be initialised even on clean scores")
	}
	if score.ComplexityDistributionScope != "finding-only" {
		t.Fatalf("complexity distribution scope = %q, want finding-only", score.ComplexityDistributionScope)
	}
	if len(score.Coverage.ContributingPillars) != 0 || score.Coverage.Caveat == "" {
		t.Fatalf("clean score coverage = %#v, want empty pillars with caveat", score.Coverage)
	}
	for _, bin := range []string{"1-5", "6-10", "11-15", "16-20", "21+"} {
		if _, ok := score.ComplexityDistribution[bin]; !ok {
			t.Fatalf("complexity distribution missing bin %q", bin)
		}
	}
	if score.PillarDetails == nil {
		t.Fatal("pillar details should be a non-nil slice on clean scores")
	}
}

// TestCalculatePillarDetailsSortedAndCounted verifies pillar detail counts and ordering.
func TestCalculatePillarDetailsSortedAndCounted(t *testing.T) {
	score := Calculate([]finding.Finding{
		{File: "a.go", Severity: finding.SeverityError, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSecurity},
		{File: "a.go", Severity: finding.SeverityError, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSecurity},
		{File: "b.go", Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarComplexity},
		{File: "b.go", Severity: finding.SeverityAdvisory, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarComplexity},
		{File: "c.go", Severity: finding.SeverityAdvisory, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarComplexity},
	})

	if len(score.PillarDetails) != 2 {
		t.Fatalf("pillar details length = %d, want 2", len(score.PillarDetails))
	}
	if score.PillarDetails[0].Pillar != "complexity" || score.PillarDetails[1].Pillar != "security" {
		t.Fatalf("pillar details not alphabetically sorted: %#v", score.PillarDetails)
	}
	complexity := score.PillarDetails[0]
	// Two findings collapsed from low+info under the 5-bucket model now both count as advisory.
	if complexity.Findings != 3 || complexity.Warning != 1 || complexity.Advisory != 2 {
		t.Fatalf("complexity counts = %#v", complexity)
	}
	// Complexity penalty = warning(8) + 2*advisory(1) = 10 raw, score clamps to 90.
	if complexity.Penalty != 10 {
		t.Errorf("complexity penalty = %v, want 10 (raw unclamped: 8 warning + 2*1 advisory)", complexity.Penalty)
	}
	security := score.PillarDetails[1]
	// Two findings collapsed from critical+high now both count as error.
	if security.Findings != 2 || security.Error != 2 {
		t.Fatalf("security counts = %#v", security)
	}
	// Security penalty = 2*error(30) = 60 raw, score clamps to 40 (grade F).
	if security.Penalty != 60 {
		t.Errorf("security penalty = %v, want 60 (raw unclamped: 2*30 error)", security.Penalty)
	}
	if security.Grade == "" {
		t.Fatal("pillar grade should be derived from per-pillar score")
	}
}

// TestCalculatePillarPenaltyIsRawUnclamped verifies PillarDetail.Penalty
// records the pre-clamp value, preserving the worst-pillar ranking signal when
// scores floor at zero (e.g. 200 advisory findings -> penalty=200, score=0).
func TestCalculatePillarPenaltyIsRawUnclamped(t *testing.T) {
	findings := make([]finding.Finding, 0, 200)
	for range 200 {
		findings = append(findings, finding.Finding{
			File:       "noisy.go",
			Severity:   finding.SeverityAdvisory,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarDocumentation,
		})
	}
	score := Calculate(findings)
	if len(score.PillarDetails) != 1 {
		t.Fatalf("pillar details length = %d, want 1", len(score.PillarDetails))
	}
	detail := score.PillarDetails[0]
	if detail.Score != 0 {
		t.Errorf("documentation score = %d, want 0 (clamped at floor)", detail.Score)
	}
	if detail.Penalty != 200 {
		t.Errorf("documentation penalty = %v, want 200 (raw unclamped: 200 advisory * 1)", detail.Penalty)
	}
}

// TestCalculateFileScoreEnrichment confirms top offenders carry max cyclomatic info.
func TestCalculateFileScoreEnrichment(t *testing.T) {
	score := Calculate([]finding.Finding{
		{
			File:       "hot.go",
			RuleID:     "complexity.cyclomatic",
			Severity:   finding.SeverityError,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarComplexity,
			Metadata:   map[string]any{"complexity": 32},
		},
		{
			File:       "hot.go",
			RuleID:     "complexity.cyclomatic",
			Severity:   finding.SeverityWarning,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarComplexity,
			Metadata:   map[string]any{"complexity": 18},
		},
		{
			File:       "cold.go",
			RuleID:     "size.function-length",
			Severity:   finding.SeverityAdvisory,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarSize,
		},
	})

	if len(score.TopOffender) != 2 {
		t.Fatalf("top offenders length = %d", len(score.TopOffender))
	}
	hot := score.TopOffender[0]
	if hot.File != "hot.go" || hot.Findings != 2 {
		t.Fatalf("hot file score = %#v", hot)
	}
	if hot.MaxCyclomatic == nil || *hot.MaxCyclomatic != 32 {
		t.Fatalf("expected max cyclomatic 32, got %#v", hot.MaxCyclomatic)
	}
	if hot.Grade == "" {
		t.Fatal("file grade should be derived from penalty-based score")
	}
	cold := score.TopOffender[1]
	if cold.MaxCyclomatic != nil {
		t.Fatalf("cold file should have no max cyclomatic, got %v", *cold.MaxCyclomatic)
	}
}

// TestCalculateComplexityDistribution checks complexity histogram bucketing.
func TestCalculateComplexityDistribution(t *testing.T) {
	score := Calculate([]finding.Finding{
		{File: "a.go", RuleID: "complexity.cyclomatic", Severity: finding.SeverityWarning, Pillar: finding.PillarComplexity, Metadata: map[string]any{"complexity": 12}},
		{File: "a.go", RuleID: "complexity.cyclomatic", Severity: finding.SeverityWarning, Pillar: finding.PillarComplexity, Metadata: map[string]any{"complexity": 17}},
		{File: "b.go", RuleID: "complexity.cyclomatic", Severity: finding.SeverityError, Pillar: finding.PillarComplexity, Metadata: map[string]any{"complexity": 42}},
		{File: "c.go", RuleID: "size.function-length", Severity: finding.SeverityAdvisory, Pillar: finding.PillarSize},
	})

	if got := score.ComplexityDistribution["11-15"]; got != 1 {
		t.Errorf("bin 11-15 = %d, want 1", got)
	}
	if got := score.ComplexityDistribution["16-20"]; got != 1 {
		t.Errorf("bin 16-20 = %d, want 1", got)
	}
	if got := score.ComplexityDistribution["21+"]; got != 1 {
		t.Errorf("bin 21+ = %d, want 1", got)
	}
	if got := score.ComplexityDistribution["1-5"]; got != 0 {
		t.Errorf("bin 1-5 = %d, want 0 (non-cyclomatic findings should not count)", got)
	}
}

// TestCalculateCompositeDesignFindingsAreScoreNeutral ensures design.* findings do not penalize the score.
func TestCalculateCompositeDesignFindingsAreScoreNeutral(t *testing.T) {
	base := []finding.Finding{
		{File: "hot.go", RuleID: "size.function-length", Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSize},
		{File: "hot.go", RuleID: "complexity.cyclomatic", Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarComplexity},
	}
	withComposite := append(append([]finding.Finding{}, base...), finding.Finding{
		File:       "hot.go",
		RuleID:     "design.god-function",
		Severity:   finding.SeverityAdvisory,
		Confidence: finding.ConfidenceHigh,
		Pillar:     finding.PillarDesign,
	})

	baseScore := Calculate(base)
	compositeScore := Calculate(withComposite)
	if compositeScore.Composite != baseScore.Composite {
		t.Fatalf("composite score = %d, want score-neutral %d", compositeScore.Composite, baseScore.Composite)
	}
	if len(compositeScore.TopOffender) != len(baseScore.TopOffender) || compositeScore.TopOffender[0].Penalty != baseScore.TopOffender[0].Penalty {
		t.Fatalf("top offenders changed: base=%#v composite=%#v", baseScore.TopOffender, compositeScore.TopOffender)
	}
	if _, ok := compositeScore.Pillars["design"]; ok {
		t.Fatalf("design pillar should be score-neutral, got pillars %#v", compositeScore.Pillars)
	}
}
