package scoring

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

func TestCalculateScoresFindings(t *testing.T) {
	score := Calculate([]finding.Finding{{
		File:       "a.go",
		Severity:   finding.SeverityMedium,
		Confidence: finding.ConfidenceHigh,
		Pillar:     finding.PillarSize,
	}, {
		File:       "b.go",
		Severity:   finding.SeverityHigh,
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
	if len(score.TopOffender) != 2 || score.TopOffender[0].Penalty < score.TopOffender[1].Penalty {
		t.Fatalf("top offenders not sorted: %#v", score.TopOffender)
	}
}

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
	for _, bin := range []string{"1-5", "6-10", "11-15", "16-20", "21+"} {
		if _, ok := score.ComplexityDistribution[bin]; !ok {
			t.Fatalf("complexity distribution missing bin %q", bin)
		}
	}
	if score.PillarDetails == nil {
		t.Fatal("pillar details should be a non-nil slice on clean scores")
	}
}

func TestCalculatePillarDetailsSortedAndCounted(t *testing.T) {
	score := Calculate([]finding.Finding{
		{File: "a.go", Severity: finding.SeverityCritical, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSecurity},
		{File: "a.go", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSecurity},
		{File: "b.go", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarComplexity},
		{File: "b.go", Severity: finding.SeverityLow, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarComplexity},
		{File: "c.go", Severity: finding.SeverityInfo, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarComplexity},
	})

	if len(score.PillarDetails) != 2 {
		t.Fatalf("pillar details length = %d, want 2", len(score.PillarDetails))
	}
	if score.PillarDetails[0].Pillar != "complexity" || score.PillarDetails[1].Pillar != "security" {
		t.Fatalf("pillar details not alphabetically sorted: %#v", score.PillarDetails)
	}
	complexity := score.PillarDetails[0]
	if complexity.Findings != 3 || complexity.Medium != 1 || complexity.Low != 1 || complexity.Info != 1 {
		t.Fatalf("complexity counts = %#v", complexity)
	}
	security := score.PillarDetails[1]
	if security.Findings != 2 || security.Critical != 1 || security.High != 1 {
		t.Fatalf("security counts = %#v", security)
	}
	if security.Grade == "" {
		t.Fatal("pillar grade should be derived from per-pillar score")
	}
}

func TestCalculateFileScoreEnrichment(t *testing.T) {
	score := Calculate([]finding.Finding{
		{
			File:       "hot.go",
			RuleID:     "complexity.cyclomatic",
			Severity:   finding.SeverityHigh,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarComplexity,
			Metadata:   map[string]any{"complexity": 32},
		},
		{
			File:       "hot.go",
			RuleID:     "complexity.cyclomatic",
			Severity:   finding.SeverityMedium,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarComplexity,
			Metadata:   map[string]any{"complexity": 18},
		},
		{
			File:       "cold.go",
			RuleID:     "size.function-length",
			Severity:   finding.SeverityLow,
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

func TestCalculateComplexityDistribution(t *testing.T) {
	score := Calculate([]finding.Finding{
		{File: "a.go", RuleID: "complexity.cyclomatic", Severity: finding.SeverityMedium, Pillar: finding.PillarComplexity, Metadata: map[string]any{"complexity": 12}},
		{File: "a.go", RuleID: "complexity.cyclomatic", Severity: finding.SeverityMedium, Pillar: finding.PillarComplexity, Metadata: map[string]any{"complexity": 17}},
		{File: "b.go", RuleID: "complexity.cyclomatic", Severity: finding.SeverityHigh, Pillar: finding.PillarComplexity, Metadata: map[string]any{"complexity": 42}},
		{File: "c.go", RuleID: "size.function-length", Severity: finding.SeverityLow, Pillar: finding.PillarSize},
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

func TestCalculateCompositeDesignFindingsAreScoreNeutral(t *testing.T) {
	base := []finding.Finding{
		{File: "hot.go", RuleID: "size.function-length", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSize},
		{File: "hot.go", RuleID: "complexity.cyclomatic", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarComplexity},
	}
	withComposite := append(append([]finding.Finding{}, base...), finding.Finding{
		File:       "hot.go",
		RuleID:     "design.god-function",
		Severity:   finding.SeverityLow,
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
