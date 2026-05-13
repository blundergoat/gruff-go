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
}
