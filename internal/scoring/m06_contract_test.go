// Package scoring's M06 contract tests pin the seven behaviours the ratified family scoring
// contract fixes, so a gruff-go-only change cannot regress one of them silently.
//
// The cross-port suite (`family-check --suite scoring`) proves the same properties for all five
// ports at once, but it runs from the specification repository and needs every port built. These
// tests fail here, in this port's own gate, the moment one of them breaks.
package scoring

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// contractShape names the weight and location a fixture finding carries, so the builder stays inside
// the parameter budget gruff-go enforces on its own source.
type contractShape struct {
	pillar     finding.Pillar
	severity   finding.Severity
	confidence finding.Confidence
	file       string
	symbol     string
}

// contractFinding builds a finding with test-chosen severity and confidence, so a test can predict its weight without a rule's real thresholds.
//
// ruleID names the simulated rule that attribution rows group by, and shape supplies the pillar, severity, confidence, file and symbol.
// It returns the finding with Location fixed at line 1, and any shape field left unset stays at its zero value.
func contractFinding(ruleID string, shape contractShape) finding.Finding {
	return finding.Finding{
		RuleID:     ruleID,
		Pillar:     shape.pillar,
		Severity:   shape.severity,
		Confidence: shape.confidence,
		File:       shape.file,
		Symbol:     shape.symbol,
		Location:   &finding.Location{Line: 1},
	}
}

// TestScaleIsNotAnAutomaticPenalty proves duplicating a project 2x or 4x, findings and evaluated files together, leaves the composite unchanged.
//
// Finding density does not change, so the grade must not move; t reports a composite that shifts at 2x or at 4x.
func TestScaleIsNotAnAutomaticPenalty(t *testing.T) {
	pillars := registeredRuleBackedPillars(t)
	single := []finding.Finding{
		contractFinding("complexity.cognitive", contractShape{pillar: finding.PillarComplexity, severity: finding.SeverityWarning, confidence: finding.ConfidenceHigh, file: "a.go", symbol: "One"}),
	}
	doubled := append(append([]finding.Finding{}, single...),
		contractFinding("complexity.cognitive", contractShape{pillar: finding.PillarComplexity, severity: finding.SeverityWarning, confidence: finding.ConfidenceHigh, file: "b.go", symbol: "Two"}),
	)

	base := Calculate(single, 10, pillars...)
	scaled := Calculate(doubled, 20, pillars...)

	if *base.Composite != *scaled.Composite {
		t.Fatalf("duplicating the project moved the composite from %v to %v", *base.Composite, *scaled.Composite)
	}

	quadrupled := append(append([]finding.Finding{}, doubled...),
		contractFinding("complexity.cognitive", contractShape{pillar: finding.PillarComplexity, severity: finding.SeverityWarning, confidence: finding.ConfidenceHigh, file: "c.go", symbol: "Three"}),
		contractFinding("complexity.cognitive", contractShape{pillar: finding.PillarComplexity, severity: finding.SeverityWarning, confidence: finding.ConfidenceHigh, file: "d.go", symbol: "Four"}),
	)

	if *Calculate(quadrupled, 40, pillars...).Composite != *base.Composite {
		t.Fatalf("scaling the project 4x moved the composite off %v", *base.Composite)
	}
}

// TestMonotonicityAtAFixedDenominator checks that adding an unclustered security error, with no new file, lowers security and the composite.
// t also requires the untouched documentation pillar to keep its score; a finding that joins a cross-pillar cluster is not covered here.
func TestMonotonicityAtAFixedDenominator(t *testing.T) {
	pillars := registeredRuleBackedPillars(t)
	before := Calculate([]finding.Finding{
		contractFinding("security.one", contractShape{pillar: finding.PillarSecurity, severity: finding.SeverityWarning, confidence: finding.ConfidenceHigh, file: "a.go", symbol: "One"}),
	}, 10, pillars...)
	after := Calculate([]finding.Finding{
		contractFinding("security.one", contractShape{pillar: finding.PillarSecurity, severity: finding.SeverityWarning, confidence: finding.ConfidenceHigh, file: "a.go", symbol: "One"}),
		contractFinding("security.two", contractShape{pillar: finding.PillarSecurity, severity: finding.SeverityError, confidence: finding.ConfidenceHigh, file: "a.go", symbol: "Two"}),
	}, 10, pillars...)

	securityBefore := findPillarDetail(t, before, "security")
	securityAfter := findPillarDetail(t, after, "security")

	if *securityAfter.Score >= *securityBefore.Score {
		t.Errorf("adding an error left security at %v, was %v", *securityAfter.Score, *securityBefore.Score)
	}

	if *after.Composite >= *before.Composite {
		t.Errorf("adding an error left the composite at %v, was %v", *after.Composite, *before.Composite)
	}

	// With no cross-pillar cluster in this fixture, a pillar that gained no finding must not move, or the composite is coupling unrelated areas.
	if *findPillarDetail(t, after, "documentation").Score != *findPillarDetail(t, before, "documentation").Score {
		t.Error("an untouched pillar moved when security gained a finding")
	}
}

// TestApplicabilityKeepsNullApartFromPerfect proves the C3 contract: a reachable pillar that
// reported nothing scores exactly 100, and a run that evaluated nothing scores nothing at all.
func TestApplicabilityKeepsNullApartFromPerfect(t *testing.T) {
	pillars := registeredRuleBackedPillars(t)
	clean := Calculate(nil, 10, pillars...)

	for _, detail := range clean.PillarDetails {
		if detail.Score == nil || *detail.Score != 100 {
			t.Fatalf("reachable clean pillar %s scored %v, want 100", detail.Pillar, detail.Score)
		}
		if !detail.Applicable {
			t.Fatalf("pillar %s is reachable but not marked applicable", detail.Pillar)
		}
	}

	nothing := Calculate(nil, 0, pillars...)

	if nothing.Composite != nil || nothing.Grade != nil {
		t.Fatalf("a run that evaluated nothing published %v / %v", nothing.Composite, nothing.Grade)
	}

	for _, detail := range nothing.PillarDetails {
		if detail.Score != nil {
			t.Fatalf("pillar %s scored %v with nothing evaluated", detail.Pillar, *detail.Score)
		}
	}
}

// TestSerializationRoundsToTwoDecimals proves the ratified precision, including that an exact half rounds away from zero.
//
// Ties matter because the four sibling ports round the same way, and t reports every raw value whose rounding differs.
// A port that broke half to even would disagree with them on the last cent for reasons unrelated to the formula.
func TestSerializationRoundsToTwoDecimals(t *testing.T) {
	cases := []struct {
		raw  float64
		want float64
	}{
		{raw: 97.681818, want: 97.68},
		{raw: 53.125, want: 53.13},
		{raw: 50.005, want: 50.01},
		{raw: 100, want: 100},
	}

	for _, testCase := range cases {
		if got := roundScore(testCase.raw); got != testCase.want {
			t.Errorf("roundScore(%v) = %v, want %v", testCase.raw, got, testCase.want)
		}
	}

	// Negative zero is normalized away, because JSON projection keeps it in some ports and not others.
	if got := roundScore(-0.001); got != 0 || !isPositiveZero(got) {
		t.Errorf("roundScore(-0.001) = %v, want a positive zero", got)
	}
}

// isPositiveZero reports whether value is zero without a sign bit.
// It reports false for any nonzero value and for negative zero, the form roundScore must never publish.
func isPositiveZero(value float64) bool {
	return value == 0 && 1/value > 0
}

// TestClusteringKeysOnSymbolWithoutLineIdentity proves the ratified cluster key groups by symbol and leaves the line out.
//
// Correlated rules disagree on which line to report: a size rule may name the declaration and a complexity rule the body.
// A line in the key would split one root cause into two and bill it twice; t checks the shared cluster and that distinct symbols stay apart.
func TestClusteringKeysOnSymbolWithoutLineIdentity(t *testing.T) {
	sameSymbolDifferentLines := []finding.Finding{
		{RuleID: "size.function-length", Pillar: finding.PillarSize, Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, File: "a.go", Symbol: "Run", Location: &finding.Location{Line: 1}},
		{RuleID: "complexity.cyclomatic", Pillar: finding.PillarComplexity, Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, File: "a.go", Symbol: "Run", Location: &finding.Location{Line: 9}},
	}
	score := Calculate(sameSymbolDifferentLines, 10)

	// One warning weighs 4, so the cluster bills 4 across two members: 2 each.
	if got := findPillarDetail(t, score, "size").Penalty; got != 2 {
		t.Errorf("size weight = %v, want 2 (the cluster's single worst member, halved)", got)
	}

	if len(score.Clusters) != 1 || score.Clusters[0].Findings != 2 {
		t.Fatalf("clusters = %#v, want one cluster of two", score.Clusters)
	}

	if score.Clusters[0].Weight != 4 {
		t.Errorf("cluster weight = %v, want 4 (billed once, not 8)", score.Clusters[0].Weight)
	}

	// Two distinct symbols are two root causes and must not share relief.
	distinct := []finding.Finding{
		{RuleID: "size.function-length", Pillar: finding.PillarSize, Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, File: "a.go", Symbol: "Run", Location: &finding.Location{Line: 1}},
		{RuleID: "complexity.cyclomatic", Pillar: finding.PillarComplexity, Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, File: "a.go", Symbol: "Walk", Location: &finding.Location{Line: 9}},
	}

	if clusters := Calculate(distinct, 10).Clusters; len(clusters) != 0 {
		t.Errorf("clusters = %#v, want none across distinct symbols", clusters)
	}
}

// TestRuleAttributionIsKeyedByNativeRuleID checks each naming rule in its fixture gets one attribution row with its finding count and weight.
//
// Rows must sort by rule ID so two runs over unchanged input publish the same bytes.
// Its findings name distinct symbols, so t sees no cluster form and post-clustering weight is not covered here.
func TestRuleAttributionIsKeyedByNativeRuleID(t *testing.T) {
	score := Calculate([]finding.Finding{
		contractFinding("naming.b-rule", contractShape{pillar: finding.PillarNaming, severity: finding.SeverityAdvisory, confidence: finding.ConfidenceHigh, file: "a.go", symbol: "One"}),
		contractFinding("naming.a-rule", contractShape{pillar: finding.PillarNaming, severity: finding.SeverityWarning, confidence: finding.ConfidenceMedium, file: "a.go", symbol: "Two"}),
		contractFinding("naming.a-rule", contractShape{pillar: finding.PillarNaming, severity: finding.SeverityWarning, confidence: finding.ConfidenceMedium, file: "b.go", symbol: "Three"}),
	}, 10)

	if len(score.RuleAttribution) != 2 {
		t.Fatalf("attribution = %#v, want one row per native rule", score.RuleAttribution)
	}

	// Sorted by rule identifier, so "naming.a-rule" precedes "naming.b-rule".
	if score.RuleAttribution[0].RuleID != "naming.a-rule" || score.RuleAttribution[1].RuleID != "naming.b-rule" {
		t.Fatalf("attribution rows out of rule-identifier order: %#v", score.RuleAttribution)
	}

	// Two warnings at medium confidence weigh 4 * 0.75 each.
	if score.RuleAttribution[0].Findings != 2 || score.RuleAttribution[0].Weight != 6 {
		t.Errorf("naming.a-rule = %#v, want 2 findings weighing 6", score.RuleAttribution[0])
	}

	// One advisory at high confidence weighs 1.
	if score.RuleAttribution[1].Findings != 1 || score.RuleAttribution[1].Weight != 1 {
		t.Errorf("naming.b-rule = %#v, want 1 finding weighing 1", score.RuleAttribution[1])
	}
}

// TestPublishedDenominatorAndPillarSet checks EvaluatedFiles is 7 and ScoredPillars and PillarDetails match the registered pillar count.
func TestPublishedDenominatorAndPillarSet(t *testing.T) {
	pillars := registeredRuleBackedPillars(t)
	score := Calculate(nil, 7, pillars...)

	if score.EvaluatedFiles == nil || *score.EvaluatedFiles != 7 {
		t.Fatalf("evaluatedFiles = %v, want the 7 passed in", score.EvaluatedFiles)
	}

	if len(score.ScoredPillars) != len(pillars) {
		t.Fatalf("scoredPillars = %d, want all %d rule-backed pillars", len(score.ScoredPillars), len(pillars))
	}

	// The composite averages the published pillar set, so a reader can recompute it from these fields.
	if len(score.PillarDetails) != len(score.ScoredPillars) {
		t.Errorf("pillar rows = %d, scored pillars = %d; the two must agree", len(score.PillarDetails), len(score.ScoredPillars))
	}
}
