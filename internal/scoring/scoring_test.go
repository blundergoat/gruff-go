// Package scoring tests the quality score gruff-go shows in CLI and machine reports.
//
// Crafted findings pin pillar scores, the composite, grades and top offenders, so score changes stay predictable for users comparing scans.
// It also checks that clearing a finding never lowers the composite, and that a run that evaluated no file reports null, not 100/A.
package scoring

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestCalculateScoresFindings scores a warning and an error in two pillars and checks the composite, grade, coverage and top-offender order.
// A failure means a two-pillar scan shows an out-of-range composite, no grade, misordered pillars or offenders, or no coverage caveat.
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
	}}, 10)

	if score.Composite == nil || *score.Composite <= scoreFloor || *score.Composite >= 100 {
		t.Fatalf("composite = %v, want a penalized score inside the ratified range", score.Composite)
	}
	if score.Grade == nil {
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

// TestCalculateCleanScore confirms a clean scan of 10 files across every rule-backed pillar scores 100 with grade A and no top offenders.
// A failure flags an unexpected score, grade, top offender, histogram bin or scope, coverage caveat, or per-pillar detail row.
func TestCalculateCleanScore(t *testing.T) {
	// The pillar set has to come from the catalogue: with no reachable pillar there is nothing to be
	// clean about, and that case is the applicability contract's null, not an A.
	score := Calculate(nil, 10, registeredRuleBackedPillars(t)...)
	if score.Composite == nil || *score.Composite != 100 || score.Grade == nil || *score.Grade != "A" {
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
	if len(score.PillarDetails) != len(registeredRuleBackedPillars(t)) {
		t.Fatalf("pillar details = %d rows, want one per rule-backed pillar on a clean scan", len(score.PillarDetails))
	}
}

// TestCalculateCompositeCountsCleanRuleBackedPillars expects clean product areas
// to contribute 100 instead of disappearing from the score shown to the user.
func TestCalculateCompositeCountsCleanRuleBackedPillars(t *testing.T) {
	registeredPillars := registeredRuleBackedPillars(t)
	pillarCount := len(registeredPillars)
	findings := []finding.Finding{
		{File: "size.go", Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSize},
		{File: "complex.go", Severity: finding.SeverityError, Confidence: finding.ConfidenceMedium, Pillar: finding.PillarComplexity},
	}

	score := Calculate(findings, 10, registeredPillars...)
	sizeScore := pillarScoreFor(4, 10)
	complexityScore := pillarScoreFor(9, 10)
	want := roundScore((sizeScore + complexityScore + 100*float64(pillarCount-2)) / float64(pillarCount))
	// A different value means the headline is not the mean across finding-bearing and clean rule-backed pillars, for example an omitted clean area.
	if score.Composite == nil || *score.Composite != want {
		t.Fatalf("composite = %v, want %v across %d rule-backed pillars", score.Composite, want, pillarCount)
	}
}

// TestCalculateCompositeNeverDropsWhenFindingRemoved checks that removing any one unclustered fixture finding never lowers the composite.
func TestCalculateCompositeNeverDropsWhenFindingRemoved(t *testing.T) {
	registeredPillars := registeredRuleBackedPillars(t)
	findings := []finding.Finding{
		{File: "size.go", Severity: finding.SeverityError, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSize},
		{File: "size.go", Severity: finding.SeverityError, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSize},
		{File: "docs.go", Severity: finding.SeverityAdvisory, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarDocumentation},
	}
	before := Calculate(findings, 10, registeredPillars...).Composite

	// Try every possible single remediation because users can clear findings in any order.
	for removedIndex := range findings {
		remaining := append([]finding.Finding(nil), findings[:removedIndex]...)
		remaining = append(remaining, findings[removedIndex+1:]...)
		after := Calculate(remaining, 10, registeredPillars...).Composite
		// A lower score would punish the user for completing a remediation.
		if *after < *before {
			t.Errorf("removing finding %d lowered composite from %v to %v", removedIndex, *before, *after)
		}
	}
}

// TestCalculateCompositeKeepsClearedPillarInMean reproduces the punished-finisher
// case where removing the last mild finding used to drop an above-average pillar.
func TestCalculateCompositeKeepsClearedPillarInMean(t *testing.T) {
	registeredPillars := registeredRuleBackedPillars(t)
	findings := []finding.Finding{
		{File: "size.go", Severity: finding.SeverityError, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSize},
		{File: "size.go", Severity: finding.SeverityError, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSize},
		{File: "docs.go", Severity: finding.SeverityAdvisory, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarDocumentation},
	}
	before := Calculate(findings, 10, registeredPillars...).Composite
	after := Calculate(findings[:2], 10, registeredPillars...).Composite

	// The quality total must rise or stay level after the documentation pillar becomes clean.
	if *after < *before {
		t.Fatalf("clearing the final documentation finding lowered composite from %v to %v", *before, *after)
	}
}

// TestCalculateCompositeCarriesTwoDecimals checks the calculated composite is the two-decimal mean of the pillar scores.
// Before M06 the composite was an integer that truncated a user's fractional score toward zero.
func TestCalculateCompositeCarriesTwoDecimals(t *testing.T) {
	registeredPillars := registeredRuleBackedPillars(t)
	pillarCount := len(registeredPillars)
	score := Calculate([]finding.Finding{{
		File:       "docs.go",
		Severity:   finding.SeverityAdvisory,
		Confidence: finding.ConfidenceHigh,
		Pillar:     finding.PillarDocumentation,
	}}, 10, registeredPillars...)
	want := roundScore((pillarScoreFor(1, 10) + 100*float64(pillarCount-1)) / float64(pillarCount))

	// A one-finding pillar leaves a fractional mean, which the ratified contract keeps to two decimals.
	if score.Composite == nil || *score.Composite != want {
		t.Fatalf("composite = %v, want the two-decimal mean %v", score.Composite, want)
	}
	if *score.Composite != roundScore(*score.Composite) {
		t.Fatalf("composite = %v carries more than two decimals", *score.Composite)
	}
}

// TestPillarCurveIsRatified pins the ratified curve itself at points whose arithmetic is exact,
// so a change to floor, densityScale, or the formula fails here rather than drifting silently.
func TestPillarCurveIsRatified(t *testing.T) {
	// floor + (100-floor)/(1 + density/densityScale), with floor 50 and densityScale 0.1.
	cases := []struct {
		weight         float64
		evaluatedFiles int
		want           float64
	}{
		{weight: 0, evaluatedFiles: 10, want: 100}, // a reachable pillar with no findings
		{weight: 1, evaluatedFiles: 10, want: 75},  // density 0.1 is the curve's half-way point
		{weight: 4, evaluatedFiles: 10, want: 60},  // density 0.4
		{weight: 9, evaluatedFiles: 10, want: 55},  // density 0.9
		{weight: 2, evaluatedFiles: 20, want: 75},  // twice the findings over twice the code is one ratio
	}
	for _, testCase := range cases {
		if got := pillarScoreFor(testCase.weight, testCase.evaluatedFiles); got != testCase.want {
			t.Errorf("pillarScoreFor(%v, %d) = %v, want %v", testCase.weight, testCase.evaluatedFiles, got, testCase.want)
		}
	}
}

// TestCalculateEvaluatedNothingIsNotPerfect proves the applicability contract: a run that evaluated
// no file reports null throughout instead of the 100/A an empty directory used to receive.
func TestCalculateEvaluatedNothingIsNotPerfect(t *testing.T) {
	registeredPillars := registeredRuleBackedPillars(t)
	score := Calculate(nil, 0, registeredPillars...)

	if score.Composite != nil || score.Grade != nil {
		t.Fatalf("composite = %v, grade = %v; want null throughout when nothing was evaluated", score.Composite, score.Grade)
	}
	if score.EvaluatedFiles == nil || *score.EvaluatedFiles != 0 {
		t.Fatalf("evaluatedFiles = %v, want a published zero", score.EvaluatedFiles)
	}
	if len(score.ScoredPillars) != len(registeredPillars) {
		t.Fatalf("scoredPillars = %d, want all %d rule-backed pillars", len(score.ScoredPillars), len(registeredPillars))
	}
	// A pillar score here would grade code that gruff-go never evaluated.
	for _, detail := range score.PillarDetails {
		if detail.Score != nil || detail.Grade != nil {
			t.Fatalf("pillar %s = %v, want no score when nothing was evaluated", detail.Pillar, detail.Score)
		}
	}
}

// registeredRuleBackedPillars derives the product areas, or pillars, from the live rule.Defaults() catalogue.
//
// Tests follow new areas this way without hardcoding names or hiding opt-in rules.
// It returns each distinct Pillar once, in no fixed order; t fails the test if the catalogue has none, so the result is never empty.
func registeredRuleBackedPillars(t *testing.T) []finding.Pillar {
	t.Helper()
	uniquePillars := map[finding.Pillar]struct{}{}
	registry := rule.Defaults()
	// Every registered rule-backed area counts, including opt-in and currently clean areas.
	for _, definition := range registry.Definitions() {
		uniquePillars[definition.Pillar] = struct{}{}
	}
	// A missing pillar universe would make every composite meaningless to report users.
	if len(uniquePillars) == 0 {
		t.Fatal("default registry has no rule-backed pillars")
	}
	pillars := make([]finding.Pillar, 0, len(uniquePillars))
	// Return values instead of only a count so the production calculation owns the denominator.
	for pillar := range uniquePillars {
		pillars = append(pillars, pillar)
	}
	return pillars
}

// TestCalculatePillarDetailsSortedAndCounted checks pillar detail rows for alphabetical order, per-severity counts and ratified penalties.
// A failure means pillar details come out of order, miscount severities, or carry a penalty other than the ratified weight.
func TestCalculatePillarDetailsSortedAndCounted(t *testing.T) {
	score := Calculate([]finding.Finding{
		{File: "a.go", Severity: finding.SeverityError, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSecurity},
		{File: "a.go", Severity: finding.SeverityError, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSecurity},
		{File: "b.go", Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarComplexity},
		{File: "b.go", Severity: finding.SeverityAdvisory, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarComplexity},
		{File: "c.go", Severity: finding.SeverityAdvisory, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarComplexity},
	}, 10)

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
	// Complexity weight = warning(4) + 2*advisory(1) = 6 under the ratified weights.
	if complexity.Penalty != 6 {
		t.Errorf("complexity penalty = %v, want 6 (ratified: 4 warning + 2*1 advisory)", complexity.Penalty)
	}
	security := score.PillarDetails[1]
	// Two findings collapsed from critical+high now both count as error.
	if security.Findings != 2 || security.Error != 2 {
		t.Fatalf("security counts = %#v", security)
	}
	// Security weight = 2*error(12) = 24; the error weight dropped 2.5x at the M06 break.
	if security.Penalty != 24 {
		t.Errorf("security penalty = %v, want 24 (ratified: 2*12 error)", security.Penalty)
	}
	if security.Grade == nil {
		t.Fatal("pillar grade should be derived from per-pillar score")
	}
}

// TestCalculatePillarPenaltyIsRawUnclamped verifies PillarDetail.Penalty records the raw summed weight, 200 for 200 advisory findings.
//
// The raw penalty keeps the worst-pillar ranking once the score nears the ratified floor and can no longer tell noisy from far noisier.
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
	score := Calculate(findings, 10)
	if len(score.PillarDetails) != 1 {
		t.Fatalf("pillar details length = %d, want 1", len(score.PillarDetails))
	}
	detail := score.PillarDetails[0]
	// The ratified curve approaches the floor but never crosses it, however much volume lands here.
	if detail.Score == nil || *detail.Score <= scoreFloor || *detail.Score >= scoreFloor+1 {
		t.Errorf("documentation score = %v, want just above the ratified floor %v", detail.Score, scoreFloor)
	}
	if detail.Penalty != 200 {
		t.Errorf("documentation penalty = %v, want 200 (raw unclamped: 200 advisory * 1)", detail.Penalty)
	}
}

// TestCalculateFileScoreEnrichment confirms top-offender files carry their highest cyclomatic complexity, a grade, and a per-file curve score.
// A file with no complexity.cyclomatic finding must keep MaxCyclomatic nil.
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
	}, 10)

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
		t.Fatal("file grade should be derived from the ratified per-file score")
	}
	// A file's density is its own weighted findings, so file and project scores share one curve.
	if hot.Score != pillarScoreFor(hot.Penalty, 1) {
		t.Errorf("hot file score = %v, want the ratified per-file curve %v", hot.Score, pillarScoreFor(hot.Penalty, 1))
	}
	cold := score.TopOffender[1]
	if cold.MaxCyclomatic != nil {
		t.Fatalf("cold file should have no max cyclomatic, got %v", *cold.MaxCyclomatic)
	}
}

// TestCalculateComplexityDistribution checks that complexity.cyclomatic findings land in the right histogram bin by their complexity metadata.
// A size.function-length finding must not count, so bin 1-5 stays at zero.
func TestCalculateComplexityDistribution(t *testing.T) {
	score := Calculate([]finding.Finding{
		{File: "a.go", RuleID: "complexity.cyclomatic", Severity: finding.SeverityWarning, Pillar: finding.PillarComplexity, Metadata: map[string]any{"complexity": 12}},
		{File: "a.go", RuleID: "complexity.cyclomatic", Severity: finding.SeverityWarning, Pillar: finding.PillarComplexity, Metadata: map[string]any{"complexity": 17}},
		{File: "b.go", RuleID: "complexity.cyclomatic", Severity: finding.SeverityError, Pillar: finding.PillarComplexity, Metadata: map[string]any{"complexity": 42}},
		{File: "c.go", RuleID: "size.function-length", Severity: finding.SeverityAdvisory, Pillar: finding.PillarSize},
	}, 10)

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
// Adding a design.hotspot-file finding must leave the composite and the top offender's penalty unchanged and add no design pillar.
func TestCalculateCompositeDesignFindingsAreScoreNeutral(t *testing.T) {
	base := []finding.Finding{
		{File: "hot.go", RuleID: "size.function-length", Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSize},
		{File: "hot.go", RuleID: "complexity.cyclomatic", Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarComplexity},
	}
	withDesignFinding := append(append([]finding.Finding{}, base...), finding.Finding{
		File:       "hot.go",
		RuleID:     "design.hotspot-file",
		Severity:   finding.SeverityAdvisory,
		Confidence: finding.ConfidenceHigh,
		Pillar:     finding.PillarDesign,
	})

	baseScore := Calculate(base, 10)
	withDesignScore := Calculate(withDesignFinding, 10)
	if *withDesignScore.Composite != *baseScore.Composite {
		t.Fatalf("composite score = %v, want score-neutral %v", *withDesignScore.Composite, *baseScore.Composite)
	}
	if len(withDesignScore.TopOffender) != len(baseScore.TopOffender) || withDesignScore.TopOffender[0].Penalty != baseScore.TopOffender[0].Penalty {
		t.Fatalf("top offenders changed: base=%#v composite=%#v", baseScore.TopOffender, withDesignScore.TopOffender)
	}
	if _, ok := withDesignScore.Pillars["design"]; ok {
		t.Fatalf("design pillar should be score-neutral, got pillars %#v", withDesignScore.Pillars)
	}
}

// correlatedFinding builds a per-symbol finding at a.go:Foo line 10, the coordinate clustering tests share to land findings on one symbol.
//
// It returns a high-confidence finding whose RuleID, Pillar and Severity come from ruleID, pillar and severity.
func correlatedFinding(ruleID string, pillar finding.Pillar, severity finding.Severity) finding.Finding {
	return finding.Finding{
		RuleID:     ruleID,
		Pillar:     pillar,
		Severity:   severity,
		Confidence: finding.ConfidenceHigh,
		File:       "a.go",
		Symbol:     "Foo",
		Location:   &finding.Location{Line: 10},
	}
}

// findPillarDetail returns the PillarDetail for name, failing the test if absent.
// It searches the PillarDetails of score, the calculated result, and returns the first row whose Pillar equals name.
func findPillarDetail(t *testing.T, score Score, name string) PillarDetail {
	t.Helper()
	for _, detail := range score.PillarDetails {
		if detail.Pillar == name {
			return detail
		}
	}
	t.Fatalf("pillar %q absent from %#v", name, score.PillarDetails)
	return PillarDetail{}
}

// TestCalculateClustersTwoCorrelatedFindings verifies P5 for the minimal case, one function tripping two correlated rules on one symbol.
//
// The function is long and complex, so size.function-length and complexity.cyclomatic each bill max(4)/2 = 2 instead of their full 4.
// The cluster bills 4 in total, one ratified warning, not 8, split across the two member pillars; two members keep the penalty exact in float64.
func TestCalculateClustersTwoCorrelatedFindings(t *testing.T) {
	score := Calculate([]finding.Finding{
		correlatedFinding("size.function-length", finding.PillarSize, finding.SeverityWarning),
		correlatedFinding("complexity.cyclomatic", finding.PillarComplexity, finding.SeverityWarning),
	}, 10)
	size := findPillarDetail(t, score, "size")
	complexity := findPillarDetail(t, score, "complexity")
	if size.Penalty != 2.0 || complexity.Penalty != 2.0 {
		t.Errorf("penalties = size %v, complexity %v; want 2.0 each (4/2 per member)", size.Penalty, complexity.Penalty)
	}
	if total := size.Penalty + complexity.Penalty; total != 4.0 {
		t.Errorf("cluster total = %v, want 4.0 (the single worst member, not 8)", total)
	}
	if size.Findings != 1 || complexity.Findings != 1 {
		t.Errorf("findings = size %d, complexity %d; want 1 each (every finding still counts)", size.Findings, complexity.Findings)
	}
	if want := pillarScoreFor(2, 10); *score.Composite != want {
		t.Errorf("composite = %v, want %v (both member pillars carry the same clustered weight)", *score.Composite, want)
	}
}

// TestCalculateClustersFullSymbolStack covers one function with four size and complexity warnings plus an advisory size.parameter-count finding.
//
// Summing raw weights would charge complexity 12; clustering bills each of the 5 members max 4 / 5 = 0.8, so complexity pays 2.4 and size 1.6.
// A failure flags wrong clustered pillar scores, a wrong composite mean of them, or a wrong per-pillar finding count.
func TestCalculateClustersFullSymbolStack(t *testing.T) {
	score := Calculate([]finding.Finding{
		correlatedFinding("complexity.cyclomatic", finding.PillarComplexity, finding.SeverityWarning),
		correlatedFinding("complexity.cognitive", finding.PillarComplexity, finding.SeverityWarning),
		correlatedFinding("complexity.nesting-depth", finding.PillarComplexity, finding.SeverityWarning),
		correlatedFinding("size.function-length", finding.PillarSize, finding.SeverityWarning),
		correlatedFinding("size.parameter-count", finding.PillarSize, finding.SeverityAdvisory),
	}, 10)
	if want := pillarScoreFor(2.4, 10); score.Pillars["complexity"] != want {
		t.Errorf("complexity score = %v, want %v (3 x 4/5 = 2.4 weight, not 12)", score.Pillars["complexity"], want)
	}
	if want := pillarScoreFor(1.6, 10); score.Pillars["size"] != want {
		t.Errorf("size score = %v, want %v (2 x 4/5 = 1.6 weight)", score.Pillars["size"], want)
	}
	complexity := findPillarDetail(t, score, "complexity")
	size := findPillarDetail(t, score, "size")
	if complexity.Findings != 3 || size.Findings != 2 {
		t.Errorf("findings = complexity %d, size %d; want 3 and 2 (clustering must not drop findings)", complexity.Findings, size.Findings)
	}
	if want := roundScore((pillarScoreFor(2.4, 10) + pillarScoreFor(1.6, 10)) / 2); *score.Composite != want {
		t.Errorf("composite = %v, want the mean of the two member pillars %v", *score.Composite, want)
	}
}

// TestCalculateDoesNotClusterAcrossSymbols verifies clustering keys on the symbol occurrence, so two functions in one file form two clusters.
//
// Foo and Bar each trip complexity.cyclomatic and size.function-length, and each cluster bills 4/2 = 2 per member, so complexity totals 4.
// Had the four findings merged into one cluster, each member would bill 4/4 = 1 and complexity would total 2.
func TestCalculateDoesNotClusterAcrossSymbols(t *testing.T) {
	finding10 := func(ruleID string, pillar finding.Pillar) finding.Finding {
		return finding.Finding{RuleID: ruleID, Pillar: pillar, Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, File: "a.go", Symbol: "Foo", Location: &finding.Location{Line: 10}}
	}
	finding30 := func(ruleID string, pillar finding.Pillar) finding.Finding {
		return finding.Finding{RuleID: ruleID, Pillar: pillar, Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, File: "a.go", Symbol: "Bar", Location: &finding.Location{Line: 30}}
	}
	score := Calculate([]finding.Finding{
		finding10("complexity.cyclomatic", finding.PillarComplexity),
		finding10("size.function-length", finding.PillarSize),
		finding30("complexity.cyclomatic", finding.PillarComplexity),
		finding30("size.function-length", finding.PillarSize),
	}, 10)
	complexity := findPillarDetail(t, score, "complexity")
	if complexity.Penalty != 4.0 {
		t.Errorf("complexity penalty = %v, want 4.0 (two separate clusters of 2, not one cluster of 2)", complexity.Penalty)
	}
}

// TestCalculateLoneCorrelatedFindingKeepsFullPenalty confirms a single correlated finding is not divided.
//
// A cluster needs at least two members, so one complexity finding on a symbol still bills its full warning penalty of 4.
func TestCalculateLoneCorrelatedFindingKeepsFullPenalty(t *testing.T) {
	score := Calculate([]finding.Finding{
		correlatedFinding("complexity.cyclomatic", finding.PillarComplexity, finding.SeverityWarning),
	}, 10)
	complexity := findPillarDetail(t, score, "complexity")
	if complexity.Penalty != 4.0 {
		t.Errorf("complexity penalty = %v, want 4.0 (a lone finding keeps its full ratified weight)", complexity.Penalty)
	}
}

// TestCalculateClusteringRequiresSymbolAndLine confirms two findings with neither a symbol nor a location never cluster.
//
// Two complexity findings with neither bill the full sum of 8, because clustering cannot prove they share one symbol occurrence.
func TestCalculateClusteringRequiresSymbolAndLine(t *testing.T) {
	noSymbol := func() finding.Finding {
		return finding.Finding{RuleID: "complexity.cyclomatic", Pillar: finding.PillarComplexity, Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, File: "a.go"}
	}
	score := Calculate([]finding.Finding{noSymbol(), noSymbol()}, 10)
	complexity := findPillarDetail(t, score, "complexity")
	if complexity.Penalty != 8.0 {
		t.Errorf("complexity penalty = %v, want 8.0 (no symbol/line means no clustering)", complexity.Penalty)
	}
}
