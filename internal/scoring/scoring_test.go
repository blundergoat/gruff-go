// Package scoring tests the quality totals shown in CLI and machine reports.
// Crafted findings keep score changes predictable for users comparing scans.
// The suite also protects the aggregate from moving backwards after a fix.
package scoring

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
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

// TestCalculateCompositeCountsCleanRuleBackedPillars expects clean product areas
// to contribute 100 instead of disappearing from the score shown to the user.
func TestCalculateCompositeCountsCleanRuleBackedPillars(t *testing.T) {
	registeredPillars := registeredRuleBackedPillars(t)
	pillarCount := len(registeredPillars)
	findings := []finding.Finding{
		{File: "size.go", Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSize},
		{File: "complex.go", Severity: finding.SeverityError, Confidence: finding.ConfidenceMedium, Pillar: finding.PillarComplexity},
	}

	score := Calculate(findings, registeredPillars...)
	want := (92 + 78 + 100*(pillarCount-2)) / pillarCount
	// A different value means the headline omitted at least one clean rule-backed area.
	if score.Composite != want {
		t.Fatalf("composite = %d, want %d across %d rule-backed pillars", score.Composite, want, pillarCount)
	}
}

// TestCalculateCompositeNeverDropsWhenFindingRemoved protects the user journey
// where resolving any one finding must not make the headline quality score worse.
func TestCalculateCompositeNeverDropsWhenFindingRemoved(t *testing.T) {
	registeredPillars := registeredRuleBackedPillars(t)
	findings := []finding.Finding{
		{File: "size.go", Severity: finding.SeverityError, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSize},
		{File: "size.go", Severity: finding.SeverityError, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSize},
		{File: "docs.go", Severity: finding.SeverityAdvisory, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarDocumentation},
	}
	before := Calculate(findings, registeredPillars...).Composite

	// Try every possible single remediation because users can clear findings in any order.
	for removedIndex := range findings {
		remaining := append([]finding.Finding(nil), findings[:removedIndex]...)
		remaining = append(remaining, findings[removedIndex+1:]...)
		after := Calculate(remaining, registeredPillars...).Composite
		// A lower score would punish the user for completing a remediation.
		if after < before {
			t.Errorf("removing finding %d lowered composite from %d to %d", removedIndex, before, after)
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
	before := Calculate(findings, registeredPillars...).Composite
	after := Calculate(findings[:2], registeredPillars...).Composite

	// The quality total must rise or stay level after the documentation pillar becomes clean.
	if after < before {
		t.Fatalf("clearing the final documentation finding lowered composite from %d to %d", before, after)
	}
}

// TestCalculateCompositeTruncatesIntegerMean pins the existing integer contract:
// fractional composite values truncate toward zero instead of rounding half-up.
func TestCalculateCompositeTruncatesIntegerMean(t *testing.T) {
	registeredPillars := registeredRuleBackedPillars(t)
	pillarCount := len(registeredPillars)
	score := Calculate([]finding.Finding{{
		File:       "docs.go",
		Severity:   finding.SeverityAdvisory,
		Confidence: finding.ConfidenceHigh,
		Pillar:     finding.PillarDocumentation,
	}}, registeredPillars...)
	want := (99 + 100*(pillarCount-1)) / pillarCount

	// A one-point finding leaves a fractional mean that proves truncation to CLI users.
	if score.Composite != want {
		t.Fatalf("composite = %d, want truncated integer mean %d", score.Composite, want)
	}
}

// registeredRuleBackedPillars derives the product areas from the live catalogue.
// Tests follow new areas without hardcoding names or hiding opt-in rules.
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
		RuleID:     "design.hotspot-file",
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

// correlatedFinding builds a per-symbol finding anchored at a.go:Foo line 10,
// the shared coordinate the clustering tests use to land findings on one symbol.
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

// TestCalculateClustersTwoCorrelatedFindings verifies P5 for the minimal case:
// a function that is both long and complex trips size.function-length and
// complexity.cyclomatic on one symbol. Each member contributes max(8)/2 = 4, so
// the cluster bills 8 total (one warning) instead of 16, split across the two
// member pillars. len 2 keeps the penalty exact in float64.
func TestCalculateClustersTwoCorrelatedFindings(t *testing.T) {
	score := Calculate([]finding.Finding{
		correlatedFinding("size.function-length", finding.PillarSize, finding.SeverityWarning),
		correlatedFinding("complexity.cyclomatic", finding.PillarComplexity, finding.SeverityWarning),
	})
	size := findPillarDetail(t, score, "size")
	complexity := findPillarDetail(t, score, "complexity")
	if size.Penalty != 4.0 || complexity.Penalty != 4.0 {
		t.Errorf("penalties = size %v, complexity %v; want 4.0 each (8/2 per member)", size.Penalty, complexity.Penalty)
	}
	if total := size.Penalty + complexity.Penalty; total != 8.0 {
		t.Errorf("cluster total = %v, want 8.0 (the single worst member, not 16)", total)
	}
	if size.Findings != 1 || complexity.Findings != 1 {
		t.Errorf("findings = size %d, complexity %d; want 1 each (every finding still counts)", size.Findings, complexity.Findings)
	}
	if score.Composite != 96 {
		t.Errorf("composite = %d, want 96 ((96+96)/2)", score.Composite)
	}
}

// TestCalculateClustersFullSymbolStack verifies the realistic case: one function
// trips all four warning-level size/complexity rules plus an advisory
// parameter-count finding. Summing raw penalties would score complexity at
// 100-24=76; clustering (max 8 / 5 members = 1.6 each) lifts it to 95, proving
// correlated findings bill once. Asserts integer scores to stay free of float
// rounding noise, and confirms every finding still counts toward its pillar.
func TestCalculateClustersFullSymbolStack(t *testing.T) {
	score := Calculate([]finding.Finding{
		correlatedFinding("complexity.cyclomatic", finding.PillarComplexity, finding.SeverityWarning),
		correlatedFinding("complexity.cognitive", finding.PillarComplexity, finding.SeverityWarning),
		correlatedFinding("complexity.nesting-depth", finding.PillarComplexity, finding.SeverityWarning),
		correlatedFinding("size.function-length", finding.PillarSize, finding.SeverityWarning),
		correlatedFinding("size.parameter-count", finding.PillarSize, finding.SeverityAdvisory),
	})
	if score.Pillars["complexity"] != 95 {
		t.Errorf("complexity score = %d, want 95 (3 x 8/5 = 4.8 penalty, not 24)", score.Pillars["complexity"])
	}
	if score.Pillars["size"] != 97 {
		t.Errorf("size score = %d, want 97 (2 x 8/5 = 3.2 penalty)", score.Pillars["size"])
	}
	complexity := findPillarDetail(t, score, "complexity")
	size := findPillarDetail(t, score, "size")
	if complexity.Findings != 3 || size.Findings != 2 {
		t.Errorf("findings = complexity %d, size %d; want 3 and 2 (clustering must not drop findings)", complexity.Findings, size.Findings)
	}
	if score.Composite != 96 {
		t.Errorf("composite = %d, want 96 ((95+97)/2)", score.Composite)
	}
}

// TestCalculateDoesNotClusterAcrossSymbols verifies clustering keys on the symbol
// occurrence: two distinct functions that each trip the same two correlated rules
// form two clusters, not one. Each cluster bills 8/2 = 4 per member, so complexity
// totals 8 (4 from each function) - had the four findings merged into one cluster,
// each member would be 8/4 = 2 and complexity would total 4.
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
	})
	complexity := findPillarDetail(t, score, "complexity")
	if complexity.Penalty != 8.0 {
		t.Errorf("complexity penalty = %v, want 8.0 (two separate clusters of 4, not one cluster of 4)", complexity.Penalty)
	}
}

// TestCalculateLoneCorrelatedFindingKeepsFullPenalty confirms a single correlated
// finding is not divided: a cluster needs at least two members, so one complexity
// finding on a symbol still bills its full warning penalty.
func TestCalculateLoneCorrelatedFindingKeepsFullPenalty(t *testing.T) {
	score := Calculate([]finding.Finding{
		correlatedFinding("complexity.cyclomatic", finding.PillarComplexity, finding.SeverityWarning),
	})
	complexity := findPillarDetail(t, score, "complexity")
	if complexity.Penalty != 8.0 {
		t.Errorf("complexity penalty = %v, want 8.0 (a lone finding keeps its full penalty)", complexity.Penalty)
	}
}

// TestCalculateClusteringRequiresSymbolAndLine confirms findings without a symbol
// (and a line) never cluster: two complexity findings with no symbol bill the full
// sum, because clustering can't prove they share one symbol occurrence.
func TestCalculateClusteringRequiresSymbolAndLine(t *testing.T) {
	noSymbol := func() finding.Finding {
		return finding.Finding{RuleID: "complexity.cyclomatic", Pillar: finding.PillarComplexity, Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, File: "a.go"}
	}
	score := Calculate([]finding.Finding{noSymbol(), noSymbol()})
	complexity := findPillarDetail(t, score, "complexity")
	if complexity.Penalty != 16.0 {
		t.Errorf("complexity penalty = %v, want 16.0 (no symbol/line means no clustering)", complexity.Penalty)
	}
}
