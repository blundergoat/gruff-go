// Package scoring turns scanner findings into the quality totals users see.
// It keeps per-pillar and per-file evidence alongside the headline grade.
// Reports use these values to show whether a remediation improved the project.
package scoring

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// Score is the top-level scoring payload rendered into the analysis report.
type Score struct {
	// Composite is the mean of every applicable pillar, at two decimals.
	// It is nil when nothing was evaluated: an empty project has no health to report,
	// and scoring it 100 would reward pointing the tool at an empty directory.
	Composite *float64 `json:"composite"`
	// Grade is the letter grade derived from Composite, nil whenever Composite is.
	Grade *string `json:"grade"`
	// EvaluatedFiles is the ratified scoring denominator: Go files that survived the
	// ignore rules and parsed. It is published so a reader can reproduce the score,
	// and it is deliberately not Summary.FilesScanned, which counts every input.
	EvaluatedFiles *int `json:"evaluatedFiles"`
	// ScoredPillars lists every pillar the rule catalogue can reach, sorted. The composite
	// denominator comes from this set, never from the pillars that produced findings.
	ScoredPillars []string `json:"scoredPillars"`
	// Clusters lists every correlated concept that billed one shared weight, so a reader can
	// see which findings the grade counted once rather than inferring it from a lower total.
	Clusters []Cluster `json:"clusters"`
	// RuleAttribution reports how much weight each native rule removed from the score.
	// The key is the native ruleId: conceptId may group reporting, but never attribution.
	RuleAttribution []RuleWeight `json:"ruleAttribution"`
	// Pillars maps each finding-bearing pillar name to its 0-100 score.
	Pillars map[string]float64 `json:"pillars"`
	// PillarDetails is the sorted per-pillar breakdown including severity counts.
	PillarDetails []PillarDetail `json:"pillarDetails"`
	// Coverage describes where deductions came from and limits what a clean area proves.
	Coverage ScoreCoverage `json:"coverage"`
	// TopOffender lists the highest-penalty files in descending order.
	TopOffender []FileScore `json:"topOffenders"`
	// ComplexityDistribution buckets cyclomatic complexity findings by range.
	ComplexityDistribution map[string]int `json:"complexityDistribution"`
	// ComplexityDistributionScope labels how ComplexityDistribution was built (e.g. "finding-only").
	ComplexityDistributionScope string `json:"complexityDistributionScope"`
}

// ScoreCoverage shows users which pillars produced score deductions.
// It is evidence coverage, not the set used as the composite denominator.
type ScoreCoverage struct {
	// ContributingPillars lists, sorted, the pillars that produced score-impacting findings.
	ContributingPillars []string `json:"contributingPillars"`
	// Caveat is an optional sentence explaining limited coverage of the score.
	Caveat string `json:"caveat,omitempty"`
}

// PillarDetail breaks down findings and grade for a single quality pillar.
// The Advisory/Warning/Error fields replace the pre-ADR-009 5-bucket counters.
type PillarDetail struct {
	// Pillar is the pillar name (e.g. "complexity", "documentation").
	Pillar string `json:"pillar"`
	// Applicable reports whether any rule in the catalogue can reach this pillar.
	// It separates "reachable and clean", which scores 100, from "nothing can reach it",
	// which has no opinion and is excluded from the composite rather than averaged as perfect.
	Applicable bool `json:"applicable"`
	// Score is the score for this pillar between the ratified floor and 100, nil when not applicable.
	Score *float64 `json:"score"`
	// Grade is the letter grade derived from Score, nil whenever Score is.
	Grade *string `json:"grade"`
	// Findings is the total number of findings counted against this pillar.
	Findings int `json:"findings"`
	// Advisory is the count of advisory-severity findings in this pillar.
	Advisory int `json:"advisory"`
	// Warning is the count of warning-severity findings in this pillar.
	Warning int `json:"warning"`
	// Error is the count of error-severity findings in this pillar.
	Error int `json:"error"`
	// Penalty is the raw unclamped score penalty accumulated for this pillar.
	// Score is derived as max(0, 100-Penalty); the raw value preserves the
	// worst-pillar ranking signal for pillars whose score floors at zero.
	Penalty float64 `json:"penalty"`
}

// Cluster is one correlated concept whose members share a single score weight.
type Cluster struct {
	// File is the project-relative path the clustered findings share.
	File string `json:"file"`
	// Symbol is the symbol they share; the cluster key is (File, Symbol) with no line identity.
	Symbol string `json:"symbol"`
	// RuleIDs lists the native rule identifiers in the cluster, sorted.
	RuleIDs []string `json:"ruleIds"`
	// Findings is how many findings the cluster holds; always at least two.
	Findings int `json:"findings"`
	// Weight is the total weight the cluster billed, which is its single worst member.
	Weight float64 `json:"weight"`
}

// RuleWeight reports one native rule's contribution to the score.
type RuleWeight struct {
	// RuleID is the native rule identifier, the ratified attribution key.
	RuleID string `json:"ruleId"`
	// Findings is how many findings this rule produced that the score counted.
	Findings int `json:"findings"`
	// Weight is the summed post-clustering weight this rule removed from the score.
	Weight float64 `json:"weight"`
}

// FileScore reports the penalty, finding count, score, and grade for a single file.
type FileScore struct {
	// File is the repo-relative path of the source file.
	File string `json:"file"`
	// Penalty is the summed ratified weight across all findings in File.
	Penalty float64 `json:"penalty"`
	// Findings is the total number of findings emitted against File.
	Findings int `json:"findings"`
	// Score is the ratified curve applied to this file's own weighted findings, so a
	// file score and a project score share one shape and top-offender ranking stays comparable.
	Score float64 `json:"score"`
	// Grade is the letter grade derived from the file's score.
	Grade string `json:"grade"`
	// MaxCyclomatic is the highest cyclomatic complexity recorded for File, omitted when no complexity finding fired.
	MaxCyclomatic *int `json:"maxCyclomatic,omitempty"`
}

// Ratified family scoring parameters. The shape is bounded-normalized-density-floored, ratified
// 2026-09-01 (specification contracts/core/scoring-shape.v1.json); these values were ratified
// 2026-09-03 (contracts/core/scoring-parameters.v1.json) and are identical in all five ports.
// Changing any of them is a family decision, not a gruff-go decision.
const (
	scoreFloor             = 50.0
	densityScale           = 0.1
	severityWeightAdvisory = 1.0
	severityWeightWarning  = 4.0
	severityWeightError    = 12.0
	confidenceWeightLow    = 0.5
	confidenceWeightMedium = 0.75
	confidenceWeightHigh   = 1.0
)

// complexityCyclomaticRuleID is the rule whose findings feed the complexity histogram.
const complexityCyclomaticRuleID = "complexity.cyclomatic"

// complexityDistributionScopeFindingOnly marks histograms built from findings only.
const complexityDistributionScopeFindingOnly = "finding-only"

// Calculate builds the score users see from findings, the evaluated-file denominator, and the
// registered pillar set. An empty pillar set falls back to finding pillars for programmatic callers.
//
// evaluatedFiles is the ratified denominator, and zero means nothing was evaluated: every pillar and
// the composite are then nil rather than 100, because an empty scan has no health to report.
func Calculate(findings []finding.Finding, evaluatedFiles int, ruleBackedPillars ...finding.Pillar) Score {
	penalties := clusterPenalties(findings)
	compositePillars := make(map[string]struct{}, len(ruleBackedPillars))
	// Every registered product area starts clean so one noisy area cannot hide the rest.
	for _, pillar := range ruleBackedPillars {
		compositePillars[string(pillar)] = struct{}{}
	}
	pillarPenalty := map[string]float64{}
	filePenalty := map[string]float64{}
	fileFindings := map[string]int{}
	fileMaxCyclomatic := map[string]int{}
	pillarCounts := map[string]*PillarDetail{}
	for index, findingItem := range findings {
		if scoreNeutralFinding(findingItem) {
			continue
		}
		penalty := penalties[index]
		pillar := string(findingItem.Pillar)
		// A custom caller may report a valid finding before supplying registry metadata.
		compositePillars[pillar] = struct{}{}
		pillarPenalty[pillar] += penalty
		filePenalty[findingItem.File] += penalty
		fileFindings[findingItem.File]++

		if pillarCounts[pillar] == nil {
			pillarCounts[pillar] = &PillarDetail{Pillar: pillar}
		}
		pillarCounts[pillar].Findings++
		incrementSeverity(pillarCounts[pillar], findingItem.Severity)

		if findingItem.RuleID == complexityCyclomaticRuleID {
			if value, ok := metadataInt(findingItem.Metadata, "complexity"); ok {
				if existing, seen := fileMaxCyclomatic[findingItem.File]; !seen || value > existing {
					fileMaxCyclomatic[findingItem.File] = value
				}
			}
		}
	}

	scoredPillars := sortedPillarNames(compositePillars)
	scored := scorePillars(scoredPillars, pillarCounts, pillarPenalty, evaluatedFiles)
	evaluated := evaluatedFiles
	score := Score{
		// The denominator is published even when it is zero: a reader needs to see that nothing was
		// evaluated, and a missing key would be indistinguishable from a port that never computed one.
		EvaluatedFiles:              &evaluated,
		Clusters:                    collectClusters(findings, penalties),
		RuleAttribution:             collectRuleAttribution(findings, penalties),
		Pillars:                     scored.findingBearing,
		ScoredPillars:               scoredPillars,
		PillarDetails:               collectPillarDetails(pillarCounts),
		Coverage:                    scoreCoverage(pillarPenalty),
		TopOffender:                 topOffenders(filePenalty, fileFindings, fileMaxCyclomatic),
		ComplexityDistribution:      complexityFindingDistribution(findings),
		ComplexityDistributionScope: complexityDistributionScopeFindingOnly,
	}

	// A run with nothing evaluated, or with no reachable pillar, reports null throughout rather than
	// a perfect score. Publishing 100 here is what let an empty directory grade A before this break.
	if scored.count == 0 {
		return score
	}

	compositeScore := roundScore(scored.total / float64(scored.count))
	compositeGrade := grade(compositeScore)
	score.Composite = &compositeScore
	score.Grade = &compositeGrade
	return score
}

// pillarScoreTotals carries what the composite needs from the per-pillar pass.
type pillarScoreTotals struct {
	// findingBearing maps each pillar that produced findings to its score.
	findingBearing map[string]float64
	// total sums every applicable pillar score, and count is how many entered that sum.
	total float64
	count int
}

// scorePillars fills in one detail row per scored pillar and returns the composite's inputs.
// Every scored pillar gets a row whether or not it produced findings, so a reader can tell a
// reachable clean pillar from one no rule can reach. With nothing evaluated no pillar has an
// opinion, so each row keeps a nil score and none enters the composite.
func scorePillars(scoredPillars []string, pillarCounts map[string]*PillarDetail, pillarPenalty map[string]float64, evaluatedFiles int) pillarScoreTotals {
	totals := pillarScoreTotals{findingBearing: map[string]float64{}}
	for _, pillar := range scoredPillars {
		if pillarCounts[pillar] == nil {
			pillarCounts[pillar] = &PillarDetail{Pillar: pillar}
		}
		detail := pillarCounts[pillar]
		detail.Applicable = true
		detail.Penalty = pillarPenalty[pillar]
		if evaluatedFiles <= 0 {
			continue
		}

		pillarScore := pillarScoreFor(pillarPenalty[pillar], evaluatedFiles)
		pillarGrade := grade(pillarScore)
		detail.Score = &pillarScore
		detail.Grade = &pillarGrade
		if _, bearing := pillarPenalty[pillar]; bearing {
			totals.findingBearing[pillar] = pillarScore
		}
		totals.total += pillarScore
		totals.count++
	}
	return totals
}

// sortedPillarNames returns the scored pillar set as a stable sorted list.
func sortedPillarNames(pillars map[string]struct{}) []string {
	names := make([]string, 0, len(pillars))
	for pillar := range pillars {
		names = append(names, pillar)
	}
	slices.Sort(names)
	return names
}

// complexityFindingDistribution builds the finding-only histogram shown in reports.
// Missing or unrelated metadata leaves the user's corresponding bins at zero.
func complexityFindingDistribution(findings []finding.Finding) map[string]int {
	distribution := emptyComplexityDistribution()
	// Only cyclomatic findings carry values that belong in this user-facing chart.
	for _, findingItem := range findings {
		// Ignore other rules because their findings have no cyclomatic value to chart.
		if findingItem.RuleID != complexityCyclomaticRuleID {
			continue
		}
		complexity, hasComplexity := metadataInt(findingItem.Metadata, "complexity")
		// A missing value means the scanner has no measurement to chart for this finding.
		if !hasComplexity {
			continue
		}
		distribution[complexityBin(complexity)]++
	}
	return distribution
}

// scoreCoverage names the pillars responsible for deductions and any evidence caveat.
func scoreCoverage(pillarPenalty map[string]float64) ScoreCoverage {
	pillars := make([]string, 0, len(pillarPenalty))
	for pillar := range pillarPenalty {
		pillars = append(pillars, pillar)
	}
	slices.Sort(pillars)
	coverage := ScoreCoverage{ContributingPillars: pillars}
	switch len(pillars) {
	case 0:
		coverage.Caveat = "No score-impacting findings; the score reflects configured parser rules and thresholds, not exhaustive semantic proof."
	case 1, 2:
		coverage.Caveat = fmt.Sprintf(
			"Composite grade is driven by %d score-impacting %s; clean pillars mean no above-threshold findings from configured rules, not broad risk coverage.",
			len(pillars),
			pluralise(len(pillars), "pillar", "pillars"),
		)
	}
	return coverage
}

// pluralise returns the singular or plural form based on count.
func pluralise(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

// findingPenalty computes the ratified weight a single finding contributes to its pillar's density.
// Severity and confidence weights are the family-ratified values recorded in the specification's
// scoring-parameters.v1.json (M06, ratified 2026-09-03), replacing the 1/8/30 scale ADR-009 carried.
// The error weight drops 2.5x at this break, so every historical gruff-go score moves.
func findingPenalty(item finding.Finding) float64 {
	base := map[finding.Severity]float64{
		finding.SeverityAdvisory: severityWeightAdvisory,
		finding.SeverityWarning:  severityWeightWarning,
		finding.SeverityError:    severityWeightError,
	}[item.Severity]
	switch item.Confidence {
	case finding.ConfidenceLow:
		return base * confidenceWeightLow
	case finding.ConfidenceMedium:
		return base * confidenceWeightMedium
	default:
		return base * confidenceWeightHigh
	}
}

// pillarScoreFor applies the ratified curve to one pillar's summed weight.
// The curve is floor + (100-floor) / (1 + density/densityScale), where density is the pillar's
// weight divided by evaluatedFiles. Dividing before transforming is what makes a duplicated project
// score the same as the original: twice the findings over twice the code is the same ratio.
func pillarScoreFor(weight float64, evaluatedFiles int) float64 {
	// Callers must return null pillars for a project with nothing evaluated rather than reach the curve.
	if evaluatedFiles <= 0 {
		return scoreFloor
	}
	density := weight / float64(evaluatedFiles)
	return roundScore(scoreFloor + (100-scoreFloor)/(1+density/densityScale))
}

// roundScore rounds one score to the ratified two-decimal precision.
// Negative zero is normalized away because JSON projection keeps it in some ports and not others.
func roundScore(value float64) float64 {
	rounded := math.Round(value*100) / 100
	if rounded == 0 {
		return 0
	}
	return rounded
}

// scoreNeutralFinding reports whether a finding is excluded from score penalties.
func scoreNeutralFinding(item finding.Finding) bool {
	return strings.HasPrefix(item.RuleID, "design.")
}

// correlatedRuleIDs are the per-symbol size and complexity rules whose findings
// describe one root cause when they land on the same function: an over-large or
// over-branchy routine trips several at once. P5 clusters them so the grade moves
// once per function, not once per metric (ADR-018, refining ADR-017 item 8).
// File-level rules (size.file-length) and the score-neutral design composite are
// excluded - they are not per-symbol signals.
var correlatedRuleIDs = map[string]bool{
	"complexity.cyclomatic":    true,
	"complexity.cognitive":     true,
	"complexity.nesting-depth": true,
	"size.function-length":     true,
	"size.parameter-count":     true,
}

// clusterKey identifies the one symbol a correlated finding belongs to. The
// ratified contract keys clustering on project-relative file and qualified
// symbol without line identity, because correlated rules do not agree on which
// line to report: a size rule may name the declaration line while a complexity
// rule names the body, and a line in the key splits one root cause into two.
//
// The contract's key is the *qualified* symbol. gruff-go emits an unqualified
// one, so two same-named methods on different types in one file share a key and
// bill one penalty between them. That under-penalises rather than over-penalises,
// and qualifying the symbol would change finding identity, which this milestone
// is not permitted to touch.
type clusterKey struct {
	file   string
	symbol string
}

// clusterPenalties returns each finding's score penalty after P5 clustering,
// aligned by index to findings. Correlated findings (correlatedRuleIDs) that
// share one (file, symbol) are one root cause: each member contributes
// max(member base penalty)/len instead of its own, so the cluster bills the grade
// once - its total collapses to the single worst member - while every finding
// still renders and counts. Lone correlated findings and all other findings keep
// their full base penalty. Mirrors gruff-py's _finding_penalties; see ADR-018.
func clusterPenalties(findings []finding.Finding) []float64 {
	penalties := make([]float64, len(findings))
	for index, item := range findings {
		penalties[index] = float64(findingPenalty(item))
	}
	groups := map[clusterKey][]int{}
	for index, item := range findings {
		if !correlatedRuleIDs[item.RuleID] {
			continue
		}
		if item.Symbol == "" {
			continue
		}
		key := clusterKey{file: item.File, symbol: item.Symbol}
		groups[key] = append(groups[key], index)
	}
	for _, members := range groups {
		if len(members) < 2 {
			continue
		}
		shared := maxFloat(penalties, members) / float64(len(members))
		for _, index := range members {
			penalties[index] = shared
		}
	}
	return penalties
}

// collectClusters reports every correlated concept that billed one shared weight, sorted by file
// then symbol so two runs over unchanged input publish the same bytes.
func collectClusters(findings []finding.Finding, penalties []float64) []Cluster {
	groups := map[clusterKey][]int{}
	for index, item := range findings {
		if !correlatedRuleIDs[item.RuleID] || item.Symbol == "" || scoreNeutralFinding(item) {
			continue
		}
		key := clusterKey{file: item.File, symbol: item.Symbol}
		groups[key] = append(groups[key], index)
	}
	clusters := make([]Cluster, 0, len(groups))
	for key, members := range groups {
		// A lone correlated finding billed its own full weight, so it is not a cluster to report.
		if len(members) < 2 {
			continue
		}
		ruleIDs := make([]string, 0, len(members))
		weight := 0.0
		for _, index := range members {
			ruleIDs = append(ruleIDs, findings[index].RuleID)
			weight += penalties[index]
		}
		slices.Sort(ruleIDs)
		clusters = append(clusters, Cluster{
			File:     key.file,
			Symbol:   key.symbol,
			RuleIDs:  ruleIDs,
			Findings: len(members),
			Weight:   roundScore(weight),
		})
	}
	slices.SortFunc(clusters, func(a, b Cluster) int {
		if n := strings.Compare(a.File, b.File); n != 0 {
			return n
		}
		return strings.Compare(a.Symbol, b.Symbol)
	})
	return clusters
}

// collectRuleAttribution reports how much weight each native rule removed from the score, sorted by
// rule identifier. Score-neutral findings contribute nothing and are omitted, because a rule that
// cannot move the grade has no attribution to report.
func collectRuleAttribution(findings []finding.Finding, penalties []float64) []RuleWeight {
	counts := map[string]int{}
	weights := map[string]float64{}
	for index, item := range findings {
		if scoreNeutralFinding(item) {
			continue
		}
		counts[item.RuleID]++
		weights[item.RuleID] += penalties[index]
	}
	attribution := make([]RuleWeight, 0, len(counts))
	for ruleID, count := range counts {
		attribution = append(attribution, RuleWeight{RuleID: ruleID, Findings: count, Weight: roundScore(weights[ruleID])})
	}
	slices.SortFunc(attribution, func(a, b RuleWeight) int {
		return strings.Compare(a.RuleID, b.RuleID)
	})
	return attribution
}

// maxFloat returns the largest penalties entry among the given member indices.
// Members is never empty (callers guard len >= 2) and every base penalty is at
// least 1, so the zero seed is always replaced by a real penalty.
func maxFloat(penalties []float64, members []int) float64 {
	largest := 0.0
	for _, index := range members {
		if penalties[index] > largest {
			largest = penalties[index]
		}
	}
	return largest
}

// grade maps a numeric score to a letter grade. The ratified bands are an even five-way split of
// the closed composite range [floor, 100], which reproduces the boundaries gruff-go already shipped,
// so no grade band moves at this break even though every score does.
func grade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// topOffenders returns the highest-penalty files, capped at five entries.
func topOffenders(filePenalty map[string]float64, fileFindings, fileMaxCyclomatic map[string]int) []FileScore {
	files := make([]FileScore, 0, len(filePenalty))
	for file, penalty := range filePenalty {
		// A file's density is its own weighted findings, so a file score and a project score
		// share one curve and the two cannot rank the same code differently.
		score := pillarScoreFor(penalty, 1)
		entry := FileScore{
			File:     file,
			Penalty:  roundScore(penalty),
			Findings: fileFindings[file],
			Score:    score,
			Grade:    grade(score),
		}
		if value, ok := fileMaxCyclomatic[file]; ok {
			maxValue := value
			entry.MaxCyclomatic = &maxValue
		}
		files = append(files, entry)
	}
	slices.SortFunc(files, func(a, b FileScore) int {
		if n := cmp.Compare(b.Penalty, a.Penalty); n != 0 {
			return n
		}
		return strings.Compare(a.File, b.File)
	})
	if len(files) > 5 {
		files = files[:5]
	}
	return files
}

// incrementSeverity bumps the severity counter on a PillarDetail.
func incrementSeverity(detail *PillarDetail, severity finding.Severity) {
	switch severity {
	case finding.SeverityError:
		detail.Error++
	case finding.SeverityWarning:
		detail.Warning++
	case finding.SeverityAdvisory:
		detail.Advisory++
	}
}

// collectPillarDetails returns sorted PillarDetail values from the count map.
func collectPillarDetails(pillarCounts map[string]*PillarDetail) []PillarDetail {
	details := make([]PillarDetail, 0, len(pillarCounts))
	for _, detail := range pillarCounts {
		details = append(details, *detail)
	}
	slices.SortFunc(details, func(a, b PillarDetail) int {
		return strings.Compare(a.Pillar, b.Pillar)
	})
	return details
}

// emptyComplexityDistribution returns a zero-valued bucket map for complexity histograms.
func emptyComplexityDistribution() map[string]int {
	return map[string]int{
		"1-5":   0,
		"6-10":  0,
		"11-15": 0,
		"16-20": 0,
		"21+":   0,
	}
}

// complexityBin returns the histogram bucket label for a cyclomatic complexity value.
func complexityBin(complexity int) string {
	switch {
	case complexity <= 5:
		return "1-5"
	case complexity <= 10:
		return "6-10"
	case complexity <= 15:
		return "11-15"
	case complexity <= 20:
		return "16-20"
	default:
		return "21+"
	}
}

// metadataInt reads an integer value from finding metadata under the given key.
func metadataInt(metadata map[string]any, key string) (int, bool) {
	if metadata == nil {
		return 0, false
	}
	value, ok := metadata[key]
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	default:
		return 0, false
	}
}
