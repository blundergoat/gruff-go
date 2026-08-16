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
	// Composite is the truncated mean across every rule-backed pillar.
	// A pillar with no score-impacting findings contributes 100.
	Composite int `json:"composite"`
	// Grade is the letter grade derived from Composite.
	Grade string `json:"grade"`
	// Pillars maps each finding-bearing pillar name to its 0-100 score.
	Pillars map[string]int `json:"pillars"`
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
	// Score is the 0-100 score for this pillar.
	Score int `json:"score"`
	// Grade is the letter grade derived from Score.
	Grade string `json:"grade"`
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

// FileScore reports the penalty, finding count, and grade for a single file.
type FileScore struct {
	// File is the repo-relative path of the source file.
	File string `json:"file"`
	// Penalty is the summed score penalty across all findings in File.
	Penalty int `json:"penalty"`
	// Findings is the total number of findings emitted against File.
	Findings int `json:"findings"`
	// Grade is the letter grade derived from the file's penalty.
	Grade string `json:"grade"`
	// MaxCyclomatic is the highest cyclomatic complexity recorded for File, omitted when no complexity finding fired.
	MaxCyclomatic *int `json:"maxCyclomatic,omitempty"`
}

// complexityCyclomaticRuleID is the rule whose findings feed the complexity histogram.
const complexityCyclomaticRuleID = "complexity.cyclomatic"

// complexityDistributionScopeFindingOnly marks histograms built from findings only.
const complexityDistributionScopeFindingOnly = "finding-only"

// Calculate builds the score users see from findings and the registered pillar set.
// An empty pillar set falls back to finding pillars for programmatic callers.
func Calculate(findings []finding.Finding, ruleBackedPillars ...finding.Pillar) Score {
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

	distribution := complexityFindingDistribution(findings)

	findingBearingPillarScores := map[string]int{}
	if len(pillarPenalty) == 0 {
		return Score{
			Composite:                   100,
			Grade:                       "A",
			Pillars:                     findingBearingPillarScores,
			PillarDetails:               []PillarDetail{},
			Coverage:                    scoreCoverage(pillarPenalty),
			TopOffender:                 []FileScore{},
			ComplexityDistribution:      distribution,
			ComplexityDistributionScope: complexityDistributionScopeFindingOnly,
		}
	}

	compositeScoreTotal := 100 * len(compositePillars)
	// Finding-bearing pillars replace their clean 100 with the penalized score shown in details.
	for pillar, penalty := range pillarPenalty {
		pillarScore := max(0, 100-roundPenalty(penalty))
		findingBearingPillarScores[pillar] = pillarScore
		compositeScoreTotal += pillarScore - 100
	}
	// Integer division deliberately truncates the fractional headline score toward zero.
	compositeScore := compositeScoreTotal / len(compositePillars)
	for pillar, detail := range pillarCounts {
		detail.Score = findingBearingPillarScores[pillar]
		detail.Grade = grade(detail.Score)
		detail.Penalty = pillarPenalty[pillar]
	}
	return Score{
		Composite:                   compositeScore,
		Grade:                       grade(compositeScore),
		Pillars:                     findingBearingPillarScores,
		PillarDetails:               collectPillarDetails(pillarCounts),
		Coverage:                    scoreCoverage(pillarPenalty),
		TopOffender:                 topOffenders(filePenalty, fileFindings, fileMaxCyclomatic),
		ComplexityDistribution:      distribution,
		ComplexityDistributionScope: complexityDistributionScopeFindingOnly,
	}
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

// findingPenalty computes the penalty score for a single finding based on severity and confidence.
// Weights collapse the old 5-bucket scale (1/3/8/15/30 for info/low/medium/high/critical) into the
// 3-bucket model (1/8/30 for advisory/warning/error) — see ADR-009.
func findingPenalty(item finding.Finding) int {
	base := map[finding.Severity]int{
		finding.SeverityAdvisory: 1,
		finding.SeverityWarning:  8,
		finding.SeverityError:    30,
	}[item.Severity]
	switch item.Confidence {
	case finding.ConfidenceLow:
		return max(1, base/2)
	case finding.ConfidenceMedium:
		return max(1, (base*3)/4)
	default:
		return base
	}
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

// clusterKey identifies the one symbol occurrence a correlated finding belongs
// to. Two findings cluster only when all three fields match, so distinct
// functions - even same-named methods on different types, which differ in line -
// never merge into one root cause.
type clusterKey struct {
	file   string
	symbol string
	line   int
}

// clusterPenalties returns each finding's score penalty after P5 clustering,
// aligned by index to findings. Correlated findings (correlatedRuleIDs) that
// share one (file, symbol, line) are one root cause: each member contributes
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
		line := findingLine(item)
		if item.Symbol == "" || line == 0 {
			continue
		}
		key := clusterKey{file: item.File, symbol: item.Symbol, line: line}
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

// findingLine returns the finding's 1-based line, or 0 when it carries no
// location. Zero disqualifies a finding from clustering: without a line we
// cannot prove two findings share one symbol occurrence.
func findingLine(item finding.Finding) int {
	if item.Location == nil {
		return 0
	}
	return item.Location.Line
}

// roundPenalty rounds a raw float penalty to the nearest whole point for the
// integer 0-100 pillar and file scores. Clustering makes penalties fractional
// (max/len); the displayed score is integral, so round half away from zero.
func roundPenalty(penalty float64) int {
	return int(math.Round(penalty))
}

// grade maps a numeric score (0-100) to a letter grade.
func grade(score int) string {
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
		rounded := roundPenalty(penalty)
		score := max(0, 100-rounded)
		entry := FileScore{
			File:     file,
			Penalty:  rounded,
			Findings: fileFindings[file],
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
