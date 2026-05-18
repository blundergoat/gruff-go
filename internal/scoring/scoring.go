// Package scoring computes compact quality scores from analysis findings.
package scoring

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
)

type Score struct {
	Composite                   int            `json:"composite"`
	Grade                       string         `json:"grade"`
	Pillars                     map[string]int `json:"pillars"`
	PillarDetails               []PillarDetail `json:"pillarDetails"`
	Coverage                    ScoreCoverage  `json:"coverage"`
	TopOffender                 []FileScore    `json:"topOffenders"`
	ComplexityDistribution      map[string]int `json:"complexityDistribution"`
	ComplexityDistributionScope string         `json:"complexityDistributionScope"`
}

type ScoreCoverage struct {
	ContributingPillars []string `json:"contributingPillars"`
	Caveat              string   `json:"caveat,omitempty"`
}

type PillarDetail struct {
	Pillar   string `json:"pillar"`
	Score    int    `json:"score"`
	Grade    string `json:"grade"`
	Findings int    `json:"findings"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
}

type FileScore struct {
	File          string `json:"file"`
	Penalty       int    `json:"penalty"`
	Findings      int    `json:"findings"`
	Grade         string `json:"grade"`
	MaxCyclomatic *int   `json:"maxCyclomatic,omitempty"`
}

const complexityCyclomaticRuleID = "complexity.cyclomatic"
const complexityDistributionScopeFindingOnly = "finding-only"

func Calculate(findings []finding.Finding) Score {
	pillarPenalty := map[string]int{}
	filePenalty := map[string]int{}
	fileFindings := map[string]int{}
	fileMaxCyclomatic := map[string]int{}
	pillarCounts := map[string]*PillarDetail{}
	for _, findingItem := range findings {
		if scoreNeutralFinding(findingItem) {
			continue
		}
		penalty := findingPenalty(findingItem)
		pillar := string(findingItem.Pillar)
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

	distribution := emptyComplexityDistribution()
	for _, findingItem := range findings {
		if findingItem.RuleID != complexityCyclomaticRuleID {
			continue
		}
		value, ok := metadataInt(findingItem.Metadata, "complexity")
		if !ok {
			continue
		}
		distribution[complexityBin(value)]++
	}

	pillars := map[string]int{}
	if len(pillarPenalty) == 0 {
		return Score{
			Composite:                   100,
			Grade:                       "A",
			Pillars:                     pillars,
			PillarDetails:               []PillarDetail{},
			Coverage:                    scoreCoverage(pillarPenalty),
			TopOffender:                 []FileScore{},
			ComplexityDistribution:      distribution,
			ComplexityDistributionScope: complexityDistributionScopeFindingOnly,
		}
	}

	total := 0
	for pillar, penalty := range pillarPenalty {
		score := max(0, 100-penalty)
		pillars[pillar] = score
		total += score
	}
	composite := total / len(pillars)
	for pillar, detail := range pillarCounts {
		detail.Score = pillars[pillar]
		detail.Grade = grade(detail.Score)
	}
	return Score{
		Composite:                   composite,
		Grade:                       grade(composite),
		Pillars:                     pillars,
		PillarDetails:               collectPillarDetails(pillarCounts),
		Coverage:                    scoreCoverage(pillarPenalty),
		TopOffender:                 topOffenders(filePenalty, fileFindings, fileMaxCyclomatic),
		ComplexityDistribution:      distribution,
		ComplexityDistributionScope: complexityDistributionScopeFindingOnly,
	}
}

func scoreCoverage(pillarPenalty map[string]int) ScoreCoverage {
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

func pluralise(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func findingPenalty(item finding.Finding) int {
	base := map[finding.Severity]int{
		finding.SeverityInfo:     1,
		finding.SeverityLow:      3,
		finding.SeverityMedium:   8,
		finding.SeverityHigh:     15,
		finding.SeverityCritical: 30,
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

func scoreNeutralFinding(item finding.Finding) bool {
	return strings.HasPrefix(item.RuleID, "design.")
}

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

func topOffenders(filePenalty, fileFindings, fileMaxCyclomatic map[string]int) []FileScore {
	files := make([]FileScore, 0, len(filePenalty))
	for file, penalty := range filePenalty {
		score := max(0, 100-penalty)
		entry := FileScore{
			File:     file,
			Penalty:  penalty,
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

func incrementSeverity(detail *PillarDetail, severity finding.Severity) {
	switch severity {
	case finding.SeverityCritical:
		detail.Critical++
	case finding.SeverityHigh:
		detail.High++
	case finding.SeverityMedium:
		detail.Medium++
	case finding.SeverityLow:
		detail.Low++
	case finding.SeverityInfo:
		detail.Info++
	}
}

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

func emptyComplexityDistribution() map[string]int {
	return map[string]int{
		"1-5":   0,
		"6-10":  0,
		"11-15": 0,
		"16-20": 0,
		"21+":   0,
	}
}

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
