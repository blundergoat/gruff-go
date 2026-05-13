// Package scoring computes compact quality scores from analysis findings.
package scoring

import (
	"cmp"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
)

type Score struct {
	Composite   int            `json:"composite"`
	Grade       string         `json:"grade"`
	Pillars     map[string]int `json:"pillars"`
	TopOffender []FileScore    `json:"topOffenders"`
}

type FileScore struct {
	File    string `json:"file"`
	Penalty int    `json:"penalty"`
}

func Calculate(findings []finding.Finding) Score {
	pillarPenalty := map[string]int{}
	filePenalty := map[string]int{}
	for _, item := range findings {
		penalty := findingPenalty(item)
		pillarPenalty[string(item.Pillar)] += penalty
		filePenalty[item.File] += penalty
	}

	pillars := map[string]int{}
	if len(pillarPenalty) == 0 {
		return Score{Composite: 100, Grade: "A", Pillars: pillars, TopOffender: []FileScore{}}
	}

	total := 0
	for pillar, penalty := range pillarPenalty {
		score := max(0, 100-penalty)
		pillars[pillar] = score
		total += score
	}
	composite := total / len(pillars)
	return Score{
		Composite:   composite,
		Grade:       grade(composite),
		Pillars:     pillars,
		TopOffender: topOffenders(filePenalty),
	}
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

func topOffenders(filePenalty map[string]int) []FileScore {
	files := make([]FileScore, 0, len(filePenalty))
	for file, penalty := range filePenalty {
		files = append(files, FileScore{File: file, Penalty: penalty})
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
