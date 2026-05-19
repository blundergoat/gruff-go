// Package report renders gruff-go analysis results into output formats.
// This file implements the compact text summary writer used by the CLI digest.
package report

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/scoring"
)

// SummaryOptions controls the compact summary rendering.
type SummaryOptions struct {
	// Top limits the number of top rules and top file offenders shown.
	Top int
}

// WriteSummaryText renders a compact human-readable digest of the report.
// WriteSummaryText renders a compact human-readable digest of the analysis report to writer.
func WriteSummaryText(writer io.Writer, report analysis.Report, opts SummaryOptions) error {
	top := opts.Top
	if top <= 0 {
		top = 10
	}
	score := report.Score
	header := fmt.Sprintf(
		"gruff-go summary\nschema: %s\nscore: %d / 100  grade: %s\nfindings: %d total\n",
		report.SchemaVersion, score.Composite, gradeOrNA(score.Grade), report.Summary.FindingsCount,
	)
	if _, err := fmt.Fprint(writer, header); err != nil {
		return err
	}
	if err := writeScoreCoverage(writer, score); err != nil {
		return err
	}
	if err := writeSeverityCounts(writer, report.Summary.CountsBySeverity); err != nil {
		return err
	}
	if err := writePillarBreakdown(writer, score.PillarDetails); err != nil {
		return err
	}
	if err := writeTopRules(writer, computeTopRules(report, top)); err != nil {
		return err
	}
	if err := writeTopOffenders(writer, score.TopOffender, top); err != nil {
		return err
	}
	_, err := fmt.Fprintf(writer, "exit: %d\n", report.Summary.ExitCode)
	return err
}

// writeScoreCoverage emits score coverage, optional caveat, and complexity distribution scope lines.
func writeScoreCoverage(writer io.Writer, score scoring.Score) error {
	contributing := "none"
	if len(score.Coverage.ContributingPillars) > 0 {
		contributing = strings.Join(score.Coverage.ContributingPillars, ", ")
	}
	if _, err := fmt.Fprintf(writer, "score coverage: %s\n", contributing); err != nil {
		return err
	}
	if score.Coverage.Caveat != "" {
		if _, err := fmt.Fprintf(writer, "score caveat: %s\n", score.Coverage.Caveat); err != nil {
			return err
		}
	}
	if score.ComplexityDistributionScope != "" {
		if _, err := fmt.Fprintf(writer, "complexity distribution: %s\n", score.ComplexityDistributionScope); err != nil {
			return err
		}
	}
	return nil
}

// writeSeverityCounts emits the severity breakdown table for the summary digest.
func writeSeverityCounts(writer io.Writer, counts map[string]int) error {
	if _, err := fmt.Fprintln(writer, "severity:"); err != nil {
		return err
	}
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		if _, err := fmt.Fprintf(writer, "  %-8s %d\n", severity, counts[severity]); err != nil {
			return err
		}
	}
	return nil
}

// writePillarBreakdown emits each pillar's grade, score, and finding count sorted by activity.
func writePillarBreakdown(writer io.Writer, details []scoring.PillarDetail) error {
	if len(details) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(writer, "pillars:"); err != nil {
		return err
	}
	sorted := append([]scoring.PillarDetail(nil), details...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Findings != sorted[j].Findings {
			return sorted[i].Findings > sorted[j].Findings
		}
		return sorted[i].Pillar < sorted[j].Pillar
	})
	for _, pillar := range sorted {
		if _, err := fmt.Fprintf(writer, "  %-16s %s  score=%d  findings=%d\n", pillar.Pillar, gradeOrNA(pillar.Grade), pillar.Score, pillar.Findings); err != nil {
			return err
		}
	}
	return nil
}

// writeTopRules emits the most-triggered rules in descending count order.
func writeTopRules(writer io.Writer, entries []ruleCount) error {
	if len(entries) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(writer, "top rules:"); err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintf(writer, "  %4d  %s\n", entry.Count, entry.RuleID); err != nil {
			return err
		}
	}
	return nil
}

// writeTopOffenders emits up to top file offenders ordered by penalty.
func writeTopOffenders(writer io.Writer, offenders []scoring.FileScore, top int) error {
	if len(offenders) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(writer, "top offenders:"); err != nil {
		return err
	}
	count := top
	if count > len(offenders) {
		count = len(offenders)
	}
	for _, file := range offenders[:count] {
		if _, err := fmt.Fprintf(writer, "  %s  penalty=%d  findings=%d  grade=%s\n", file.File, file.Penalty, file.Findings, gradeOrNA(file.Grade)); err != nil {
			return err
		}
	}
	return nil
}

// ruleCount pairs a rule ID with the number of times it fired in the report.
type ruleCount struct {
	// RuleID identifies the rule the count applies to.
	RuleID string
	// Count is the number of findings emitted by RuleID in the report.
	Count int
}

// computeTopRules returns the top rule IDs by finding count, capped at top entries.
func computeTopRules(report analysis.Report, top int) []ruleCount {
	counts := map[string]int{}
	for _, item := range report.Findings {
		counts[item.RuleID]++
	}
	entries := make([]ruleCount, 0, len(counts))
	for id, count := range counts {
		entries = append(entries, ruleCount{RuleID: id, Count: count})
	}
	slices.SortFunc(entries, func(a, b ruleCount) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.RuleID, b.RuleID)
	})
	if len(entries) > top {
		entries = entries[:top]
	}
	return entries
}

// gradeOrNA returns grade or the placeholder "n/a" when grade is empty.
func gradeOrNA(grade string) string {
	if grade == "" {
		return "n/a"
	}
	return grade
}
