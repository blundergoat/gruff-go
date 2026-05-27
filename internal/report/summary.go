// Package report renders gruff-go analysis results into output formats.
// Compact summaries are optimized for quick terminal checks and CI log snippets.
package report

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/scoring"
)

// SummarySchemaVersion identifies the shared cross-port summary digest contract.
// All five gruff-* ports emit the same `gruff.summary.v2` shape (7-column pillar
// block sourced from BuildPillarSummaryRows); the bare prefix reflects that it
// is the canonical schema rather than a per-port one. Distinct from the analysis
// report schema so the summary digest can evolve independently.
const SummarySchemaVersion = "gruff.summary.v2"

// summaryPillarOrder enumerates every pillar surfaced in the summary digest. It
// mirrors the spec's canonical pillar list and intentionally excludes the
// design pillar, whose findings are score-neutral (see ADR-009 and
// scoring.scoreNeutralFinding).
var summaryPillarOrder = []finding.Pillar{
	finding.PillarSize,
	finding.PillarComplexity,
	finding.PillarDocumentation,
	finding.PillarSensitiveData,
	finding.PillarSecurity,
	finding.PillarTestQuality,
	finding.PillarNaming,
	finding.PillarMaintain,
	finding.PillarDeadCode,
	finding.PillarModernisation,
}

// PillarSummaryRow is a single per-pillar entry in the summary digest. It is
// serialised into the gruff.summary.v2 JSON payload and rendered into the
// canonical text Pillars block.
type PillarSummaryRow struct {
	// Pillar is the canonical pillar name (e.g. "documentation").
	Pillar string `json:"pillar"`
	// Grade is the letter grade derived from Score.
	Grade string `json:"grade"`
	// Score is the 0-100 numeric pillar score.
	Score float64 `json:"score"`
	// Applicable reports whether the pillar contributes to the composite score.
	Applicable bool `json:"applicable"`
	// Findings is the total finding count for this pillar.
	Findings int `json:"findings"`
	// Advisory is the count of advisory-severity findings.
	Advisory int `json:"advisory"`
	// Warning is the count of warning-severity findings.
	Warning int `json:"warning"`
	// Error is the count of error-severity findings.
	Error int `json:"error"`
	// Penalty is the raw unclamped score penalty accumulated for this pillar.
	// It preserves the worst-pillar ranking signal when Score floors at zero
	// (e.g. a pillar with 200 advisory findings has penalty=200, score=0).
	Penalty float64 `json:"penalty"`
}

// SummaryOptions controls the compact summary rendering.
type SummaryOptions struct {
	// Top limits the number of top rules and top file offenders shown.
	Top int
	// ScanDuration is the measured wall-clock duration of the summary scan.
	ScanDuration time.Duration
}

// WriteSummaryText renders the short human-readable digest used by the summary command.
func WriteSummaryText(writer io.Writer, report analysis.Report, opts SummaryOptions) error {
	top := opts.Top
	if top <= 0 {
		top = 10
	}
	score := report.Score
	header := fmt.Sprintf(
		"gruff-go summary\nscanned: %s (in %s)\nfiles: %d analysed, %d skipped\n",
		summaryInputs(report.Run.Inputs),
		summaryWorkingDir(report.Run.WorkingDirectory),
		report.Summary.FilesScanned, report.Summary.FilesSkipped,
	)
	if _, err := fmt.Fprint(writer, header); err != nil {
		return err
	}
	if gitignored := countGitignored(report.Paths.Skipped); gitignored > 0 {
		if _, err := fmt.Fprintf(writer, "  ignored by .gitignore: %d\n", gitignored); err != nil {
			return err
		}
	}
	if opts.ScanDuration > 0 {
		if _, err := fmt.Fprintf(writer, "scan time: %s\n", summaryDuration(opts.ScanDuration)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "schema: %s\nscore: %d / 100  grade: %s\nfindings: %d total\n", report.SchemaVersion, score.Composite, gradeOrNA(score.Grade), report.Summary.FindingsCount); err != nil {
		return err
	}
	if err := writeScoreCoverage(writer, score); err != nil {
		return err
	}
	if err := writeSeverityCounts(writer, report.Summary.CountsBySeverity); err != nil {
		return err
	}
	if err := writePillarsBlock(writer, BuildPillarSummaryRows(report)); err != nil {
		return err
	}
	if err := writeTopRules(writer, computeTopRules(report, top)); err != nil {
		return err
	}
	if err := writeTopOffenders(writer, score.TopOffender, top); err != nil {
		return err
	}
	if err := writeFreshStartHint(writer, report); err != nil {
		return err
	}
	_, err := fmt.Fprintf(writer, "exit: %d\n", report.Summary.ExitCode)
	return err
}

// WriteSummaryV01JSON writes the gruff.summary.v2 digest payload used by the
// `summary --format=json` command. The payload is intentionally smaller than
// the analysis schema: callers that need the full per-finding report should
// use `analyse --format=json` or `analyse --format=summary-json`.
func WriteSummaryV01JSON(writer io.Writer, report analysis.Report) error {
	payload := struct {
		SchemaVersion string             `json:"schemaVersion"`
		Pillars       []PillarSummaryRow `json:"pillars"`
	}{
		SchemaVersion: SummarySchemaVersion,
		Pillars:       BuildPillarSummaryRows(report),
	}
	return WriteJSON(writer, payload)
}

// writeFreshStartHint gives first-run users a concrete baseline workflow when
// the summary found existing debt and no baseline was applied.
func writeFreshStartHint(writer io.Writer, report analysis.Report) error {
	if report.Summary.FindingsCount == 0 || report.Baseline.Applied {
		return nil
	}
	inputs := summaryCommandInputs(report.Run.Inputs)
	if _, err := fmt.Fprintf(writer, "fresh start: gruff-go analyse --generate-baseline gruff-baseline.json %s\n", inputs); err != nil {
		return err
	}
	_, err := fmt.Fprintf(writer, "then scan with: gruff-go analyse --baseline gruff-baseline.json %s\n", inputs)
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
	for _, severity := range []string{"error", "warning", "advisory"} {
		if _, err := fmt.Fprintf(writer, "  %-8s %d\n", severity, counts[severity]); err != nil {
			return err
		}
	}
	return nil
}

// BuildPillarSummaryRows returns the canonical per-pillar rows used by the
// summary digest in both text and JSON output. Every applicable pillar is
// included (clean pillars surface as grade A with zero findings) so the rendered
// block always covers the same row set across runs. Rows are sorted by findings
// descending, with ties broken by pillar name ascending.
func BuildPillarSummaryRows(report analysis.Report) []PillarSummaryRow {
	details := map[string]scoring.PillarDetail{}
	for _, detail := range report.Score.PillarDetails {
		details[detail.Pillar] = detail
	}
	rows := make([]PillarSummaryRow, 0, len(summaryPillarOrder))
	for _, pillar := range summaryPillarOrder {
		name := string(pillar)
		row := PillarSummaryRow{
			Pillar:     name,
			Grade:      "A",
			Score:      100.0,
			Applicable: true,
		}
		if detail, ok := details[name]; ok {
			row.Grade = summaryGrade(detail.Score)
			row.Score = float64(detail.Score)
			row.Findings = detail.Findings
			row.Advisory = detail.Advisory
			row.Warning = detail.Warning
			row.Error = detail.Error
			row.Penalty = detail.Penalty
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Findings != rows[j].Findings {
			return rows[i].Findings > rows[j].Findings
		}
		return rows[i].Pillar < rows[j].Pillar
	})
	return rows
}

// writePillarsBlock emits the canonical Pillars block defined by the cross-port
// summary harmonisation spec. Column widths follow the rust port's reference
// implementation: each per-severity cell pads its numeric value to the maximum
// digit width seen across findings/advisory/warning, with three literal spaces
// between cells.
func writePillarsBlock(writer io.Writer, rows []PillarSummaryRow) error {
	if _, err := fmt.Fprintln(writer, "Pillars"); err != nil {
		return err
	}
	if len(rows) == 0 {
		_, err := fmt.Fprintln(writer, "  (none)")
		return err
	}
	nameWidth := 0
	countWidth := 1
	for _, row := range rows {
		if width := len(row.Pillar); width > nameWidth {
			nameWidth = width
		}
		for _, value := range []int{row.Findings, row.Advisory, row.Warning} {
			if width := summaryDigitWidth(value); width > countWidth {
				countWidth = width
			}
		}
	}
	rowFormat := fmt.Sprintf(
		"  %%-%ds %%s %%6.2f findings=%%-%dd   advisory=%%-%dd   warning=%%-%dd   error=%%d\n",
		nameWidth, countWidth, countWidth, countWidth,
	)
	for _, row := range rows {
		if _, err := fmt.Fprintf(writer, rowFormat, row.Pillar, row.Grade, row.Score, row.Findings, row.Advisory, row.Warning, row.Error); err != nil {
			return err
		}
	}
	return nil
}

// summaryDigitWidth returns the number of decimal digits needed to render value,
// matching the rust port's digit_width helper (zero takes one column).
func summaryDigitWidth(value int) int {
	if value <= 0 {
		return 1
	}
	width := 0
	for value > 0 {
		value /= 10
		width++
	}
	return width
}

// summaryGrade mirrors the scoring package's unexported grade ladder so the
// summary renderer can grade pillars that did not produce a PillarDetail entry.
func summaryGrade(score int) string {
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

// summaryInputs renders the run's input paths for the scanned line, falling back to "." when the slice is empty.
func summaryInputs(inputs []string) string {
	if len(inputs) == 0 {
		return "."
	}
	return strings.Join(inputs, ", ")
}

// summaryCommandInputs renders input paths as command arguments for copy/paste hints.
func summaryCommandInputs(inputs []string) string {
	if len(inputs) == 0 {
		return "."
	}
	args := make([]string, 0, len(inputs))
	for _, input := range inputs {
		if strings.HasPrefix(input, "-") || strings.ContainsAny(input, " \t\n\"'`$&;|()<>") {
			args = append(args, strconv.Quote(input))
			continue
		}
		args = append(args, input)
	}
	return strings.Join(args, " ")
}

// summaryWorkingDir renders the absolute working directory for the scanned line, returning "?" when the field is empty.
func summaryWorkingDir(dir string) string {
	if dir == "" {
		return "?"
	}
	return dir
}

// summaryDuration renders scan durations without Unicode unit symbols so CLI
// output remains portable in plain terminals and logs.
func summaryDuration(duration time.Duration) string {
	if duration < time.Millisecond {
		return "<1ms"
	}
	if duration < time.Second {
		return fmt.Sprintf("%dms", duration.Milliseconds())
	}
	if duration < time.Minute {
		return fmt.Sprintf("%.1fs", duration.Seconds())
	}
	minutes := int(duration / time.Minute)
	remainder := duration - time.Duration(minutes)*time.Minute
	return fmt.Sprintf("%dm %.1fs", minutes, remainder.Seconds())
}
