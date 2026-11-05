// Package report renders gruff-go analysis results into output formats.
//
// This file renders the compact text digest and JSON projection that gruff-go summary prints.
// Compact summaries are optimized for quick terminal checks and CI log snippets.
package report

import (
	"fmt"
	"io"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/scoring"
)

// SummarySchemaVersion identifies the canonical gruff.summary.v3 projection of the analysis report.
//
// The summary JSON publishes scoring PillarDetails within that projection, not the BuildPillarSummaryRows rows the text digest prints.
// The bare prefix reflects that it is the canonical schema shared by all five gruff-* ports rather than a per-port one.
// It is distinct from the analysis report schema so the summary digest can evolve independently.
const SummarySchemaVersion = analysis.SummarySchemaVersion

// summaryPillarOrder enumerates every pillar that gets a row in the summary digest's Pillars block.
//
// It mirrors the spec's canonical pillar list and intentionally excludes the design pillar.
// Design findings are score-neutral, see ADR-009 and scoring.scoreNeutralFinding, so design never gets a Pillars row.
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

// PillarSummaryRow is a single per-pillar entry in the summary digest, printed as one line of the canonical text Pillars block.
//
// The summary JSON publishes scoring PillarDetails instead, so these rows and their default grade and score never reach it.
type PillarSummaryRow struct {
	// Pillar is the canonical pillar name (e.g. "documentation").
	Pillar string `json:"pillar"`
	// Grade is the letter grade derived from Score.
	Grade string `json:"grade"`
	// Score is the 0-100 numeric pillar score.
	Score float64 `json:"score"`
	// Applicable reports whether the pillar's detail is applicable and has a score; a pillar with no detail stays true.
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
	// It keeps the raw ranking signal when rounded scores tie near the density curve's floor of 50, where Score alone cannot order pillars.
	Penalty float64 `json:"penalty"`
}

// SummaryOptions controls the compact summary rendering.
//
// A zero value is valid: Top falls back to 10 entries and the scan time line is left out.
type SummaryOptions struct {
	// Top limits the number of top rules and top file offenders shown.
	Top int
	// ScanDuration is the measured wall-clock duration of the summary scan.
	ScanDuration time.Duration
}

// WriteSummaryText renders the short human-readable digest used by the summary command.
//
// The digest for report goes to writer; in opts, Top limits top rules and offenders and defaults to 10 when not positive.
// Scan time prints only when opts has a positive ScanDuration, and the first write error from writer stops output and is returned.
// The masthead and composite block always come first, and the digest ends with an exit: line carrying the run's exit code.
func WriteSummaryText(writer io.Writer, report analysis.Report, opts SummaryOptions) error {
	top := opts.Top
	if top <= 0 {
		top = 10
	}
	score := report.Score
	fileCounts := countSummaryFiles(report)
	// FAMILY-CONTRACT section 1: the masthead and the two-line composite block are the first three lines, and every port-local line sits below them.
	// Keeping the composite block directly below the masthead puts the number a reader came for where the analyse text header puts it.
	if _, err := fmt.Fprintf(writer, "%s %s summary\n", report.Tool.Name, report.Tool.Version); err != nil {
		return err
	}
	if err := writeCompositeBlock(writer, report); err != nil {
		return err
	}
	scanCard := fmt.Sprintf(
		"scanned: %s (in %s)\nfiles: %d Go parsed, %d text scanned, %d failed, %d skipped\n",
		summaryInputs(report.Run.Inputs),
		summaryWorkingDir(report.Run.WorkingDirectory),
		fileCounts.parsedGoFiles, fileCounts.scannedTextFiles, fileCounts.failedFiles, report.Summary.FilesSkipped,
	)
	if _, err := fmt.Fprint(writer, scanCard); err != nil {
		return err
	}
	if err := writeTextDiagnostics(writer, report.Diagnostics); err != nil {
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
	if _, err := fmt.Fprintf(writer, "schema: %s\n", report.SchemaVersion); err != nil {
		return err
	}
	if err := writeScoreCoverage(writer, score); err != nil {
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
	// summary applies sensitive exclusions, so it owes the same audit line analyse prints: a surface that filters may never filter in silence.
	//
	// See FAMILY-CONTRACT.md section 13a, "Where the audit must appear"; shared writeTextSuppressions keeps the wording identical.
	// The line lands below the canonical Composite and Findings block as a permitted extension line under section 1.
	if err := writeTextSuppressions(writer, report.Suppressions); err != nil {
		return err
	}
	if err := writeSummaryBaseline(writer, report.Baseline); err != nil {
		return err
	}
	if err := writeFreshStartHint(writer, report); err != nil {
		return err
	}
	_, err := fmt.Fprintf(writer, "exit: %d\n", report.Summary.ExitCode)
	return err
}

// summaryFileCounts records the scan categories shown in human-readable summary output.
// Keeping these counts internal avoids changing the versioned JSON report contract.
type summaryFileCounts struct {
	parsedGoFiles    int
	scannedTextFiles int
	failedFiles      int
}

// countSummaryFiles classifies each discovered input for the files line of the text summary, while JSON stays unchanged.
//
// The counts group inputs by extension after setting aside files with a parse-stage diagnostic.
// It returns counts from analysisReport: failedFiles holds distinct files with a parse-stage diagnostic, even ones absent from Paths.Scanned.
// Each other scanned path counts as parsed Go when its extension is .go in any case, else as scanned text; an empty report gives all zeros.
//
// A Go file over the deep-scan budget still counts as parsed Go, though its AST was skipped.
func countSummaryFiles(analysisReport analysis.Report) summaryFileCounts {
	parseFailedPaths := map[string]struct{}{}
	// One file may emit several diagnostics, so path identity keeps the failure count file-based.
	for _, diagnostic := range analysisReport.Diagnostics {
		// Parser-stage diagnostics cover both read failures and Go syntax errors before rule analysis.
		if diagnostic.Stage == "parse" && diagnostic.File != "" {
			parseFailedPaths[diagnostic.File] = struct{}{}
		}
	}

	// Explicit-file scans can diagnose a supporting Go sibling without listing it in Paths.Scanned.
	// Count every diagnosed file once before classifying the successfully scanned paths.
	fileCounts := summaryFileCounts{failedFiles: len(parseFailedPaths)}
	// Every discovered path contributes to exactly one user-visible summary category.
	for _, scannedPath := range analysisReport.Paths.Scanned {
		// A failed read or parse never reached rule analysis.
		if _, failed := parseFailedPaths[scannedPath]; failed {
			continue
		}
		// A Go input without a parse-stage diagnostic counts here, even when the deep-scan budget skipped its AST.
		if strings.EqualFold(path.Ext(scannedPath), ".go") {
			fileCounts.parsedGoFiles++
			continue
		}
		// Every other readable input was scanned by the raw-text rule set.
		fileCounts.scannedTextFiles++
	}
	return fileCounts
}

// writeSummaryBaseline prints the three-state baseline counts line when a baseline was applied to the summary run.
//
// The user sees one line such as baseline: 2 new, 40 unchanged, 1 resolved, built from NewFindings, UnchangedFindings and ResolvedFindings.
// Counts only, with no detail lists, keep the digest compact; runs without a baseline print nothing, so their summaries are unchanged.
//
// The line goes to writer only when summary has Applied set.
// It returns the write error from writer, or nil when the line is written or summary was not applied.
func writeSummaryBaseline(writer io.Writer, summary analysis.BaselineSummary) error {
	if !summary.Applied {
		return nil
	}
	_, err := fmt.Fprintf(writer, "baseline: %d new, %d unchanged, %d resolved\n",
		summary.NewFindings, summary.UnchangedFindings, summary.ResolvedFindings)
	return err
}

// WriteSummaryV01JSON writes the canonical v3 analysis projection used by the summary --format=json command.
//
// The legacy function name remains internal so callers do not select a second summary implementation.
// It builds the payload by calling MachineSummary on report and encodes it to writer through WriteJSON.
// It returns the MachineSummary error before anything is written, or else whatever error WriteJSON returns, which is nil on success.
func WriteSummaryV01JSON(writer io.Writer, report analysis.Report) error {
	payload, err := report.MachineSummary()
	if err != nil {
		return err
	}
	return WriteJSON(writer, payload)
}

// writeFreshStartHint gives first-run users a concrete baseline workflow when the summary found existing debt and no baseline was applied.
//
// Both hint lines go to writer and repeat the run inputs from report, formatted by summaryCommandInputs.
// A path holding shell characters such as a dollar sign, or starting with a dash, may need editing before the command runs.
// It writes nothing and returns nil when report has no findings or a baseline was applied; otherwise it returns the first write error or nil.
func writeFreshStartHint(writer io.Writer, report analysis.Report) error {
	// With no findings there is nothing to adopt, and an applied baseline already gives the user a comparison, so the hint stays out.
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

// writeScoreCoverage emits the summary's score coverage line, then optional caveat and complexity distribution scope lines.
//
// From score it prints the contributing pillars joined by commas, or none when that list is empty.
// Caveat and complexity distribution lines follow only when non-empty, and the first write error to writer is returned.
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

// BuildPillarSummaryRows returns the canonical per-pillar rows for the text summary digest's Pillars block.
//
// The JSON summary publishes scoring PillarDetails instead, so these rows never reach summary --format=json.
// Every pillar in summaryPillarOrder is included, clean ones as grade A with zero findings, so the block covers the same rows across runs.
// Rows are sorted by findings descending, with ties broken by pillar name ascending.
//
// Counts, penalty and any non-nil score are copied from the matching PillarDetail in report.
// A pillar with no PillarDetail in report stays applicable at grade A and score 100 with zero counts and zero penalty.
// A pillar whose detail has a nil Score is marked not applicable yet keeps the default grade A and score 100 in its row.
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
			// A pillar with no score evaluated nothing, so the row is marked not applicable.
			// Its default grade A and score 100 stay in place, and the text Pillars block still prints them.
			row.Applicable = detail.Applicable && detail.Score != nil
			if detail.Score != nil {
				row.Grade = summaryGrade(*detail.Score)
				row.Score = *detail.Score
			}
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

// writePillarsBlock emits the canonical Pillars block of the summary digest, one aligned line per pillar row.
//
// Column widths follow the rust port's reference implementation from the cross-port summary harmonisation spec.
// The findings, advisory and warning cells pad to the widest of those counts, with three literal spaces between cells; error is unpadded.
//
// The rows print in the order given under a Pillars heading, with a single (none) line when rows is empty.
// It returns the first write error from writer, or nil once every row is written.
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

// summaryDigitWidth returns the number of decimal digits needed to render value, matching the rust port's digit_width helper.
// The Pillars block uses it to size count columns, and a zero or negative value gives one column.
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

// summaryGrade mirrors the scoring package's unexported grade ladder so the summary renderer can grade a non-nil PillarDetail score.
// It returns A for a score of 90 or more, B from 80, C from 70, D from 60, and F below 60 or for NaN.
func summaryGrade(score float64) string {
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

// writeTopRules emits the summary digest's top rules list, most-triggered rule first.
//
// The entries print in the order given, which computeTopRules sorts by count, and nothing is written when entries is empty.
// It returns the first write error from writer, or nil when every line is written.
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

// writeTopOffenders emits the summary digest's top offenders list: up to top files, ordered by penalty.
//
// The offenders print in the order given with score, findings and grade, and nothing is written when offenders is empty.
// A zero top prints only the heading, a negative top panics on the slice bound, and the first write error from writer is returned.
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
		if _, err := fmt.Fprintf(writer, "  %s  score=%.2f  findings=%d  grade=%s\n", file.File, file.Score, file.Findings, file.Grade); err != nil {
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

// computeTopRules returns the top rule IDs by finding count, capped at top entries, for the summary's top rules list.
//
// It counts every finding in report by RuleID and sorts by descending count, breaking ties by rule ID in ascending order.
// An empty report or a zero top gives an empty slice, while a negative top panics on the slice bound.
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

// gradeOrNA returns the grade letter, or the placeholder "n/a" when the run graded nothing.
// A nil grade means no applicable pillar was evaluated, which is distinct from a bad grade.
func gradeOrNA(grade *string) string {
	if grade == nil || *grade == "" {
		return "n/a"
	}
	return *grade
}

// writeCompositeBlock emits the cross-port canonical two-line score block shared by the summary digest and the analyse text header.
//
// The composite score renders with two fixed decimals, and the findings tally is error-first and separated by a middot, U+00B7.
// It matches the gruff-ts reference port byte for byte; only the language token and data differ across ports.
//
// Both lines go to writer from report, and a nil composite prints n/a with a nothing-evaluated note instead of a grade and score.
// It returns the first write error, or nil once the Findings line is written.
func writeCompositeBlock(writer io.Writer, report analysis.Report) error {
	counts := severityCounts(report)
	// A run that evaluated nothing has no composite to render, and printing 100.00 here is exactly
	// what let an empty directory read as perfect before the M06 break.
	if report.Score.Composite == nil {
		if _, err := fmt.Fprintf(writer, "Composite: n/a (nothing evaluated)\n"); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(writer, "Composite: %s (%.2f / 100)\n", gradeOrNA(report.Score.Grade), *report.Score.Composite); err != nil {
		return err
	}
	_, err := fmt.Fprintf(writer, "Findings: %d total · %d error · %d warning · %d advisory\n",
		counts.total, counts.error, counts.warning, counts.advisory)
	return err
}

// summaryInputs renders the run's input paths for the scanned line, falling back to "." when the slice is empty.
// It returns the inputs joined by a comma and a space, without quoting, or a single dot when inputs is empty or nil.
func summaryInputs(inputs []string) string {
	if len(inputs) == 0 {
		return "."
	}
	return strings.Join(inputs, ", ")
}

// summaryCommandInputs formats input paths as command arguments for the fresh-start hint lines.
//
// It returns the inputs joined by spaces; strconv.Quote wraps any input that starts with a dash or holds a space, tab, newline or quote.
// The dollar, ampersand, semicolon, pipe, parenthesis, angle bracket and backtick characters also force quoting; empty inputs give a single dot.
// This Go-style quoting does not stop a shell expanding a dollar sign or backtick, and a quoted leading dash still reaches the command.
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

// summaryWorkingDir renders the absolute working directory for the scanned line of the summary.
// It returns dir unchanged when non-empty, with no check that it is absolute, or ? when dir is empty, so the scanned line reads (in ?).
func summaryWorkingDir(dir string) string {
	if dir == "" {
		return "?"
	}
	return dir
}

// summaryDuration renders the scan time line's duration without Unicode unit symbols, so it stays portable in plain terminals and logs.
//
// It returns <1ms for any duration under one millisecond, zero and negative included, and whole milliseconds such as 250ms below a second.
// Below a minute it gives seconds to one decimal place, and longer durations give whole minutes then seconds, such as 2m 5.0s.
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
