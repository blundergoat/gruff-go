// Package report renders gruff-go analysis results into output formats.
//
// Markdown output is tuned for CI logs and GitHub PR comments.
// It holds a short header, severity counts, any diagnostics, the canonical Pillars table and a compact top-rules block.
// A run with no diagnostics skips the Diagnostics section, and one with no findings skips Top rules, so the output stays short.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
)

// markdownTopRules caps the top-rules table so PR comments stay compact.
const markdownTopRules = 5

// WriteMarkdown renders the analysis report as CommonMark-flavoured markdown with the canonical Pillars table.
//
// Output is consumable in CI logs and as a GitHub PR comment body.
// It writes the header, severity counts, diagnostics, Pillars table and top rules for report to writer, in that order.
// It returns the first error a write to writer fails with, leaving any sections already written in place, and nil once every section is written.
func WriteMarkdown(writer io.Writer, report analysis.Report) error {
	if err := writeMarkdownHeader(writer, report); err != nil {
		return err
	}
	if err := writeMarkdownSeverityCounts(writer, report); err != nil {
		return err
	}
	if err := writeMarkdownDiagnostics(writer, report.Diagnostics); err != nil {
		return err
	}
	if err := writeMarkdownPillarsTable(writer, BuildPillarSummaryRows(report)); err != nil {
		return err
	}
	if err := writeMarkdownTopRules(writer, computeTopRules(report, markdownTopRules)); err != nil {
		return err
	}
	return nil
}

// writeMarkdownDiagnostics keeps degradation and failure messages visible in PR-comment output.
//
// It writes nothing to writer when diagnostics is empty, else a Diagnostics heading and one bullet per entry with its label, file and message.
// It returns the first error a write to writer fails with, and nil otherwise.
func writeMarkdownDiagnostics(writer io.Writer, diagnostics []analysis.Diagnostic) error {
	if len(diagnostics) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(writer, "\n## Diagnostics"); err != nil {
		return err
	}
	for _, diagnostic := range diagnostics {
		if _, err := fmt.Fprintf(writer, "\n- `%s` `%s` - %s\n", escapeMarkdownCell(diagnosticLabel(diagnostic)), escapeMarkdownCell(diagnostic.File), diagnostic.Message); err != nil {
			return err
		}
	}
	return nil
}

// writeMarkdownHeader emits the title and the canonical composite score line.
//
// The composite line shows the report grade and score out of 100, or n/a when nothing was evaluated; schema and file-count lines follow.
// It returns the first error a write to writer fails with, and nil otherwise.
func writeMarkdownHeader(writer io.Writer, report analysis.Report) error {
	if _, err := fmt.Fprintf(writer, "# gruff-go report\n\n"); err != nil {
		return err
	}
	grade := gradeOrNA(report.Score.Grade)
	// A run that evaluated nothing renders no number, matching the text and machine views.
	if report.Score.Composite == nil {
		if _, err := fmt.Fprintf(writer, "Composite: **n/a (nothing evaluated)**\n"); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(writer, "Composite: **%s (%.2f / 100)**\n", grade, *report.Score.Composite); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "**Schema:** `%s`\n", report.SchemaVersion); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "**Files:** %d scanned, %d skipped\n", report.Summary.FilesScanned, report.Summary.FilesSkipped); err != nil {
		return err
	}
	return nil
}

// writeMarkdownSeverityCounts emits the canonical error-first findings tally line, with the middot (U+00B7) separator all gruff ports share.
//
// It writes the total, error, warning and advisory finding counts from report to writer and returns the error that write fails with, or nil.
func writeMarkdownSeverityCounts(writer io.Writer, report analysis.Report) error {
	counts := severityCounts(report)
	_, err := fmt.Fprintf(
		writer,
		"Findings: %d total · %d error · %d warning · %d advisory\n",
		counts.total,
		counts.error,
		counts.warning,
		counts.advisory,
	)
	return err
}

// writeMarkdownPillarsTable emits the canonical 7-column Pillars table shared across the cross-port summary harmonisation effort.
//
// It writes to writer one table row per entry in rows, with the score to two decimals, or one placeholder row reading none when rows is empty.
// It returns the first error a write to writer fails with, and nil otherwise.
func writeMarkdownPillarsTable(writer io.Writer, rows []PillarSummaryRow) error {
	if _, err := fmt.Fprintf(writer, "\n## Pillars\n\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "| Pillar | Grade | Score | Findings | Advisory | Warning | Error |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "| --- | --- | ---: | ---: | ---: | ---: | ---: |"); err != nil {
		return err
	}
	if len(rows) == 0 {
		_, err := fmt.Fprintln(writer, "| _(none)_ |  |  |  |  |  |  |")
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(
			writer,
			"| %s | %s | %s | %d | %d | %d | %d |\n",
			escapeMarkdownCell(row.Pillar),
			escapeMarkdownCell(row.Grade),
			fmt.Sprintf("%.2f", row.Score),
			row.Findings,
			row.Advisory,
			row.Warning,
			row.Error,
		); err != nil {
			return err
		}
	}
	return nil
}

// writeMarkdownTopRules emits a compact top-rules table; the section is omitted when no findings fired.
//
// entries holds the rule IDs and counts to list, one row each in the given order, with each rule ID in a code span.
// It writes nothing to writer when entries is empty and returns the first error a write to writer fails with, or nil.
func writeMarkdownTopRules(writer io.Writer, entries []ruleCount) error {
	if len(entries) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(writer, "\n## Top rules\n\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "| Rule | Count |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "|---|---:|"); err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintf(writer, "| `%s` | %d |\n", escapeMarkdownCell(entry.RuleID), entry.Count); err != nil {
			return err
		}
	}
	return nil
}

// escapeMarkdownCell escapes the pipe character so a value containing one does not break the surrounding table row.
//
// It returns value with each pipe prefixed by a backslash, or value unchanged when it has no pipe; no other character is escaped.
func escapeMarkdownCell(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}
