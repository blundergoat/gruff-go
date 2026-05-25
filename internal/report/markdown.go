// Package report renders gruff-go analysis results into output formats.
// Markdown output is tuned for CI logs and GitHub PR comments: a short header,
// severity counts, the canonical Pillars table, and a compact top-rules block.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
)

// markdownTopRules caps the top-rules table so PR comments stay compact.
const markdownTopRules = 5

// WriteMarkdown renders the analysis report as CommonMark-flavoured markdown
// with the canonical Pillars table. Output is consumable in CI logs and as a
// GitHub PR comment body.
func WriteMarkdown(writer io.Writer, report analysis.Report) error {
	if err := writeMarkdownHeader(writer, report); err != nil {
		return err
	}
	if err := writeMarkdownSeverityCounts(writer, report); err != nil {
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

// writeMarkdownHeader emits the title and headline grade/score line.
func writeMarkdownHeader(writer io.Writer, report analysis.Report) error {
	if _, err := fmt.Fprintf(writer, "# gruff-go report\n\n"); err != nil {
		return err
	}
	grade := gradeOrNA(report.Score.Grade)
	if _, err := fmt.Fprintf(writer, "**Grade:** %s (%d / 100)\n", grade, report.Score.Composite); err != nil {
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

// writeMarkdownSeverityCounts emits the severity totals line.
func writeMarkdownSeverityCounts(writer io.Writer, report analysis.Report) error {
	counts := severityCounts(report)
	_, err := fmt.Fprintf(
		writer,
		"**Findings:** %d total - %d error, %d warning, %d advisory\n",
		counts.total,
		counts.error,
		counts.warning,
		counts.advisory,
	)
	return err
}

// writeMarkdownPillarsTable emits the canonical 7-column Pillars table shared
// across the cross-port summary harmonisation effort.
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

// writeMarkdownTopRules emits a compact top-rules table; the section is
// omitted when no findings fired.
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

// escapeMarkdownCell escapes the pipe character so values containing `|` do
// not break the surrounding table row.
func escapeMarkdownCell(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}
