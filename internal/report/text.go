// Package report renders gruff-go analysis results into output formats.
// Plain-text output favours deterministic sections and one-line findings for terminal review.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// WriteText renders the complete report in the human-readable CLI format.
func WriteText(writer io.Writer, report analysis.Report) error {
	if err := writeTextHeader(writer, report); err != nil {
		return err
	}
	if err := writeTextDiagnostics(writer, report.Diagnostics); err != nil {
		return err
	}
	if err := writeTextFindings(writer, report.Findings); err != nil {
		return err
	}
	_, err := fmt.Fprintf(writer, "exit: %d\n", report.Summary.ExitCode)
	return err
}

// writeTextHeader emits the leading metadata block: schema, file counts, score coverage, and scope.
func writeTextHeader(writer io.Writer, report analysis.Report) error {
	if _, err := fmt.Fprintf(writer, "gruff-go analysis\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "schema: %s\n", report.SchemaVersion); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "files: %d scanned, %d skipped\n", report.Summary.FilesScanned, report.Summary.FilesSkipped); err != nil {
		return err
	}
	if gitignored := countGitignored(report.Paths.Skipped); gitignored > 0 {
		if _, err := fmt.Fprintf(writer, "  ignored by .gitignore: %d\n", gitignored); err != nil {
			return err
		}
	}
	if report.DisplayFilter.Applied {
		if _, err := fmt.Fprintf(writer, "display filter: %d findings hidden; score and exit use full scan\n", report.DisplayFilter.HiddenFindings); err != nil {
			return err
		}
	}
	if len(report.Score.Coverage.ContributingPillars) > 0 {
		if _, err := fmt.Fprintf(writer, "score coverage: %s\n", strings.Join(report.Score.Coverage.ContributingPillars, ", ")); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintln(writer, "score coverage: no score-impacting findings"); err != nil {
		return err
	}
	if report.Score.Coverage.Caveat != "" {
		if _, err := fmt.Fprintf(writer, "score caveat: %s\n", report.Score.Coverage.Caveat); err != nil {
			return err
		}
	}
	if report.Score.ComplexityDistributionScope != "" {
		if _, err := fmt.Fprintf(writer, "complexity distribution: %s\n", report.Score.ComplexityDistributionScope); err != nil {
			return err
		}
	}
	return nil
}

// writeTextDiagnostics emits a one-line entry per diagnostic when any exist.
func writeTextDiagnostics(writer io.Writer, diagnostics []analysis.Diagnostic) error {
	if len(diagnostics) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(writer, "diagnostics:"); err != nil {
		return err
	}
	for _, diagnostic := range diagnostics {
		location := ""
		if diagnostic.Location != nil && diagnostic.Location.Line > 0 {
			location = fmt.Sprintf(":%d", diagnostic.Location.Line)
		}
		if _, err := fmt.Fprintf(writer, "  [%s] %s%s %s\n", diagnostic.Stage, diagnostic.File, location, diagnostic.Message); err != nil {
			return err
		}
	}
	return nil
}

// writeTextFindings emits one line per finding in the order produced by the analyser.
func writeTextFindings(writer io.Writer, findings []finding.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(writer, "findings: none")
		return err
	}
	if _, err := fmt.Fprintln(writer, "findings:"); err != nil {
		return err
	}
	for _, item := range findings {
		location := ""
		if item.Location != nil && item.Location.Line > 0 {
			location = fmt.Sprintf(":%d", item.Location.Line)
		}
		if _, err := fmt.Fprintf(writer, "  [%s] %s%s %s: %s\n", item.Severity, item.File, location, item.RuleID, item.Message); err != nil {
			return err
		}
	}
	return nil
}

// countGitignored returns the number of skipped paths whose reason is "gitignored".
func countGitignored(skipped []analysis.SkippedPath) int {
	n := 0
	for _, item := range skipped {
		if item.Reason == "gitignored" {
			n++
		}
	}
	return n
}

// WriteRuleText writes one line per registered rule with id, pillar, severity, capability, and title.
func WriteRuleText(writer io.Writer, definitions []rule.Definition) error {
	if len(definitions) == 0 {
		_, err := fmt.Fprintln(writer, "No rules registered.")
		return err
	}
	for _, definition := range definitions {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", definition.ID, definition.Pillar, definition.Severity, definition.Capability, definition.Title); err != nil {
			return err
		}
	}
	return nil
}
