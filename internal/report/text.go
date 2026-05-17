package report

import (
	"fmt"
	"io"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

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
	return nil
}

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

func countGitignored(skipped []analysis.SkippedPath) int {
	n := 0
	for _, item := range skipped {
		if item.Reason == "gitignored" {
			n++
		}
	}
	return n
}

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
