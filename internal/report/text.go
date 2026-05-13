package report

import (
	"fmt"
	"io"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/rule"
)

func WriteText(writer io.Writer, report analysis.Report) error {
	if _, err := fmt.Fprintf(writer, "gruff-go analysis\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "schema: %s\n", report.SchemaVersion); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "files: %d scanned, %d skipped\n", report.Summary.FilesScanned, report.Summary.FilesSkipped); err != nil {
		return err
	}
	if report.DisplayFilter.Applied {
		if _, err := fmt.Fprintf(writer, "display filter: %d findings hidden; score and exit use full scan\n", report.DisplayFilter.HiddenFindings); err != nil {
			return err
		}
	}
	if len(report.Diagnostics) > 0 {
		if _, err := fmt.Fprintln(writer, "diagnostics:"); err != nil {
			return err
		}
		for _, diagnostic := range report.Diagnostics {
			location := ""
			if diagnostic.Location != nil && diagnostic.Location.Line > 0 {
				location = fmt.Sprintf(":%d", diagnostic.Location.Line)
			}
			if _, err := fmt.Fprintf(writer, "  [%s] %s%s %s\n", diagnostic.Stage, diagnostic.File, location, diagnostic.Message); err != nil {
				return err
			}
		}
	}
	if len(report.Findings) > 0 {
		if _, err := fmt.Fprintln(writer, "findings:"); err != nil {
			return err
		}
		for _, finding := range report.Findings {
			location := ""
			if finding.Location != nil && finding.Location.Line > 0 {
				location = fmt.Sprintf(":%d", finding.Location.Line)
			}
			if _, err := fmt.Fprintf(writer, "  [%s] %s%s %s: %s\n", finding.Severity, finding.File, location, finding.RuleID, finding.Message); err != nil {
				return err
			}
		}
	} else {
		if _, err := fmt.Fprintln(writer, "findings: none"); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(writer, "exit: %d\n", report.Summary.ExitCode)
	return err
}

func WriteRuleText(writer io.Writer, definitions []rule.Definition) error {
	if len(definitions) == 0 {
		_, err := fmt.Fprintln(writer, "No rules registered.")
		return err
	}
	for _, definition := range definitions {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", definition.ID, definition.Pillar, definition.Severity, definition.Title); err != nil {
			return err
		}
	}
	return nil
}
