package analysis

import (
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/source"
)

// diagnosticsFromAllSkippedInputs reports explicit input paths that produced no
// scanned files because discovery skipped every target before parsing. Without
// this diagnostic, a direct scan of metadata, generated output, or config-ignored
// paths looks like a clean zero-file run.
func diagnosticsFromAllSkippedInputs(inputs []string, discovery source.Result) []Diagnostic {
	if len(inputs) == 0 || len(discovery.Files) > 0 || len(discovery.Missing) > 0 || len(discovery.Skipped) == 0 {
		return nil
	}
	diagnostics := make([]Diagnostic, 0, len(discovery.Skipped))
	for _, skipped := range discovery.Skipped {
		details := []string{"reason=" + skipped.Reason}
		if skipped.Source != "" {
			details = append(details, "source="+skipped.Source)
		}
		if skipped.Pattern != "" {
			details = append(details, "pattern="+skipped.Pattern)
		}
		diagnostics = append(diagnostics, Diagnostic{
			Stage:    "discovery",
			Message:  "explicit input skipped before parsing (" + strings.Join(details, ", ") + "); run from the target project root, pass --include-ignored for generated/git/default skips, or remove the matching paths.ignore entry",
			File:     skipped.Path,
			Severity: finding.SeverityError,
		})
	}
	return diagnostics
}
