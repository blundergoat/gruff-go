package analysis

import (
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/source"
)

// diagnosticsFromAllSkippedInputs reports each discovery skip record as an error when explicit inputs yield no scanned file or missing path.
//
// Without this diagnostic, a direct scan of metadata, generated output, or config-ignored paths looks like a clean zero-file run.
//
// inputs holds the explicit input paths; only its length matters, and an empty list returns nil.
// discovery is the source discovery result; the function also returns nil when it has any file or missing path, or no skipped path.
// Otherwise the result holds one error-severity diagnostic per discovery.Skipped entry, naming its path, reason, and any source or pattern.
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
