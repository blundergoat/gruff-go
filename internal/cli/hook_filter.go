package cli

import (
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/diff"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// hookFindings filters and sorts findings according to B1/B3/B9.
func hookFindings(items []finding.Finding, definitions []rule.Definition, changed diff.ChangedLines, changedEnabled bool, base hookIdentitySet) ([]hookFinding, int) {
	definitionsByID := hookDefinitionsByID(definitions)
	out := []hookFinding{}
	suppressed := 0
	for _, current := range items {
		scope := hookScope(current)
		if base.contains(current) {
			continue
		}
		if changedEnabled && (scope == "file" || scope == "project") {
			if !base.enabled {
				suppressed++
				continue
			}
		}
		if changedEnabled && scope != "file" && scope != "project" && !hookFindingChanged(current, changed) {
			suppressed++
			continue
		}
		out = append(out, toHookFinding(current, scope, definitionsByID[current.RuleID]))
	}
	slices.SortFunc(out, compareHookFindings)
	return out, suppressed
}

// hookDefinitionsByID indexes rule descriptors for remediation fallback.
func hookDefinitionsByID(definitions []rule.Definition) map[string]rule.Definition {
	out := map[string]rule.Definition{}
	for _, definition := range definitions {
		out[definition.ID] = definition
	}
	return out
}

// toHookFinding normalizes one analysis finding into the hook JSON shape.
func toHookFinding(item finding.Finding, scope string, definition rule.Definition) hookFinding {
	line, endLine := hookLine(item), hookEndLine(item)
	remediation := hookRemediation(item, definition)
	return hookFinding{
		RuleID:         item.RuleID,
		Pillar:         item.Pillar,
		Severity:       item.Severity,
		Scope:          scope,
		File:           item.File,
		Line:           line,
		EndLine:        endLine,
		Symbol:         nonEmptyHookString(item.Symbol),
		Message:        item.Message,
		Remediation:    remediation,
		Metadata:       hookMetadata(item.RuleID, item.Metadata),
		StableIdentity: item.ComputeContractStableIdentity(),
		Fingerprint:    item.Fingerprint,
	}
}

// hookRemediation guarantees B4's non-null remediation string.
func hookRemediation(item finding.Finding, definition rule.Definition) string {
	if item.Remediation != "" {
		return item.Remediation
	}
	if definition.Remediation != "" {
		return definition.Remediation
	}
	return "Review the rule documentation for remediation guidance."
}

// hookFileScopeRuleIDs are rules whose findings describe a whole file rather than
// a single line, so changed-region scoping cannot attribute them to an edited
// line. Keep in sync with the rule registry; TestHookScopeAndDirectionRuleIDsExist
// fails if an ID goes stale. docs.comment-rubric is handled separately because
// only its package-summary finding (kind=="package") is file-scoped.
var hookFileScopeRuleIDs = map[string]struct{}{
	"size.file-length":          {},
	"design.hotspot-file":       {},
	"docs.package-comment":      {},
	"naming.package-underscore": {},
	"naming.package-stutter":    {},
}

// hookScope classifies findings into the closed hook scope enum.
func hookScope(item finding.Finding) string {
	if _, ok := hookFileScopeRuleIDs[item.RuleID]; ok {
		return "file"
	}
	if item.RuleID == "docs.comment-rubric" && item.Metadata["kind"] == "package" {
		return "file"
	}
	if item.File == "" {
		return "project"
	}
	if item.Location == nil || item.Location.Line == 0 {
		return "file"
	}
	if item.Symbol != "" {
		return "symbol"
	}
	return "line"
}

// hookFindingChanged applies B1's direct span-intersection test.
func hookFindingChanged(item finding.Finding, changed diff.ChangedLines) bool {
	if item.Location == nil || item.Location.Line == 0 {
		return diff.FileChanged(changed, item.File)
	}
	start := item.Location.Line
	end := item.Location.EndLine
	if end == 0 || end < start {
		end = start
	}
	return diff.RangeChanged(changed, item.File, start, end)
}

// hookLine returns the optional start line pointer for JSON null handling.
func hookLine(item finding.Finding) *int {
	if item.Location == nil || item.Location.Line <= 0 {
		return nil
	}
	line := item.Location.Line
	return &line
}

// hookEndLine returns the optional end line pointer when the finding has a span.
func hookEndLine(item finding.Finding) *int {
	if item.Location == nil || item.Location.EndLine <= 0 {
		return nil
	}
	endLine := item.Location.EndLine
	return &endLine
}

// nonEmptyHookString returns nil for absent optional strings.
func nonEmptyHookString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// compareHookFindings implements B9 deterministic ordering.
func compareHookFindings(a, b hookFinding) int {
	if hookSeverityRank(a.Severity) != hookSeverityRank(b.Severity) {
		return hookSeverityRank(b.Severity) - hookSeverityRank(a.Severity)
	}
	if a.File != b.File {
		return strings.Compare(a.File, b.File)
	}
	if hookLineValue(a.Line) != hookLineValue(b.Line) {
		return hookLineValue(a.Line) - hookLineValue(b.Line)
	}
	if a.RuleID != b.RuleID {
		return strings.Compare(a.RuleID, b.RuleID)
	}
	return strings.Compare(a.StableIdentity, b.StableIdentity)
}

// hookSeverityRank maps the closed severity enum to descending priority.
func hookSeverityRank(severity finding.Severity) int {
	switch severity {
	case finding.SeverityError:
		return 3
	case finding.SeverityWarning:
		return 2
	case finding.SeverityAdvisory:
		return 1
	default:
		return 0
	}
}

// hookLineValue provides a sortable zero for null line values.
func hookLineValue(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}
