// Package cli filters analyzer findings into the agent-hook JSON contract.
// This file applies shared baseline classification and changed-region scope so
// users see only unreviewed findings attributable to the current edit.
package cli

import (
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/diff"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// hookFindings returns unreviewed findings inside the user's changed region.
// The suppressed count remains limited to changed-scope drops for hook JSON.
func hookFindings(currentFindings []finding.Finding, ruleDefinitions []rule.Definition, changedLines diff.ChangedLines, changedScopeEnabled bool, hookBaseline hookFindingBaseline) ([]hookFinding, int) {
	definitionsByID := hookDefinitionsByID(ruleDefinitions)
	visibleFindings := []hookFinding{}
	changedScopeSuppressed := 0
	unreviewedFindings := hookBaseline.newFindings(currentFindings)
	// Scope only the complete slice left after one-to-one baseline classification.
	for _, currentFinding := range unreviewedFindings {
		findingScope := hookScope(currentFinding)
		// File/project findings need a prior base because no edited line anchors them.
		if changedScopeEnabled && (findingScope == "file" || findingScope == "project") {
			// Without a base, the hook cannot attribute the whole-file issue to this edit.
			if !hookBaseline.enabled {
				changedScopeSuppressed++
				continue
			}
		}
		// Line and symbol findings must intersect the user's requested changed region.
		if changedScopeEnabled && findingScope != "file" && findingScope != "project" && !hookFindingChanged(currentFinding, changedLines) {
			changedScopeSuppressed++
			continue
		}
		visibleFindings = append(visibleFindings, toHookFinding(currentFinding, findingScope, definitionsByID[currentFinding.RuleID]))
	}
	slices.SortFunc(visibleFindings, compareHookFindings)
	return visibleFindings, changedScopeSuppressed
}

// hookDefinitionsByID indexes rules used to complete hook remediation text.
// Empty input leaves findings with the generic user guidance fallback.
func hookDefinitionsByID(ruleDefinitions []rule.Definition) map[string]rule.Definition {
	definitionsByID := map[string]rule.Definition{}
	// Index each active rule once for the findings shown in hook JSON.
	for _, ruleDefinition := range ruleDefinitions {
		definitionsByID[ruleDefinition.ID] = ruleDefinition
	}
	return definitionsByID
}

// toHookFinding converts one visible scan result into the stable hook shape.
// Users receive normalized location, identity, metadata, and remediation fields.
func toHookFinding(currentFinding finding.Finding, findingScope string, ruleDefinition rule.Definition) hookFinding {
	startLine, endLine := hookLine(currentFinding), hookEndLine(currentFinding)
	remediation := hookRemediation(currentFinding, ruleDefinition)
	return hookFinding{
		RuleID:         currentFinding.RuleID,
		Pillar:         currentFinding.Pillar,
		Severity:       currentFinding.Severity,
		Scope:          findingScope,
		File:           currentFinding.File,
		Line:           startLine,
		EndLine:        endLine,
		Symbol:         nonEmptyHookString(currentFinding.Symbol),
		Message:        currentFinding.Message,
		Remediation:    remediation,
		Metadata:       hookMetadata(currentFinding.RuleID, currentFinding.Metadata),
		StableIdentity: currentFinding.ComputeContractStableIdentity(),
		Fingerprint:    currentFinding.Fingerprint,
	}
}

// hookRemediation guarantees actionable, non-empty guidance in hook JSON.
// Finding-specific text wins before the rule or generic user fallback.
func hookRemediation(currentFinding finding.Finding, ruleDefinition rule.Definition) string {
	// A rule instance may provide remediation tailored to this exact finding.
	if currentFinding.Remediation != "" {
		return currentFinding.Remediation
	}
	// Otherwise use the rule's general fix guidance shown in the catalogue.
	if ruleDefinition.Remediation != "" {
		return ruleDefinition.Remediation
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

// hookScope selects the location granularity shown to the user's agent.
// Missing file or line context intentionally falls back to broader scopes.
func hookScope(currentFinding finding.Finding) string {
	// Known whole-file rules cannot be attributed to one changed line.
	if _, isFileScopeRule := hookFileScopeRuleIDs[currentFinding.RuleID]; isFileScopeRule {
		return "file"
	}
	// Package-summary rubric findings also describe the whole source file.
	if currentFinding.RuleID == "docs.comment-rubric" && currentFinding.Metadata["kind"] == "package" {
		return "file"
	}
	// Empty file context means the finding belongs to the project as a whole.
	if currentFinding.File == "" {
		return "project"
	}
	// A nil or empty location still lets the hook point users at the file.
	if currentFinding.Location == nil || currentFinding.Location.Line == 0 {
		return "file"
	}
	// A named function or type gives the agent a more useful symbol-level target.
	if currentFinding.Symbol != "" {
		return "symbol"
	}
	return "line"
}

// hookFindingChanged reports whether a finding intersects the user's edit.
// Missing line context falls back to the changed-file decision.
func hookFindingChanged(currentFinding finding.Finding, changedLines diff.ChangedLines) bool {
	// A nil or empty location can only be scoped at file level.
	if currentFinding.Location == nil || currentFinding.Location.Line == 0 {
		return diff.FileChanged(changedLines, currentFinding.File)
	}
	startLine := currentFinding.Location.Line
	endLine := currentFinding.Location.EndLine
	// Empty or reversed spans behave as one line in the hook UI.
	if endLine == 0 || endLine < startLine {
		endLine = startLine
	}
	return diff.RangeChanged(changedLines, currentFinding.File, startLine, endLine)
}

// hookLine returns the optional start line used by hook JSON consumers.
// Nil means the user should navigate by file or project scope instead.
func hookLine(currentFinding finding.Finding) *int {
	// A nil or non-positive location is serialized as JSON null for the user.
	if currentFinding.Location == nil || currentFinding.Location.Line <= 0 {
		return nil
	}
	startLine := currentFinding.Location.Line
	return &startLine
}

// hookEndLine returns the optional span end used by hook JSON consumers.
// Nil means the user-facing finding identifies only its start line.
func hookEndLine(currentFinding finding.Finding) *int {
	// A nil or non-positive end is omitted because there is no user-visible span.
	if currentFinding.Location == nil || currentFinding.Location.EndLine <= 0 {
		return nil
	}
	endLine := currentFinding.Location.EndLine
	return &endLine
}

// nonEmptyHookString returns nil for absent optional strings.
func nonEmptyHookString(value string) *string {
	// Empty optional text becomes JSON null instead of an ambiguous empty label.
	if value == "" {
		return nil
	}
	return &value
}

// compareHookFindings orders hook results for a stable user review queue.
// Severity wins, followed by file, line, rule, and stable identity.
func compareHookFindings(leftFinding, rightFinding hookFinding) int {
	// Higher-severity issues appear first for the user and coding agent.
	if hookSeverityRank(leftFinding.Severity) != hookSeverityRank(rightFinding.Severity) {
		return hookSeverityRank(rightFinding.Severity) - hookSeverityRank(leftFinding.Severity)
	}
	// File ordering keeps related edits together in hook output.
	if leftFinding.File != rightFinding.File {
		return strings.Compare(leftFinding.File, rightFinding.File)
	}
	// Earlier source locations appear first within the same file.
	if hookLineValue(leftFinding.Line) != hookLineValue(rightFinding.Line) {
		return hookLineValue(leftFinding.Line) - hookLineValue(rightFinding.Line)
	}
	// Rule ordering makes same-line findings deterministic for UI consumers.
	if leftFinding.RuleID != rightFinding.RuleID {
		return strings.Compare(leftFinding.RuleID, rightFinding.RuleID)
	}
	return strings.Compare(leftFinding.StableIdentity, rightFinding.StableIdentity)
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
	// A nil JSON line sorts before concrete locations in the same file.
	if value == nil {
		return 0
	}
	return *value
}
