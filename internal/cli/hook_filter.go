// Package cli filters analyzer findings into the agent-hook JSON contract.
//
// This file applies shared baseline classification and, when enabled, changed-region scope for the gruff-go hook command.
// With changed scope on, line and symbol findings must overlap the edit, and file or project findings need an enabled baseline.
// Changed-scope drops count as suppressed; baseline drops do not.
package cli

import (
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/diff"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// hookFindings picks the findings gruff-go hook shows for the current edit and counts the ones changed scope hid.
//
// currentFindings is first classified against hookBaseline, and only the unreviewed findings it leaves are scoped and converted.
// With changedScopeEnabled, line and symbol findings must intersect changedLines, and file or project findings need hookBaseline enabled.
// ruleDefinitions supplies the rule remediation fallback, and the visible findings are sorted by compareHookFindings.
//
// It returns the visible findings, an empty non-nil slice when none survive, and the number hidden by changed scope.
// Baseline drops are not part of that count; it holds only changed-scope drops.
func hookFindings(currentFindings []finding.Finding, ruleDefinitions []rule.Definition, changedLines diff.ChangedLines, changedScopeEnabled bool, hookBaseline hookFindingBaseline) ([]hookFinding, int) {
	definitionsByID := hookDefinitionsByID(ruleDefinitions)
	visibleFindings := []hookFinding{}
	changedScopeSuppressed := 0
	// Findings the baseline classifies as reviewed are dropped here and do not add to the suppressed count.
	unreviewedFindings := hookBaseline.newFindings(currentFindings)
	// Scope only the complete slice left after one-to-one baseline classification.
	for _, currentFinding := range unreviewedFindings {
		findingScope := hookScope(currentFinding)
		// File/project findings need a prior base because no edited line anchors them.
		if changedScopeEnabled && (findingScope == "file" || findingScope == "project") {
			// Without a base, the hook cannot attribute the whole-file issue to this edit, so it is hidden and counted as suppressed.
			if !hookBaseline.enabled {
				changedScopeSuppressed++
				continue
			}
		}
		// Line and symbol findings outside the user's changed region are hidden and counted as suppressed.
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
//
// It returns a non-nil map from each rule ID in ruleDefinitions to its definition; a later duplicate ID overwrites an earlier one.
// Empty ruleDefinitions gives an empty map, so findings without their own remediation get the generic sentence.
func hookDefinitionsByID(ruleDefinitions []rule.Definition) map[string]rule.Definition {
	definitionsByID := map[string]rule.Definition{}
	// For a duplicate rule ID, the last definition supplies the rule-level remediation fallback.
	for _, ruleDefinition := range ruleDefinitions {
		definitionsByID[ruleDefinition.ID] = ruleDefinition
	}
	return definitionsByID
}

// toHookFinding converts one visible finding into the hook JSON entry the agent reads.
//
// currentFinding supplies the location, identity, message and metadata fields, and findingScope is copied into Scope unchanged.
// ruleDefinition supplies the remediation text when currentFinding carries none, before the generic fallback.
// Confidence is normalized, so a finding from an unrated rule reads high.
//
// It returns the entry; Line, Symbol and BaselineStatus are null when the finding lacks them, and EndLine follows hookEndLine.
// StableIdentity is nil whenever hookStableIdentity refuses an identity, as for every sensitive-data finding.
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
		SymbolOrdinal:  currentFinding.SymbolOrdinal,
		Message:        currentFinding.Message,
		Remediation:    remediation,
		Confidence:     hookConfidence(currentFinding.Confidence),
		BaselineStatus: nonEmptyHookString(currentFinding.BaselineStatus),
		Metadata:       hookMetadata(currentFinding.RuleID, currentFinding.Metadata),
		StableIdentity: hookStableIdentity(currentFinding),
		Fingerprint:    currentFinding.Fingerprint,
	}
}

// hookConfidence reports the confidence the gate will read for this finding.
//
// It returns confidence unchanged when it is one of the three ratified levels, and high for anything else, empty included.
// A rule this port never rated would otherwise publish an empty string, which a consumer cannot compare against a floor.
// The family contract makes such a finding high, so it can never slip under a gate.
func hookConfidence(confidence finding.Confidence) finding.Confidence {
	// Only the three ratified levels are meaningful; anything else, empty included, is treated as unrated.
	if confidence.Valid() {
		return confidence
	}

	return finding.ConfidenceHigh
}

// hookStableIdentity returns the ratified family identity, or nil, written as null, where the family refuses to give one.
//
// A sensitive-data finding is deliberately unidentifiable, because a durable identity would let a stored review hide a secret.
// A finding this port cannot name is reported without an identity rather than with a guessed one.
//
// It yields nil when currentFinding is not baseline eligible or ComputeBaselineIdentity fails, as for a symbol with no declaration ordinal.
func hookStableIdentity(currentFinding finding.Finding) *string {
	if !currentFinding.IsBaselineEligible() {
		return nil
	}

	identity, err := currentFinding.ComputeBaselineIdentity()

	// A symbol with no declaration ordinal lands here; publishing a partial identity would collide two declarations.
	if err != nil {
		return nil
	}

	return &identity
}

// hookRemediation gives the agent actionable, non-empty fix guidance for one finding in hook JSON.
// It returns the Remediation of currentFinding when set, else that of ruleDefinition, else a fixed sentence pointing at the rule documentation.
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

// hookFileScopeRuleIDs lists rules whose findings describe a whole file, so changed-region scoping cannot tie them to an edited line.
//
// With changed scope on, their findings show only when the hook baseline is enabled; otherwise they count as suppressed.
// Keep it in sync with the rule registry; TestHookScopeAndDirectionRuleIDsExist fails if an ID goes stale.
// docs.comment-rubric is handled separately in hookScope, because only its package-summary finding, metadata kind package, is file-scoped.
var hookFileScopeRuleIDs = map[string]struct{}{
	"size.file-length":          {},
	"design.hotspot-file":       {},
	"docs.package-comment":      {},
	"naming.package-underscore": {},
	"naming.package-stutter":    {},
}

// hookScope selects the location granularity, file, project, symbol or line, that the agent sees for currentFinding.
//
// It returns file for hookFileScopeRuleIDs and package-kind docs.comment-rubric findings, then project when currentFinding has no File.
// Otherwise it returns file when the location is nil or its line is zero, symbol when Symbol is set, and line for everything else.
// Missing file or line context intentionally falls back to these broader scopes.
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

// hookFindingChanged reports whether currentFinding intersects the user's edit as recorded in changedLines.
//
// A finding with no location or a zero line counts as changed when its file changed at all.
// Otherwise its span, with an unset or reversed end counting as the start line, must overlap a changed range.
// A false result makes hookFindings hide the finding and count it as suppressed.
func hookFindingChanged(currentFinding finding.Finding, changedLines diff.ChangedLines) bool {
	// A nil or empty location can only be scoped at file level.
	if currentFinding.Location == nil || currentFinding.Location.Line == 0 {
		return diff.FileChanged(changedLines, currentFinding.File)
	}
	startLine := currentFinding.Location.Line
	endLine := currentFinding.Location.EndLine
	// A finding with an unset or reversed end counts as changed only when its start line was edited.
	if endLine == 0 || endLine < startLine {
		endLine = startLine
	}
	return diff.RangeChanged(changedLines, currentFinding.File, startLine, endLine)
}

// hookLine returns the start line hook JSON shows for currentFinding, as a pointer to a copy.
// It is nil, written as null, when the finding has no location or a non-positive line.
func hookLine(currentFinding finding.Finding) *int {
	// A nil or non-positive location is serialized as JSON null for the user.
	if currentFinding.Location == nil || currentFinding.Location.Line <= 0 {
		return nil
	}
	startLine := currentFinding.Location.Line
	return &startLine
}

// hookEndLine returns the span end every v2 hook finding carries, nil, written as null, when currentFinding has no positive start line.
//
// A single-line finding repeats its start line: an EndLine below the start, zero included, becomes the start, and any other EndLine is kept.
func hookEndLine(currentFinding finding.Finding) *int {
	// Without a location there is no span to state, and line is null for the same reason.
	if currentFinding.Location == nil || currentFinding.Location.Line <= 0 {
		return nil
	}
	endLine := currentFinding.Location.EndLine
	// An unset or reversed end means the finding occupies its start line alone, which the contract says to spell out.
	if endLine < currentFinding.Location.Line {
		endLine = currentFinding.Location.Line
	}
	return &endLine
}

// nonEmptyHookString returns nil for absent optional strings.
// A non-empty value is returned as a pointer to a copy of it.
func nonEmptyHookString(value string) *string {
	// Empty optional text becomes JSON null instead of an ambiguous empty label.
	if value == "" {
		return nil
	}
	return &value
}

// compareHookFindings orders hook results for the agent's review queue, most severe first.
//
// Sort keys are severity, file, line, rule ID and stable identity; findings equal on all of them have no guaranteed relative order.
// The result is negative when leftFinding sorts before rightFinding, positive when it sorts after, and zero when every sort key matches.
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
	// Same-line findings are ordered by rule ID before stable identity is compared.
	if leftFinding.RuleID != rightFinding.RuleID {
		return strings.Compare(leftFinding.RuleID, rightFinding.RuleID)
	}
	return strings.Compare(hookIdentityValue(leftFinding.StableIdentity), hookIdentityValue(rightFinding.StableIdentity))
}

// hookIdentityValue provides a sortable empty string for the null identity a sensitive finding carries.
// It returns the string identity points to, or an empty string when identity is nil, which sorts before any non-empty identity.
func hookIdentityValue(identity *string) string {
	// A sensitive finding has no identity; its empty key sorts first only when severity, file, line and rule ID all tie.
	if identity == nil {
		return ""
	}
	return *identity
}

// hookSeverityRank maps the closed severity enum to descending priority.
// It returns the rank 3 for SeverityError, 2 for SeverityWarning, 1 for SeverityAdvisory, and 0 for any other value, so higher ranks sort first.
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
// It returns the line value points to, or zero when value is nil, which sorts before any positive line.
func hookLineValue(value *int) int {
	// A nil JSON line sorts before positive lines once severity and file tie.
	if value == nil {
		return 0
	}
	return *value
}
