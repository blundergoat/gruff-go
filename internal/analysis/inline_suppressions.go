package analysis

import (
	"regexp"
	"sort"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// SuppressionSourceInline marks an audit row that another tool's suppression comment produced.
//
// ApplyInlineSuppressions sets it as the Source of each row it appends; rows for built-in suppressions carry SuppressionSourceBuiltIn.
const SuppressionSourceInline = "inline"

// InlineSuppressionReason is the reason on each inline audit row; every port publishes these exact words (FAMILY-CONTRACT.md section 13c).
//
// It is also the justification on each suppressed finding, which a SARIF reader sees on the suppressed result.
const InlineSuppressionReason = "Another tool's suppression comment names this check, so the finding is suppressed where it was written."

// SuppressedFinding is a finding another tool's comment suppressed.
//
// It is dropped from the findings list and does not count toward the score.
// SARIF keeps it as a result marked suppressed, so a code-scanning tool shows it as suppressed rather than fixed.
type SuppressedFinding struct {
	// Finding is the suppressed finding as the rule reported it.
	Finding finding.Finding
	// Justification is the audit reason a SARIF reader sees on the suppressed result.
	Justification string
}

// gosecCheckRules maps each gosec check that section 13c names for gruff-go to the rule that makes the same claim.
//
// G101, hard-coded credentials, is not listed; it covers every sensitive-data rule through gosecCredentialCheck.
// Any other named check, such as G304, adds no suppression; mapped checks in the same list still cover their rules.
var gosecCheckRules = map[string]string{
	"G112": "security.http-server-no-timeout",
	"G402": "security.tls-insecure-config",
	"G204": "security.shell-command",
}

// zizmorCheckRules maps each zizmor audit section 13c names to the workflow rule that makes the same claim.
// An unmapped audit name adds no suppression; mapped audits in the same comment still cover their rules.
var zizmorCheckRules = map[string]string{
	"unpinned-uses":      "security.github-actions-unpinned-action",
	"dangerous-triggers": "security.github-actions-pull-request-target",
}

// gosecCredentialCheck is gosec's hard-coded-credentials check, which makes every sensitive-data rule's claim.
const gosecCredentialCheck = "G101"

// functionLengthRule is the rule golangci-lint's `funlen` linter covers.
const functionLengthRule = "size.function-length"

// gosecDirective matches `#nosec` and its optional check list, e.g. `#nosec G204 -- fixed git arguments`.
var gosecDirective = regexp.MustCompile(`#nosec((?:[ \t]*,?[ \t]*G\d+)*)`)

// gosecCode matches one gosec check in a `#nosec` list.
var gosecCode = regexp.MustCompile(`G\d+`)

// nolintDirective matches golangci-lint's `//nolint` and its optional linter list, e.g. `//nolint:funlen,gosec`.
var nolintDirective = regexp.MustCompile(`//nolint(?::([\w,-]+))?(?:[^\w:,-]|$)`)

// zizmorDirective matches zizmor's # zizmor: ignore comment and captures the comma-separated audits inside its brackets, such as unpinned-uses.
var zizmorDirective = regexp.MustCompile(`#\s*zizmor:\s*ignore\[([^\]]*)\]`)

// ApplyInlineSuppressions removes each finding another tool's suppression comment covers and counts it in one inline audit row per file and rule.
//
// A mapped check or a supported bare directive counts on the reported line, or on the line above when it starts with //, # or /*.
// For example, #nosec G204 above exec.Command("sh", "-c", script) suppresses security.shell-command there and nothing else.
// The rows follow the built-in rows and continue their numbering.
//
// The sources map holds each file's text by the path findings carry; a finding whose file is absent from sources is kept.
// It returns the kept findings in order, summaries with the inline rows appended in path then rule order, and the suppressed findings.
// Each suppressed finding carries InlineSuppressionReason as its justification; when nothing is suppressed, summaries comes back unchanged.
func ApplyInlineSuppressions(findings []finding.Finding, summaries []SuppressionSummary, sources map[string]string) ([]finding.Finding, []SuppressionSummary, []SuppressedFinding) {
	type fileAndRule struct{ file, rule string }
	countByFileAndRule := map[fileAndRule]int{}
	linesByFile := map[string][]string{}
	kept := make([]finding.Finding, 0, len(findings))
	suppressed := []SuppressedFinding{}
	for _, item := range findings {
		lines, read := linesByFile[item.File]
		if !read {
			lines = strings.Split(sources[item.File], "\n")
			linesByFile[item.File] = lines
		}
		if !isSuppressedInline(lines, item) {
			kept = append(kept, item)
			continue
		}
		countByFileAndRule[fileAndRule{item.File, item.RuleID}]++
		suppressed = append(suppressed, SuppressedFinding{Finding: item, Justification: InlineSuppressionReason})
	}
	keys := make([]fileAndRule, 0, len(countByFileAndRule))
	for key := range countByFileAndRule {
		keys = append(keys, key)
	}
	// Byte order, path first and then rule id, matches the built-in rows.
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].file != keys[right].file {
			return keys[left].file < keys[right].file
		}
		return keys[left].rule < keys[right].rule
	})
	nextIndex := 0
	for _, summary := range summaries {
		if summary.Source == SuppressionSourceBuiltIn {
			nextIndex++
		}
	}
	for offset, key := range keys {
		summaries = append(summaries, SuppressionSummary{
			Index:      nextIndex + offset,
			Rule:       key.rule,
			Paths:      []string{key.file},
			Reason:     InlineSuppressionReason,
			Suppressed: countByFileAndRule[key],
			Source:     SuppressionSourceInline,
		})
	}
	return kept, summaries, suppressed
}

// sourcesByFile indexes each parsed file's text by the path a finding carries, which may be absolute for an input outside the analysis root.
// It returns a map from the File.Path of each parsed unit in units to its Source, which is empty, not nil, when units is empty.
func sourcesByFile(units []parser.Unit) map[string]string {
	sources := make(map[string]string, len(units))
	for _, unit := range units {
		sources[unit.File.Path] = unit.Source
	}
	return sources
}

// isSuppressedInline reports whether a matching directive sits on the finding's line, or on the line above when it starts with //, # or /*.
//
// The finding's line is matched as raw text, so a directive inside a string literal there also counts.
// A file-level finding has no line to carry one, and leading spaces on the line above are ignored.
// The lines are the file's text split on newlines, and item is the finding; it is false when item has no location or its line is outside lines.
func isSuppressedInline(lines []string, item finding.Finding) bool {
	if item.Location == nil || item.Location.Line < 1 || item.Location.Line > len(lines) {
		return false
	}
	if inlineCommentCovers(lines[item.Location.Line-1], item) {
		return true
	}
	if item.Location.Line < 2 {
		return false
	}
	above := strings.TrimSpace(lines[item.Location.Line-2])
	startsWithCommentMarker := strings.HasPrefix(above, "//") || strings.HasPrefix(above, "#") || strings.HasPrefix(above, "/*")
	return startsWithCommentMarker && inlineCommentCovers(above, item)
}

// inlineCommentCovers reports whether one line names a check section 13c maps to the finding's rule.
//
// A bare #nosec, //nolint, //nolint:all or //nolint:gosec covers every security and sensitive-data rule, as gosec and golangci-lint read them.
// A bare //nolint or //nolint:all also covers size.function-length, the funlen rule.
// A #nosec naming checks covers only those the table lists, so #nosec G304 covers nothing and #nosec G101 covers every sensitive-data rule.
//
// The line is checked for gosec, golangci-lint and zizmor directives against the rule of item.
// The item counts as broad when its pillar is security or its rule ID has the sensitive-data prefix.
func inlineCommentCovers(line string, item finding.Finding) bool {
	broad := item.Pillar == finding.PillarSecurity || strings.HasPrefix(item.RuleID, "sensitive-data.")
	return gosecCommentCovers(line, item.RuleID, broad) || nolintCommentCovers(line, item.RuleID, broad) ||
		zizmorCommentCovers(line, item.RuleID)
}

// gosecCommentCovers reports whether any #nosec on the line covers the finding's rule, named by ruleID; each one is checked in turn.
//
// A #nosec naming checks covers only the rules those checks map to, and G101 maps to every sensitive-data rule.
// Without a check list, it covers the rule only when broad is set, which marks a security or sensitive-data finding.
func gosecCommentCovers(line, ruleID string, broad bool) bool {
	for _, match := range gosecDirective.FindAllStringSubmatch(line, -1) {
		codes := gosecCode.FindAllString(match[1], -1)
		if len(codes) == 0 && broad {
			return true
		}
		for _, code := range codes {
			if gosecCheckRules[code] == ruleID || (code == gosecCredentialCheck && strings.HasPrefix(ruleID, "sensitive-data.")) {
				return true
			}
		}
	}
	return false
}

// nolintCommentCovers reports whether a //nolint on the line covers the rule; a bare //nolint counts as //nolint:all.
//
// Each listed linter, or all for a bare one, is checked against ruleID with nolintLinterCovers.
// The broad flag marks a security or sensitive-data finding.
func nolintCommentCovers(line, ruleID string, broad bool) bool {
	for _, match := range nolintDirective.FindAllStringSubmatch(line, -1) {
		linters := []string{"all"}
		if match[1] != "" {
			linters = strings.Split(match[1], ",")
		}
		for _, linter := range linters {
			if nolintLinterCovers(linter, ruleID, broad) {
				return true
			}
		}
	}
	return false
}

// nolintLinterCovers reports whether one golangci-lint linter name covers the rule.
//
// The names all and gosec cover every security and sensitive-data rule, and all and funlen cover size.function-length.
// The ruleID is the finding's rule and broad marks a security or sensitive-data finding; any other linter name covers nothing.
func nolintLinterCovers(linter, ruleID string, broad bool) bool {
	switch linter {
	case "all":
		return broad || ruleID == functionLengthRule
	case "gosec":
		return broad
	case "funlen":
		return ruleID == functionLengthRule
	}
	return false
}

// zizmorCommentCovers reports whether a zizmor ignore comment on the line names an audit mapped to the rule.
// Audits are comma-separated and trimmed, and ruleID must equal the rule zizmorCheckRules maps an audit to; unknown audits cover nothing.
func zizmorCommentCovers(line, ruleID string) bool {
	for _, match := range zizmorDirective.FindAllStringSubmatch(line, -1) {
		for _, audit := range strings.Split(match[1], ",") {
			if zizmorCheckRules[strings.TrimSpace(audit)] == ruleID {
				return true
			}
		}
	}
	return false
}
