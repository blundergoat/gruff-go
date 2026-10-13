package analysis

import (
	"regexp"
	"sort"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// SuppressionSourceInline marks an audit row that another tool's suppression comment produced.
const SuppressionSourceInline = "inline"

// InlineSuppressionReason is the reason on each inline audit row; every port publishes these exact words
// (FAMILY-CONTRACT.md section 13c).
const InlineSuppressionReason = "Another tool's suppression comment names this check, so the finding is suppressed where it was written."

// SuppressedFinding is a finding another tool's comment suppressed. It leaves the findings list and the score, and
// SARIF keeps it as a result marked suppressed, so a code-scanning tool shows it as suppressed rather than fixed.
type SuppressedFinding struct {
	// Finding is the suppressed finding as the rule reported it.
	Finding finding.Finding
	// Justification is the audit reason a SARIF reader sees on the suppressed result.
	Justification string
}

// gosecCheckRules maps each gosec check section 13c names for gruff-go to the rule that makes the same claim;
// G101, hard-coded credentials, covers every sensitive-data rule instead (gosecCredentialCheck).
var gosecCheckRules = map[string]string{
	"G112": "security.http-server-no-timeout",
	"G402": "security.tls-insecure-config",
	"G204": "security.shell-command",
}

// zizmorCheckRules maps each zizmor audit section 13c names to the workflow rule that makes the same claim.
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

// zizmorDirective matches zizmor's `# zizmor: ignore[unpinned-uses]` and its audit list.
var zizmorDirective = regexp.MustCompile(`#\s*zizmor:\s*ignore\[([^\]]*)\]`)

// ApplyInlineSuppressions removes each finding another tool's suppression comment covers and counts it in one
// inline audit row per file and rule.
//
// The comment must sit on the reported line, or alone on the line directly above it, and name a check section 13c
// maps to the finding's rule: `#nosec G204` above `exec.Command("sh", "-c", script)` suppresses
// security.shell-command there and nothing else. The rows follow the built-in rows and continue their numbering.
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

// sourcesByFile indexes each parsed file's text by its project-relative path, the path a finding carries.
func sourcesByFile(units []parser.Unit) map[string]string {
	sources := make(map[string]string, len(units))
	for _, unit := range units {
		sources[unit.File.Path] = unit.Source
	}
	return sources
}

// isSuppressedInline reports whether the finding's own line, or a comment-only line directly above it, carries a
// comment naming a check that makes the finding's claim. A file-level finding has no line to carry one.
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
	isCommentOnly := strings.HasPrefix(above, "//") || strings.HasPrefix(above, "#") || strings.HasPrefix(above, "/*")
	return isCommentOnly && inlineCommentCovers(above, item)
}

// inlineCommentCovers reports whether one line names a check section 13c maps to the finding's rule.
//
// A bare `#nosec`, `//nolint`, `//nolint:all` or `//nolint:gosec` covers every security and sensitive-data rule,
// as gosec and golangci-lint read them; a bare `//nolint` or `//nolint:all` also covers `funlen`. A `#nosec` naming
// checks covers only the checks the table lists, so `#nosec G304` covers nothing and `#nosec G101` covers every
// sensitive-data rule.
func inlineCommentCovers(line string, item finding.Finding) bool {
	broad := item.Pillar == finding.PillarSecurity || strings.HasPrefix(item.RuleID, "sensitive-data.")
	return gosecCommentCovers(line, item.RuleID, broad) || nolintCommentCovers(line, item.RuleID, broad) ||
		zizmorCommentCovers(line, item.RuleID)
}

// gosecCommentCovers reports whether a `#nosec` on the line covers the rule: bare, it covers every security and
// sensitive-data rule (broad); with checks, only the rules those checks map to, G101 mapping to every
// sensitive-data rule.
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

// nolintCommentCovers reports whether a `//nolint` on the line covers the rule; a bare `//nolint` reads as `all`.
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

// nolintLinterCovers reports whether one golangci-lint linter name covers the rule: `all` and `gosec` cover every
// security and sensitive-data rule, and `all` and `funlen` cover size.function-length.
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

// zizmorCommentCovers reports whether a `# zizmor: ignore[...]` on the line names an audit mapped to the rule.
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
