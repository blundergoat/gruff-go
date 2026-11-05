// Package analysis applies the ratified sensitive-data exclusion contract and the built-in test-path skip.
//
// A configured exclusion names one sensitive-data rule and one project-relative path, and carries a written rationale.
// It is always counted: an entry that matched nothing reports zero rather than disappearing (FAMILY-CONTRACT.md section 13a).
//
// The built-in skip hides sensitive-data and security findings in test, fixture and example files, and publishes every skip as an audit row.
package analysis

import (
	"regexp"
	"sort"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// BuiltInTestPathReason is the reason a user reads on each sensitive-data builtInTestPath audit row; every port publishes these exact words.
const BuiltInTestPathReason = "Test, fixture and example files hold sample credentials, so sensitive-data rules skip them by path."

// BuiltInSecurityTestPathReason is the reason on each security builtInTestPath audit row; every port publishes these exact words.
const BuiltInSecurityTestPathReason = "Test, fixture and example files exercise insecure calls on purpose, so security rules skip them by path."

// builtInTestPathExemptRule is the family's fixture-PII rule, which keeps reading test paths; gruff-go has no rule with this id.
const builtInTestPathExemptRule = "sensitive-data.pii-test-fixture"

// builtInTestPathDirectories are directory names, compared case-insensitively, that make a path test code, e.g. `testdata/` or `Examples/`.
var builtInTestPathDirectories = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "spec": true, "testdata": true, "fixtures": true, "examples": true,
}

// builtInTestFileName matches a whole base name that marks a test file in any family language, e.g. `keys_test.go` or `login.spec.ts`.
var builtInTestFileName = regexp.MustCompile(`^(?:.*_test\.go|test_.*\.py|.*_test\.py|.*Test\.php|.*\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs))$`)

// SuppressionSourceBuiltIn marks an audit row the family's built-in test-path skip produced (section 13a).
const SuppressionSourceBuiltIn = "built-in"

// SensitiveExclusion is one validated sensitive-data suppression scope the user configured.
//
// The config package owns validation: every field was already checked against the closed key set, the rule catalogue and the path rules.
// A finding is suppressed only when its rule ID, display path and any configured symbol all match exactly.
type SensitiveExclusion struct {
	// Rule is the exact rule ID a finding must carry to be suppressed.
	Rule string
	// Path is the project-relative display path a finding must carry.
	Path string
	// Symbol narrows the scope to findings carrying that exact symbol; empty matches any.
	Symbol string
	// Reason is the configured rationale republished in the audit row.
	Reason string
}

// SuppressionSummary is one audit row: a configured, built-in test-path or inline suppression scope and the number of findings it removed.
//
// It carries scope and rationale text only, never a finding message, preview or matched value (FAMILY-CONTRACT.md section 5).
// Configured entries always get a row, so one that matched nothing reports zero.
type SuppressionSummary struct {
	// Index is the configured entry's position; built-in and inline rows share a separate sequence, built-in first.
	Index int `json:"index"`
	// Rule is the rule ID whose findings the row counts.
	Rule string `json:"rule"`
	// Paths carries the scope's single display path in the family array shape; a scan input outside the analysis root can leave it absolute.
	Paths []string `json:"paths"`
	// Symbol is the configured symbol narrowing, nil when the entry has none; the hook audit row then omits the symbol key.
	Symbol *string `json:"symbol"`
	// Reason is the rationale a reviewer reads instead of the finding: the configured text, or fixed built-in or inline policy wording.
	Reason string `json:"reason"`
	// Suppressed counts the findings this entry removed from the report.
	Suppressed int `json:"suppressed"`
	// Source is "built-in" for a test-path skip, "inline" for another tool's comment, and empty for a configured entry.
	Source string `json:"source,omitempty"`
}

// ApplySensitiveExclusions removes every finding a configured entry claims and returns the survivors with one audit row per entry.
//
// A finding is suppressed only when the rule ID, the project-relative display path and any configured symbol all match exactly.
// No part of the finding's message or matched value takes part in the decision.
//
// findings is read but never modified, and exclusions are the validated configured entries, whose positions become the rows' Index values.
// With no exclusions it returns findings itself and an empty, non-nil row slice.
func ApplySensitiveExclusions(findings []finding.Finding, exclusions []SensitiveExclusion) ([]finding.Finding, []SuppressionSummary) {
	summaries := newSuppressionSummaries(exclusions)
	if len(exclusions) == 0 {
		return findings, summaries
	}
	kept := make([]finding.Finding, 0, len(findings))
	for _, item := range findings {
		index, claimed := claimingSensitiveExclusion(exclusions, item)
		if !claimed {
			kept = append(kept, item)
			continue
		}
		summaries[index].Suppressed++
	}
	return kept, summaries
}

// ApplyBuiltInTestPathSkip hides sensitive-data and security findings in test, fixture and example code, publishing one row per file and rule.
//
// A user with sample keys or a deliberate shell call under testdata/ sees builtInTestPath audit rows instead, so the skip is never silent.
// It covers every gruff-go sensitive-data rule, pii-pattern included, and every security rule (FAMILY-CONTRACT.md section 13a).
//
// findings is read but not modified, and summaries holds the audit rows so far; new rows are numbered after the built-in rows already in it.
// It returns the findings that stay, in their original order, and summaries with the new rows appended in path then rule ID order.
// When no finding is skipped, summaries comes back unchanged.
func ApplyBuiltInTestPathSkip(findings []finding.Finding, summaries []SuppressionSummary) ([]finding.Finding, []SuppressionSummary) {
	// A rule has one pillar, so carrying it in the key adds no rows; it picks the row's reason.
	type fileAndRule struct {
		file, rule string
		security   bool
	}
	skippedCountByFileAndRule := map[fileAndRule]int{}
	kept := make([]finding.Finding, 0, len(findings))
	// Each finding either stays in the report or is folded into its file's audit row.
	for _, item := range findings {
		// Only the two pillars' findings in test code are skipped, and never the family's fixture-PII rule.
		if isSkippedOnTestPaths(item) && IsBuiltInTestPath(item.File) {
			skippedCountByFileAndRule[fileAndRule{item.File, item.RuleID, item.Pillar == finding.PillarSecurity}]++
			continue
		}
		kept = append(kept, item)
	}
	skippedFilesAndRules := make([]fileAndRule, 0, len(skippedCountByFileAndRule))
	for skipped := range skippedCountByFileAndRule {
		skippedFilesAndRules = append(skippedFilesAndRules, skipped)
	}
	// Byte order, path first and then rule id, is the order every port publishes these rows in.
	sort.Slice(skippedFilesAndRules, func(left, right int) bool {
		if skippedFilesAndRules[left].file != skippedFilesAndRules[right].file {
			return skippedFilesAndRules[left].file < skippedFilesAndRules[right].file
		}
		return skippedFilesAndRules[left].rule < skippedFilesAndRules[right].rule
	})
	// Built-in rows are numbered among themselves, so a test-path row follows any built-in row already in summaries.
	nextIndex := 0
	for _, summary := range summaries {
		if summary.Source == SuppressionSourceBuiltIn {
			nextIndex++
		}
	}
	// One row per file and rule; text output shows it as builtInTestPath with the file in brackets, then the rule ID and the count.
	for offset, skipped := range skippedFilesAndRules {
		summaries = append(summaries, SuppressionSummary{
			Index:      nextIndex + offset,
			Rule:       skipped.rule,
			Paths:      []string{skipped.file},
			Reason:     builtInTestPathReasonFor(skipped.security),
			Suppressed: skippedCountByFileAndRule[skipped],
			Source:     SuppressionSourceBuiltIn,
		})
	}
	return kept, summaries
}

// isSkippedOnTestPaths reports whether the test-path skip covers item, judging only its Pillar and RuleID; IsBuiltInTestPath checks the path.
//
// It covers every sensitive-data rule except the fixture-PII rule, and every security-pillar rule, dependency.go-mod-local-replace included.
// A false result means this skip leaves the finding in place, even when it sits in test code.
func isSkippedOnTestPaths(item finding.Finding) bool {
	if item.Pillar == finding.PillarSecurity {
		return true
	}
	return strings.HasPrefix(item.RuleID, "sensitive-data.") && item.RuleID != builtInTestPathExemptRule
}

// builtInTestPathReasonFor returns the audit reason for a skipped finding; security is true when the finding is in the security pillar.
// A security row says a test may call an insecure API on purpose, rather than repeating the sample-credential reason.
func builtInTestPathReasonFor(security bool) string {
	if security {
		return BuiltInSecurityTestPathReason
	}
	return BuiltInTestPathReason
}

// IsBuiltInTestPathReason reports whether reason belongs to a test-path audit row, of either pillar.
func IsBuiltInTestPathReason(reason string) bool {
	return reason == BuiltInTestPathReason || reason == BuiltInSecurityTestPathReason
}

// IsBuiltInTestPath reports whether displayPath is test, fixture or example code, such as testdata/keys.json or keys_test.go.
//
// displayPath may use slash or backslash separators; a directory segment listed in builtInTestPathDirectories matches regardless of ASCII case.
// Otherwise only the base name decides, by matching builtInTestFileName.
func IsBuiltInTestPath(displayPath string) bool {
	segments := strings.Split(strings.ReplaceAll(displayPath, "\\", "/"), "/")
	// Any directory on the path, compared case-insensitively over ASCII letters as every port does, can make it test code.
	for _, directory := range segments[:len(segments)-1] {
		if builtInTestPathDirectories[asciiLower(directory)] {
			return true
		}
	}
	// Otherwise the file name alone must mark a test, e.g. `keys_test.go` or `KeysTest.php`.
	return builtInTestFileName.MatchString(segments[len(segments)-1])
}

// asciiLower lowercases only A-Z, so a directory such as `FİXTURES` stays unmatched, as it does in the other ports.
// It returns value with each ASCII capital letter lowered and every other rune, non-ASCII capitals included, unchanged.
func asciiLower(value string) string {
	return strings.Map(func(character rune) rune {
		if character >= 'A' && character <= 'Z' {
			return character + ('a' - 'A')
		}
		return character
	}, value)
}

// newSuppressionSummaries seeds one zeroed audit row per configured entry, so an entry whose scope matches nothing still publishes a row.
//
// The slice is never nil, so consumers read an empty JSON array rather than a null.
// It returns one row per entry of exclusions, in order, carrying its rule, path, reason and position, with a nil Symbol when the entry names none.
// With no exclusions the result is an empty slice.
func newSuppressionSummaries(exclusions []SensitiveExclusion) []SuppressionSummary {
	summaries := make([]SuppressionSummary, 0, len(exclusions))
	for index, exclusion := range exclusions {
		var symbol *string
		// An entry without a symbol keeps Symbol nil, which the hook audit row turns into an omitted symbol key.
		if exclusion.Symbol != "" {
			narrowed := exclusion.Symbol
			symbol = &narrowed
		}
		summaries = append(summaries, SuppressionSummary{
			Index:      index,
			Rule:       exclusion.Rule,
			Paths:      []string{exclusion.Path},
			Symbol:     symbol,
			Reason:     exclusion.Reason,
			Suppressed: 0,
		})
	}
	return summaries
}

// claimingSensitiveExclusion returns the index of the first entry in exclusions that claims item, so each finding is counted once.
//
// Validation rejects only an exact repeat of rule, path and symbol, so a symbol-free entry and one naming the finding's symbol can both match.
// The earlier entry in exclusions then wins and gets the count.
//
// exclusions are the configured entries and item is the finding tested; the bool is false, with index zero, when no entry claims it.
func claimingSensitiveExclusion(exclusions []SensitiveExclusion, item finding.Finding) (int, bool) {
	for index, exclusion := range exclusions {
		if sensitiveExclusionClaims(exclusion, item) {
			return index, true
		}
	}
	return 0, false
}

// sensitiveExclusionClaims reports whether exclusion's declared scope covers item, the finding being tested.
//
// An absent symbol matches any finding; a configured symbol must match exactly.
// So an entry carrying one legitimately claims nothing on a pillar whose findings stamp no symbol, and the user sees zero on its row.
//
// exclusion claims item only when its Rule equals the finding's RuleID and its Path equals the finding's File, before any Symbol check.
func sensitiveExclusionClaims(exclusion SensitiveExclusion, item finding.Finding) bool {
	if exclusion.Rule != item.RuleID || exclusion.Path != item.File {
		return false
	}
	return exclusion.Symbol == "" || exclusion.Symbol == item.Symbol
}
