// Package analysis applies the ratified sensitive-data exclusion contract.
// A configured exclusion names one sensitive-data rule and one project-relative
// path, carries a written rationale, and is always counted: an entry that
// matched nothing reports zero rather than disappearing
// (FAMILY-CONTRACT.md section 13a).
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

// SuppressionSourceBuiltIn marks an audit row no configured entry produced.
const SuppressionSourceBuiltIn = "built-in"

// SensitiveExclusion is one validated sensitive-data suppression scope. The
// config package owns validation, so every field here has already been checked
// against the closed key set, the rule catalogue, and the path rules.
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

// SuppressionSummary is one audit row: the configured scope plus the number of
// findings it removed this run. It carries configuration text only - never a
// message excerpt, preview, or matched value (FAMILY-CONTRACT.md section 5).
type SuppressionSummary struct {
	// Index is the entry's position in the configured sensitiveExclusions list.
	Index int `json:"index"`
	// Rule is the configured rule ID.
	Rule string `json:"rule"`
	// Paths carries the entry's single configured path in the family array shape.
	Paths []string `json:"paths"`
	// Symbol is the configured symbol narrowing, or null when the entry has none.
	Symbol *string `json:"symbol"`
	// Reason is the configured rationale a reviewer reads instead of the finding.
	Reason string `json:"reason"`
	// Suppressed counts the findings this entry removed from the report.
	Suppressed int `json:"suppressed"`
	// Source is "built-in" on a row the family's lockfile skip produced, and empty on a configured entry's row.
	Source string `json:"source,omitempty"`
}

// ApplySensitiveExclusions removes every finding a configured entry claims and
// returns the survivors together with one audit row per entry. A finding is
// suppressed only when the rule ID, the project-relative display path, and any
// configured symbol all match exactly, so no part of the finding's message or
// matched value can take part in the decision.
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

// ApplyBuiltInTestPathSkip hides sensitive-data and security findings in test, fixture and example files, and publishes one audit row per hidden file and rule.
//
// A user scanning a project with sample keys or a deliberate shell call in `testdata/` sees builtInTestPath[...] rows instead of findings.
// The skip is never silent, and it covers every gruff-go sensitive-data rule, pii-pattern included, and every security rule (FAMILY-CONTRACT.md section 13a).
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
	// Built-in rows are numbered among themselves, so the first test-path row follows the last lockfile row.
	nextIndex := 0
	for _, summary := range summaries {
		if summary.Source == SuppressionSourceBuiltIn {
			nextIndex++
		}
	}
	// One row per file and rule, which text output shows as `builtInTestPath[testdata/keys.json] sensitive-data.aws-access-key: 2`.
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

// isSkippedOnTestPaths reports whether the test-path class covers a finding: every sensitive-data rule except the
// fixture-PII rule, and every security-pillar rule, `dependency.go-mod-local-replace` included.
func isSkippedOnTestPaths(item finding.Finding) bool {
	if item.Pillar == finding.PillarSecurity {
		return true
	}
	return strings.HasPrefix(item.RuleID, "sensitive-data.") && item.RuleID != builtInTestPathExemptRule
}

// builtInTestPathReasonFor returns the audit reason for a skipped finding, so a security row says why a test may call
// an insecure API on purpose rather than repeating the sample-credential reason.
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

// IsBuiltInTestPath reports whether a finding's file is test, fixture or example code, e.g. a file under `testdata/` or one named `keys_test.go`.
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
func asciiLower(value string) string {
	return strings.Map(func(character rune) rune {
		if character >= 'A' && character <= 'Z' {
			return character + ('a' - 'A')
		}
		return character
	}, value)
}

// newSuppressionSummaries seeds one zeroed audit row per configured entry, so an
// entry whose scope matches nothing still publishes a row. The slice is never
// nil: consumers read an empty JSON array rather than a null.
func newSuppressionSummaries(exclusions []SensitiveExclusion) []SuppressionSummary {
	summaries := make([]SuppressionSummary, 0, len(exclusions))
	for index, exclusion := range exclusions {
		var symbol *string
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

// claimingSensitiveExclusion returns the index of the first entry that claims
// the finding. Validation rejects duplicate scopes, so at most one entry can
// claim any finding and the first match is the only match.
func claimingSensitiveExclusion(exclusions []SensitiveExclusion, item finding.Finding) (int, bool) {
	for index, exclusion := range exclusions {
		if sensitiveExclusionClaims(exclusion, item) {
			return index, true
		}
	}
	return 0, false
}

// sensitiveExclusionClaims reports whether one entry's declared scope covers the
// finding. An absent symbol matches any finding; a configured symbol must match
// exactly, which is why an entry carrying one legitimately claims nothing on a
// pillar whose findings stamp no symbol.
func sensitiveExclusionClaims(exclusion SensitiveExclusion, item finding.Finding) bool {
	if exclusion.Rule != item.RuleID || exclusion.Path != item.File {
		return false
	}
	return exclusion.Symbol == "" || exclusion.Symbol == item.Symbol
}
