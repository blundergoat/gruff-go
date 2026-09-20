// Package analysis applies the ratified sensitive-data exclusion contract.
// A configured exclusion names one sensitive-data rule and one project-relative
// path, carries a written rationale, and is always counted: an entry that
// matched nothing reports zero rather than disappearing
// (FAMILY-CONTRACT.md section 13a).
package analysis

import (
	"path"
	"path/filepath"
	"sort"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// BuiltInLockfileRule is the one rule the built-in lockfile skip covers. Every other sensitive-data rule still
// reads a lockfile, because a credential pasted into one is as live as anywhere else.
const BuiltInLockfileRule = "sensitive-data.high-entropy-string"

// BuiltInLockfileReason is the rationale every port publishes on a built-in lockfile audit row.
const BuiltInLockfileReason = "Lockfile digests are published integrity hashes, so the entropy rule skips package-manager lockfiles by name."

// SuppressionSourceBuiltIn marks an audit row no configured entry produced.
const SuppressionSourceBuiltIn = "built-in"

// builtInLockfileNames is the ratified list of package-manager lockfiles, matched by exact base name at any depth.
var builtInLockfileNames = map[string]bool{
	"package-lock.json":   true,
	"npm-shrinkwrap.json": true,
	"yarn.lock":           true,
	"pnpm-lock.yaml":      true,
	"composer.lock":       true,
	"Cargo.lock":          true,
	"go.sum":              true,
	"uv.lock":             true,
	"poetry.lock":         true,
}

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

// ApplyBuiltInLockfileSkip removes the entropy rule's findings from package-manager lockfiles and appends one audit
// row per lockfile that had any, after the configured rows. A lockfile digest is a published integrity hash, and a
// real project carries thousands of them; the skip is counted on every surface rather than applied in silence, and
// a lockfile with nothing to skip publishes no row (FAMILY-CONTRACT.md section 13a).
func ApplyBuiltInLockfileSkip(findings []finding.Finding, summaries []SuppressionSummary) ([]finding.Finding, []SuppressionSummary) {
	skippedByPath := map[string]int{}
	kept := make([]finding.Finding, 0, len(findings))
	for _, item := range findings {
		// A display path may carry a Windows separator, which path.Base does not split on, so it is normalised
		// first: php, py and rs normalise too, and a lockfile must be one lockfile in every port.
		if item.RuleID == BuiltInLockfileRule && builtInLockfileNames[path.Base(filepath.ToSlash(item.File))] {
			skippedByPath[item.File]++
			continue
		}
		kept = append(kept, item)
	}
	// Built-in rows are numbered among themselves, so the index means the same thing in every port however many
	// entries the user configured. `source` is what tells a consumer which channel a row came from.
	paths := make([]string, 0, len(skippedByPath))
	for lockfile := range skippedByPath {
		paths = append(paths, lockfile)
	}
	sort.Strings(paths)
	for builtInIndex, lockfile := range paths {
		summaries = append(summaries, SuppressionSummary{
			Index:      builtInIndex,
			Rule:       BuiltInLockfileRule,
			Paths:      []string{lockfile},
			Reason:     BuiltInLockfileReason,
			Suppressed: skippedByPath[lockfile],
			Source:     SuppressionSourceBuiltIn,
		})
	}
	return kept, summaries
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
