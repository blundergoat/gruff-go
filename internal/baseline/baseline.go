// Package baseline reads, writes, and applies reviewed finding baselines.
// It classifies scan results as new, unchanged, or resolved for CLI and hook
// users while preserving deterministic one-to-one identity matching.
package baseline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// SchemaVersion identifies the on-disk baseline schema accepted by this package.
const SchemaVersion = "gruff-go.baseline.v0.1"

// File is the JSON document containing findings a user has reviewed.
// The baseline command creates it, while analyse and hook consume its entries
// to separate existing debt from issues introduced by the current change.
type File struct {
	// SchemaVersion identifies the on-disk baseline schema; must match SchemaVersion.
	SchemaVersion string `json:"schemaVersion"`
	// Findings lists the accepted finding identities suppressed by Apply.
	Findings []Entry `json:"findings"`
}

// Entry is one reviewed occurrence stored in a user's baseline file.
// Fingerprint supports exact matching; optional StableIdentity lets that same
// occurrence remain reviewed after a line or measured-value change.
type Entry struct {
	// RuleID is the rule whose finding is suppressed.
	RuleID string `json:"ruleId"`
	// File is the repo-relative path the suppressed finding targets.
	File string `json:"file"`
	// Fingerprint is the stable identity hash of the suppressed finding.
	Fingerprint string `json:"fingerprint"`
	// StableIdentity is the hook-contract identity used for value-independent
	// new-only matching. Optional so older baselines still parse and keep their
	// legacy fingerprint semantics.
	StableIdentity string `json:"stableIdentity,omitempty"`
}

// exactMatchKey identifies one exact baseline occurrence by its stored fields.
// Duplicate keys remain separate queue entries, so one reviewed occurrence can
// hide only one current finding in the user's report.
type exactMatchKey struct {
	ruleID      string
	file        string
	fingerprint string
}

// stableMatchKey identifies one line-insensitive contract occurrence.
// It is used only after every possible exact pair has been consumed, and an
// empty stored identity means a legacy entry cannot enter this phase.
type stableMatchKey struct {
	ruleID         string
	file           string
	stableIdentity string
}

// baselinePairing records which current and prior occurrences were consumed.
// Parallel boolean slices keep duplicate rows distinct and let the UI account
// for every finding exactly once without changing the persisted schema.
type baselinePairing struct {
	currentMatched  []bool
	baselineMatched []bool
}

// ApplyResult summarises how a baseline affected a set of findings, classifying
// the run into three states: new (Findings), unchanged (Unchanged), and resolved
// (Resolved). The states are additive over the original suppression surface -
// SuppressedFindings and StaleEntries stay populated and equal UnchangedCount and
// ResolvedCount respectively (see ADR-012).
type ApplyResult struct {
	// Findings holds the surviving findings after baseline suppression - the "new" set.
	Findings []finding.Finding
	// Unchanged holds the current findings that a baseline entry matched (the
	// findings dropped from Findings). Same membership SuppressedFindings counts.
	Unchanged []finding.Finding
	// Resolved holds baseline entries that matched no current finding - findings
	// that were fixed since the baseline was taken. Same membership StaleEntries counts.
	Resolved []Entry
	// SuppressedFindings is the count of findings hidden by matching baseline entries.
	SuppressedFindings int
	// StaleEntries is the count of baseline entries that did not match any current finding.
	StaleEntries int
	// Entries is the total number of entries the baseline contained.
	Entries int
}

// NewCount returns findings the user has not reviewed in this baseline.
// The CLI uses this count in baseline status and finding-gate decisions.
func (result ApplyResult) NewCount() int { return len(result.Findings) }

// UnchangedCount returns current findings paired with reviewed entries.
// The UI reports them as unchanged and normally hides their detail.
func (result ApplyResult) UnchangedCount() int { return len(result.Unchanged) }

// ResolvedCount returns reviewed entries with no current occurrence.
// Users see these as debt that can be removed when refreshing the baseline.
func (result ApplyResult) ResolvedCount() int { return len(result.Resolved) }

// FromFindings builds the deterministic baseline created by the user command.
// Empty input produces a valid baseline with no reviewed entries.
func FromFindings(currentFindings []finding.Finding) File {
	baselineEntries := make([]Entry, 0, len(currentFindings))
	// Persist every current occurrence, including duplicates the user reviewed.
	for _, currentFinding := range currentFindings {
		baselineEntries = append(baselineEntries, Entry{
			RuleID:         currentFinding.RuleID,
			File:           currentFinding.File,
			Fingerprint:    currentFinding.Fingerprint,
			StableIdentity: currentFinding.ComputeContractStableIdentity(),
		})
	}
	slices.SortFunc(baselineEntries, compareEntries)
	return File{SchemaVersion: SchemaVersion, Findings: baselineEntries}
}

// Load reads the baseline path selected by the user and validates its JSON.
// A missing or unreadable path returns an error that becomes a baseline diagnostic.
func Load(baselinePath string) (File, error) {
	// #nosec G304 -- CLI intentionally reads an explicit user-provided baseline path.
	baselineJSON, err := os.ReadFile(baselinePath)
	// A user may have moved, deleted, or lost permission to read the baseline file.
	if err != nil {
		return File{}, err
	}
	return Parse(baselineJSON)
}

// Parse decodes strict baseline JSON and rejects incompatible or incomplete rows.
// Empty or malformed input means the user's reviewed-debt file cannot be trusted.
func Parse(baselineJSON []byte) (File, error) {
	var baselineFile File
	decoder := json.NewDecoder(bytes.NewReader(baselineJSON))
	decoder.DisallowUnknownFields()
	// Truncated or malformed JSON can happen after a manual edit or merge conflict.
	if err := decoder.Decode(&baselineFile); err != nil {
		return File{}, err
	}
	// An unsupported version asks the user to regenerate instead of guessing semantics.
	if baselineFile.SchemaVersion != SchemaVersion {
		return File{}, fmt.Errorf("unsupported schemaVersion %q; expected %q. Regenerate with `gruff-go baseline --out <path>` from a clean scan", baselineFile.SchemaVersion, SchemaVersion)
	}
	// Validate every reviewed occurrence before any one-to-one pairing begins.
	for entryIndex, baselineEntry := range baselineFile.Findings {
		// Missing required identity fields would make the row suppress unpredictably.
		if baselineEntry.RuleID == "" || baselineEntry.File == "" || baselineEntry.Fingerprint == "" {
			return File{}, fmt.Errorf("findings[%d] must include ruleId, file, and fingerprint", entryIndex)
		}
	}
	return baselineFile, nil
}

// Write saves a generated baseline with owner-only permissions.
// Users call it through baseline or analyse --generate-baseline.
func Write(baselinePath string, baselineFile File) error {
	baselineJSON, err := Marshal(baselineFile)
	// Serialization can fail if future entry fields contain unsupported values.
	if err != nil {
		return err
	}
	return os.WriteFile(baselinePath, baselineJSON, 0o600)
}

// Marshal renders readable baseline JSON with a trailing newline.
// The baseline writer uses it before saving the user's reviewed findings.
func Marshal(baselineFile File) ([]byte, error) {
	baselineJSON, err := json.MarshalIndent(baselineFile, "", "  ")
	// A serialization error prevents writing a partial baseline to disk.
	if err != nil {
		return nil, err
	}
	return append(baselineJSON, '\n'), nil
}

// Apply classifies current findings as new or unchanged and prior rows as resolved.
// Analyse and hook use this one-to-one result to hide only reviewed occurrences
// while retaining ADR-012 compatibility counts.
func Apply(currentFindings []finding.Finding, baselineFile File) ApplyResult {
	pairing := pairBaselineOccurrences(currentFindings, baselineFile.Findings)
	kept := make([]finding.Finding, 0, len(currentFindings))
	unchanged := make([]finding.Finding, 0)
	// Preserve scan order while splitting what the user sees from reviewed debt.
	for findingIndex, currentFinding := range currentFindings {
		// A consumed current occurrence appears once in the unchanged UI state.
		if pairing.currentMatched[findingIndex] {
			unchanged = append(unchanged, currentFinding)
			continue
		}
		kept = append(kept, currentFinding)
	}
	resolved := make([]Entry, 0)
	// Keep every unconsumed prior row so duplicate reviewed issues remain visible.
	for entryIndex, baselineEntry := range baselineFile.Findings {
		// A consumed prior occurrence is represented by the unchanged current item.
		if pairing.baselineMatched[entryIndex] {
			continue
		}
		resolved = append(resolved, baselineEntry)
	}
	slices.SortFunc(resolved, compareEntries)
	return ApplyResult{
		Findings:           kept,
		Unchanged:          unchanged,
		Resolved:           resolved,
		SuppressedFindings: len(unchanged),
		StaleEntries:       len(resolved),
		Entries:            len(baselineFile.Findings),
	}
}

// pairBaselineOccurrences consumes exact pairs first, then contract-stable pairs.
// The returned state drives all new, unchanged, and resolved UI counts.
func pairBaselineOccurrences(currentFindings []finding.Finding, baselineEntries []Entry) baselinePairing {
	pairing := baselinePairing{
		currentMatched:  make([]bool, len(currentFindings)),
		baselineMatched: make([]bool, len(baselineEntries)),
	}
	pairExactOccurrences(currentFindings, baselineEntries, &pairing)
	pairStableOccurrences(currentFindings, baselineEntries, &pairing)
	return pairing
}

// pairExactOccurrences consumes one queued prior index for each exact current key.
// This phase preserves legacy baseline behavior and always wins over line shifts.
func pairExactOccurrences(currentFindings []finding.Finding, baselineEntries []Entry, pairing *baselinePairing) {
	entryIndicesByIdentity := map[exactMatchKey][]int{}
	// Queue every baseline row in input order instead of collapsing duplicate keys.
	for entryIndex, baselineEntry := range baselineEntries {
		identity := baselineEntry.exactMatchKey()
		entryIndicesByIdentity[identity] = append(entryIndicesByIdentity[identity], entryIndex)
	}
	nextEntryByIdentity := map[exactMatchKey]int{}
	// Consume at most one queued prior occurrence for each current finding.
	for findingIndex, currentFinding := range currentFindings {
		identity := exactMatchKey{ruleID: currentFinding.RuleID, file: currentFinding.File, fingerprint: currentFinding.Fingerprint}
		candidateEntryIndices := entryIndicesByIdentity[identity]
		nextEntryOffset := nextEntryByIdentity[identity]
		// No remaining exact occurrence means the user may still get a stable match.
		if nextEntryOffset >= len(candidateEntryIndices) {
			continue
		}
		matchedEntryIndex := candidateEntryIndices[nextEntryOffset]
		nextEntryByIdentity[identity] = nextEntryOffset + 1
		pairing.currentMatched[findingIndex] = true
		pairing.baselineMatched[matchedEntryIndex] = true
	}
}

// pairStableOccurrences consumes remaining rows by contract-stable identity.
// Users keep reviewed findings across line or measured-value changes one-for-one.
func pairStableOccurrences(currentFindings []finding.Finding, baselineEntries []Entry, pairing *baselinePairing) {
	entryIndicesByIdentity := map[stableMatchKey][]int{}
	// Only unmatched modern entries can participate in line-insensitive pairing.
	for entryIndex, baselineEntry := range baselineEntries {
		// Exact matches cannot be reused, and empty identities are legacy exact-only rows.
		if pairing.baselineMatched[entryIndex] || baselineEntry.StableIdentity == "" || !ruleAllowsContractStableMatch(baselineEntry.RuleID) {
			continue
		}
		identity := stableMatchKey{ruleID: baselineEntry.RuleID, file: baselineEntry.File, stableIdentity: baselineEntry.StableIdentity}
		entryIndicesByIdentity[identity] = append(entryIndicesByIdentity[identity], entryIndex)
	}
	nextEntryByIdentity := map[stableMatchKey]int{}
	// Match each still-new current occurrence against one remaining prior row.
	for findingIndex, currentFinding := range currentFindings {
		// A current finding already paired exactly must not consume a second entry.
		if pairing.currentMatched[findingIndex] || !findingAllowsContractStableMatch(currentFinding) {
			continue
		}
		identity := stableMatchKey{
			ruleID:         currentFinding.RuleID,
			file:           currentFinding.File,
			stableIdentity: currentFinding.ComputeContractStableIdentity(),
		}
		candidateEntryIndices := entryIndicesByIdentity[identity]
		nextEntryOffset := nextEntryByIdentity[identity]
		// No remaining semantic occurrence leaves this finding visible as new.
		if nextEntryOffset >= len(candidateEntryIndices) {
			continue
		}
		matchedEntryIndex := candidateEntryIndices[nextEntryOffset]
		nextEntryByIdentity[identity] = nextEntryOffset + 1
		pairing.currentMatched[findingIndex] = true
		pairing.baselineMatched[matchedEntryIndex] = true
	}
}

// ruleAllowsContractStableMatch keeps sensitive findings exact-only. Baseline
// entries do not persist symbols, so generic security filtering happens when
// the current finding supplies its semantic subject below.
func ruleAllowsContractStableMatch(ruleID string) bool {
	return !strings.HasPrefix(ruleID, "sensitive-data.")
}

// findingAllowsContractStableMatch requires generic security findings to match
// exact locations while preserving line shifts for a named security subject.
func findingAllowsContractStableMatch(currentFinding finding.Finding) bool {
	if !ruleAllowsContractStableMatch(currentFinding.RuleID) {
		return false
	}
	return !strings.HasPrefix(currentFinding.RuleID, "security.") || currentFinding.Symbol != ""
}

// exactMatchKey returns the persisted fingerprint identity for one prior row.
// Empty fields cannot occur after Parse but remain deterministic in memory tests.
func (entry Entry) exactMatchKey() exactMatchKey {
	return exactMatchKey{ruleID: entry.RuleID, file: entry.File, fingerprint: entry.Fingerprint}
}

// compareEntries orders baseline entries by (file, ruleId, fingerprint), the same
// ordering FromFindings uses, so Resolved is deterministic across runs.
func compareEntries(leftEntry, rightEntry Entry) int {
	// File order keeps baseline rows grouped where users will edit them.
	if leftEntry.File != rightEntry.File {
		return strings.Compare(leftEntry.File, rightEntry.File)
	}
	// Rule order makes duplicate categories deterministic within one file.
	if leftEntry.RuleID != rightEntry.RuleID {
		return strings.Compare(leftEntry.RuleID, rightEntry.RuleID)
	}
	return strings.Compare(leftEntry.Fingerprint, rightEntry.Fingerprint)
}
