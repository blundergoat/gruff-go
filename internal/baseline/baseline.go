// Package baseline reads, writes, and applies finding baselines.
// It supports suppressing previously accepted findings by fingerprint match.
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

// File is the persisted baseline document containing accepted findings.
type File struct {
	// SchemaVersion identifies the on-disk baseline schema; must match SchemaVersion.
	SchemaVersion string `json:"schemaVersion"`
	// Findings lists the accepted finding identities suppressed by Apply.
	Findings []Entry `json:"findings"`
}

// Entry is a single accepted finding identified by rule, file, and fingerprint.
type Entry struct {
	// RuleID is the rule whose finding is suppressed.
	RuleID string `json:"ruleId"`
	// File is the repo-relative path the suppressed finding targets.
	File string `json:"file"`
	// Fingerprint is the stable identity hash of the suppressed finding.
	Fingerprint string `json:"fingerprint"`
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

// NewCount returns the number of new findings (current findings absent from the baseline).
func (r ApplyResult) NewCount() int { return len(r.Findings) }

// UnchangedCount returns the number of unchanged findings (current findings the baseline matched).
func (r ApplyResult) UnchangedCount() int { return len(r.Unchanged) }

// ResolvedCount returns the number of resolved findings (baseline entries no current finding matched).
func (r ApplyResult) ResolvedCount() int { return len(r.Resolved) }

// FromFindings builds a baseline File from the supplied findings, sorted deterministically.
func FromFindings(findings []finding.Finding) File {
	entries := make([]Entry, 0, len(findings))
	for _, item := range findings {
		entries = append(entries, Entry{
			RuleID:      item.RuleID,
			File:        item.File,
			Fingerprint: item.Fingerprint,
		})
	}
	slices.SortFunc(entries, compareEntries)
	return File{SchemaVersion: SchemaVersion, Findings: entries}
}

// Load reads and parses a baseline File from the given filesystem path.
func Load(path string) (File, error) {
	// #nosec G304 -- CLI intentionally reads an explicit user-provided baseline path.
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	return Parse(data)
}

// Parse decodes baseline JSON bytes into a validated File.
func Parse(data []byte) (File, error) {
	var file File
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return File{}, err
	}
	if file.SchemaVersion != SchemaVersion {
		return File{}, fmt.Errorf("unsupported schemaVersion %q; expected %q. Regenerate with `gruff-go baseline --out <path>` from a clean scan", file.SchemaVersion, SchemaVersion)
	}
	for index, entry := range file.Findings {
		if entry.RuleID == "" || entry.File == "" || entry.Fingerprint == "" {
			return File{}, fmt.Errorf("findings[%d] must include ruleId, file, and fingerprint", index)
		}
	}
	return file, nil
}

// Write serialises the baseline File to disk at path with restricted permissions.
func Write(path string, file File) error {
	data, err := Marshal(file)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Marshal encodes the baseline File as indented JSON with a trailing newline.
func Marshal(file File) ([]byte, error) {
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Apply classifies findings against the baseline: kept findings are new,
// matched findings are unchanged, and baseline entries that matched nothing are
// resolved. It collects each set in addition to the legacy counts so callers can
// render the three states without re-running the match (ADR-012).
func Apply(findings []finding.Finding, file File) ApplyResult {
	entries := map[Entry]struct{}{}
	for _, entry := range file.Findings {
		entries[entry] = struct{}{}
	}
	matched := map[Entry]struct{}{}
	kept := make([]finding.Finding, 0, len(findings))
	unchanged := make([]finding.Finding, 0)
	for _, item := range findings {
		entry := Entry{RuleID: item.RuleID, File: item.File, Fingerprint: item.Fingerprint}
		if _, ok := entries[entry]; ok {
			matched[entry] = struct{}{}
			unchanged = append(unchanged, item)
			continue
		}
		kept = append(kept, item)
	}
	resolved := make([]Entry, 0, len(entries)-len(matched))
	for _, entry := range file.Findings {
		if _, ok := matched[entry]; !ok {
			resolved = append(resolved, entry)
		}
	}
	slices.SortFunc(resolved, compareEntries)
	return ApplyResult{
		Findings:           kept,
		Unchanged:          unchanged,
		Resolved:           resolved,
		SuppressedFindings: len(unchanged),
		StaleEntries:       len(resolved),
		Entries:            len(entries),
	}
}

// compareEntries orders baseline entries by (file, ruleId, fingerprint), the same
// ordering FromFindings uses, so Resolved is deterministic across runs.
func compareEntries(a, b Entry) int {
	if a.File != b.File {
		return strings.Compare(a.File, b.File)
	}
	if a.RuleID != b.RuleID {
		return strings.Compare(a.RuleID, b.RuleID)
	}
	return strings.Compare(a.Fingerprint, b.Fingerprint)
}
