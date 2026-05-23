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

// ApplyResult summarises how a baseline affected a set of findings.
type ApplyResult struct {
	// Findings holds the surviving findings after baseline suppression.
	Findings []finding.Finding
	// SuppressedFindings is the count of findings hidden by matching baseline entries.
	SuppressedFindings int
	// StaleEntries is the count of baseline entries that did not match any current finding.
	StaleEntries int
	// Entries is the total number of entries the baseline contained.
	Entries int
}

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
	slices.SortFunc(entries, func(a, b Entry) int {
		if a.File != b.File {
			return strings.Compare(a.File, b.File)
		}
		if a.RuleID != b.RuleID {
			return strings.Compare(a.RuleID, b.RuleID)
		}
		return strings.Compare(a.Fingerprint, b.Fingerprint)
	})
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
		return File{}, fmt.Errorf("unsupported schemaVersion %q", file.SchemaVersion)
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

// Apply suppresses findings present in the baseline and reports stale entries.
func Apply(findings []finding.Finding, file File) ApplyResult {
	entries := map[Entry]struct{}{}
	for _, entry := range file.Findings {
		entries[entry] = struct{}{}
	}
	matched := map[Entry]struct{}{}
	kept := make([]finding.Finding, 0, len(findings))
	suppressed := 0
	for _, item := range findings {
		entry := Entry{RuleID: item.RuleID, File: item.File, Fingerprint: item.Fingerprint}
		if _, ok := entries[entry]; ok {
			matched[entry] = struct{}{}
			suppressed++
			continue
		}
		kept = append(kept, item)
	}
	return ApplyResult{
		Findings:           kept,
		SuppressedFindings: suppressed,
		StaleEntries:       len(entries) - len(matched),
		Entries:            len(entries),
	}
}
