// Package baseline reads, writes, and applies finding baselines.
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

const SchemaVersion = "gruff-go.baseline.v0.1"

type File struct {
	SchemaVersion string  `json:"schemaVersion"`
	Findings      []Entry `json:"findings"`
}

type Entry struct {
	RuleID      string `json:"ruleId"`
	File        string `json:"file"`
	Fingerprint string `json:"fingerprint"`
}

type ApplyResult struct {
	Findings           []finding.Finding
	SuppressedFindings int
	StaleEntries       int
	Entries            int
}

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

func Load(path string) (File, error) {
	// #nosec G304 -- CLI intentionally reads an explicit user-provided baseline path.
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	return Parse(data)
}

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

func Write(path string, file File) error {
	data, err := Marshal(file)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func Marshal(file File) ([]byte, error) {
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

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
