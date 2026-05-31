// Package rule defines gruff-go's rule registry and analysers.
// This file implements the composite design rule that derives a finding from other findings.
package rule

import (
	"slices"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// Default thresholds for the design.hotspot-file composite rule.
const (
	hotspotFileMinFindings = 3
	hotspotFileMinPillars  = 2
)

// DesignHotspotFileRule flags files whose findings cross multiple quality pillars.
type DesignHotspotFileRule struct {
	// MinFindings is the minimum count of underlying findings a file needs before the composite fires.
	MinFindings int
	// MinPillars is the minimum number of distinct quality pillars those findings must span.
	MinPillars int
}

// minFindings returns the effective minimum-finding threshold for the hotspot rule.
func (r DesignHotspotFileRule) minFindings() int {
	if r.MinFindings <= 0 {
		return hotspotFileMinFindings
	}
	return r.MinFindings
}

// minPillars returns the effective minimum-pillar threshold for the hotspot rule.
func (r DesignHotspotFileRule) minPillars() int {
	if r.MinPillars <= 0 {
		return hotspotFileMinPillars
	}
	return r.MinPillars
}

// Definition declares the design.hotspot-file composite. It emits the design
// pillar to match its design.* rule ID, and is the only rule that does so, so
// list-rules keeps exposing the design pillar required by the cross-port 11-pillar
// contract; re-pillaring it would silently drop a contract pillar. Like every
// design.* composite it is score-neutral (see internal/scoring): the underlying
// findings already carry the penalty. Gated by default thresholds of 3 findings
// spanning at least 2 quality pillars.
func (r DesignHotspotFileRule) Definition() Definition {
	minFindings := r.minFindings()
	minPillars := r.minPillars()
	return Definition{
		ID:             "design.hotspot-file",
		Title:          "Hotspot file",
		Description:    "Flags files with findings across multiple quality pillars, highlighting cross-cutting maintenance hotspots.",
		Pillar:         finding.PillarDesign,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Thresholds: map[string]float64{
			"minFindings": float64(minFindings),
			"minPillars":  float64(minPillars),
		},
		Tags:        []string{"composite"},
		Remediation: "Triage the file as a unit: separate unrelated responsibilities before tuning individual rule thresholds.",
	}
}

// AnalyzeFindings emits one hotspot composite per file whose findings cross enough pillars.
func (r DesignHotspotFileRule) AnalyzeFindings(findings []finding.Finding, _ Context) []finding.Finding {
	minFindings := r.minFindings()
	minPillars := r.minPillars()
	groups := map[string]*fileCompositeGroup{}
	for _, item := range findings {
		if item.File == "" || item.Pillar == finding.PillarDesign {
			continue
		}
		group := groups[item.File]
		if group == nil {
			group = &fileCompositeGroup{file: item.File, pillars: map[finding.Pillar]int{}}
			groups[item.File] = group
		}
		group.findings = append(group.findings, item)
		group.pillars[item.Pillar]++
	}

	files := make([]string, 0, len(groups))
	for file := range groups {
		files = append(files, file)
	}
	slices.Sort(files)

	out := []finding.Finding{}
	for _, file := range files {
		group := groups[file]
		if len(group.findings) < minFindings || len(group.pillars) < minPillars {
			continue
		}
		metadata := compositeEvidenceMetadata(group.findings)
		metadata["findings"] = len(group.findings)
		metadata["pillars"] = sortedPillars(group.pillars)
		metadata["minFindings"] = minFindings
		metadata["minPillars"] = minPillars
		out = append(out, finding.Finding{
			Message:  "file has findings across multiple quality pillars",
			File:     group.file,
			Metadata: metadata,
		})
	}
	return out
}

// fileCompositeGroup buckets all findings per file for hotspot detection.
type fileCompositeGroup struct {
	file     string
	findings []finding.Finding
	pillars  map[finding.Pillar]int
}

// compositeEvidenceMetadata builds the metadata payload for composite findings.
func compositeEvidenceMetadata(evidence []finding.Finding) map[string]any {
	metadata := map[string]any{
		"ruleIds": uniqueSortedRuleIDs(evidence),
	}
	if fingerprints := uniqueSortedFingerprints(evidence); len(fingerprints) > 0 {
		metadata["underlyingFingerprints"] = fingerprints
	}
	if line := firstEvidenceLine(evidence); line > 0 {
		metadata["primaryLine"] = line
	}
	return metadata
}

// uniqueSortedRuleIDs collects the rule IDs of the evidence findings into a
// deterministic sorted set. Dedup matters because the same rule can fire
// multiple times on one file (e.g. two separate size findings), and the sort
// keeps JSON output diff-stable across runs so golden tests aren't flaky. Empty
// rule IDs are dropped to avoid an empty string sneaking into metadata.
func uniqueSortedRuleIDs(findings []finding.Finding) []string {
	seen := map[string]struct{}{}
	for _, evidence := range findings {
		if evidence.RuleID != "" {
			seen[evidence.RuleID] = struct{}{}
		}
	}
	return sortedStringSet(seen)
}

// uniqueSortedFingerprints collects the underlying-finding fingerprints into a
// deterministic sorted set so downstream consumers can correlate a composite
// back to its evidence without depending on iteration order. Same diff-
// stability rationale as uniqueSortedRuleIDs.
func uniqueSortedFingerprints(findings []finding.Finding) []string {
	seen := map[string]struct{}{}
	for _, evidence := range findings {
		if evidence.Fingerprint != "" {
			seen[evidence.Fingerprint] = struct{}{}
		}
	}
	return sortedStringSet(seen)
}

// sortedStringSet drains a dedup set (the map[string]struct{} is keyed for
// uniqueness only; the struct{} value carries no info) into a sorted slice.
// Centralised so the various "unique sorted X" helpers above stay consistent
// rather than each open-coding the same drain+sort.
func sortedStringSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

// sortedPillars returns the pillar names from the count map as a sorted
// []string for composite metadata. The per-pillar counts are intentionally
// dropped - the composite only needs the *set* of pillars crossed - and the
// string conversion produces a JSON-friendly slice of names rather than a
// nested map.
func sortedPillars(pillars map[finding.Pillar]int) []string {
	out := make([]string, 0, len(pillars))
	for pillar := range pillars {
		out = append(out, string(pillar))
	}
	slices.Sort(out)
	return out
}

// firstEvidenceLine picks the earliest non-zero evidence line so a composite
// finding - which has no source location of its own - still navigates the
// reader somewhere useful in the IDE. Line 0 is treated as "missing" rather
// than the literal first line; otherwise a file-level evidence finding (no
// line info) would mask a real line further down.
func firstEvidenceLine(findings []finding.Finding) int {
	first := 0
	for _, evidence := range findings {
		if evidence.Location == nil || evidence.Location.Line <= 0 {
			continue
		}
		if first == 0 || evidence.Location.Line < first {
			first = evidence.Location.Line
		}
	}
	return first
}
