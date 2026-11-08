// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements the composite design rule that derives a finding from other findings.
// It reads the findings other rules produced and flags a file once its finding count and distinct pillars reach the rule's thresholds.
package rule

import (
	"slices"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// Default thresholds for the design.hotspot-file composite rule.
//
// A file needs at least hotspotFileMinFindings findings spanning at least hotspotFileMinPillars quality pillars before the composite fires.
// They apply whenever DesignHotspotFileRule leaves MinFindings or MinPillars at zero or below.
const (
	hotspotFileMinFindings = 3
	hotspotFileMinPillars  = 2
)

// DesignHotspotFileRule flags files whose findings reach its count and distinct-pillar thresholds; by default that means two or more pillars.
//
// Its finding is score-neutral triage: the user is pointed at the underlying findings to fix as a cluster, not at a separate code edit.
type DesignHotspotFileRule struct {
	// MinFindings is the minimum count of underlying findings a file needs before the composite fires; zero or less uses hotspotFileMinFindings.
	MinFindings int
	// MinPillars is the minimum number of distinct quality pillars those findings must span; zero or less uses hotspotFileMinPillars.
	MinPillars int
}

// minFindings returns the effective minimum-finding threshold for the hotspot rule.
// It gives MinFindings, or hotspotFileMinFindings when MinFindings is zero or less, so a zero-value rule uses the default.
func (r DesignHotspotFileRule) minFindings() int {
	if r.MinFindings <= 0 {
		return hotspotFileMinFindings
	}
	return r.MinFindings
}

// minPillars returns the effective minimum-pillar threshold for the hotspot rule.
// It gives MinPillars, or hotspotFileMinPillars when MinPillars is zero or less, so a zero-value rule uses the default.
func (r DesignHotspotFileRule) minPillars() int {
	if r.MinPillars <= 0 {
		return hotspotFileMinPillars
	}
	return r.MinPillars
}

// Definition declares the design.hotspot-file composite.
//
// It alone emits the design pillar to match its design.* rule ID, keeping that pillar in list-rules for the cross-port 11-pillar contract.
// Re-pillaring it would drop a contract pillar; like every design.* composite it is score-neutral, as its evidence carries the penalty.
//
// It returns the rule's Definition; its thresholds are MinFindings and MinPillars, with a field that is zero or less replaced by its default.
// Those defaults are 3 findings spanning at least 2 quality pillars.
func (r DesignHotspotFileRule) Definition() Definition {
	minFindings := r.minFindings()
	minPillars := r.minPillars()
	return Definition{
		ID:             "design.hotspot-file",
		Title:          "Hotspot file",
		Description:    "Emits score-neutral composite triage when a file has findings across multiple quality pillars.",
		Pillar:         finding.PillarDesign,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Thresholds: map[string]float64{
			"minFindings": float64(minFindings),
			"minPillars":  float64(minPillars),
		},
		Tags:        []string{"composite"},
		Remediation: "Triage the file as a cluster, then fix the underlying findings; the composite is not a separate code edit.",
	}
}

// AnalyzeFindings emits one hotspot composite per file whose findings cross enough pillars.
//
// Findings with no file or in the design pillar are skipped; a file qualifies when its count and distinct pillars both reach the thresholds.
// It returns one composite per qualifying file, in path order, with evidence and threshold metadata, or an empty non-nil slice if none qualifies.
func (r DesignHotspotFileRule) AnalyzeFindings(findings []finding.Finding, _ Context) []finding.Finding {
	minFindings := r.minFindings()
	minPillars := r.minPillars()
	groups := map[string]*fileCompositeGroup{}
	for _, item := range findings {
		// Only hotspot composites carry the design pillar, so skipping it keeps one hotspot from counting another as evidence.
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

	hotspots := []finding.Finding{}
	for _, file := range files {
		group := groups[file]
		// With the default pillar threshold of 2, five findings all in one pillar get no hotspot; a file must reach both thresholds.
		if len(group.findings) < minFindings || len(group.pillars) < minPillars {
			continue
		}
		metadata := compositeEvidenceMetadata(group.findings)
		metadata["findings"] = len(group.findings)
		metadata["pillars"] = sortedPillars(group.pillars)
		metadata["minFindings"] = minFindings
		metadata["minPillars"] = minPillars
		hotspots = append(hotspots, finding.Finding{
			Message:  "score-neutral hotspot: triage underlying findings across multiple quality pillars",
			File:     group.file,
			Metadata: metadata,
		})
	}
	return hotspots
}

// fileCompositeGroup buckets one file's findings for hotspot detection.
// It holds the file path, that file's non-design findings and a finding count per pillar, of which only the pillar names reach metadata.
type fileCompositeGroup struct {
	file     string
	findings []finding.Finding
	pillars  map[finding.Pillar]int
}

// compositeEvidenceMetadata builds the metadata payload for composite findings.
//
// evidence is the list of underlying findings the composite summarises.
// It returns a new map that always holds ruleIds, possibly empty, adding underlyingFingerprints and primaryLine only when evidence supplies them.
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

// uniqueSortedRuleIDs collects the rule IDs of the evidence findings into a deterministic sorted set.
//
// Dedup matters because the same rule can fire more than once on one file, such as two separate size findings.
// The sort keeps JSON output diff-stable across runs, so golden tests are not flaky.
//
// Empty rule IDs are dropped so an empty string never sneaks into metadata.
// It returns the distinct non-empty rule IDs in ascending order, and an empty slice, never nil, when no finding has one.
func uniqueSortedRuleIDs(findings []finding.Finding) []string {
	seen := map[string]struct{}{}
	for _, evidence := range findings {
		if evidence.RuleID != "" {
			seen[evidence.RuleID] = struct{}{}
		}
	}
	return sortedStringSet(seen)
}

// uniqueSortedFingerprints collects the underlying-finding fingerprints into a deterministic sorted set.
//
// A consumer can correlate a composite back to its evidence without depending on iteration order.
// The sort keeps output diff-stable for the same reason as in uniqueSortedRuleIDs.
//
// findings is the composite's evidence, and entries with an empty Fingerprint are dropped.
// It returns the distinct fingerprints in ascending order, and an empty slice, never nil, when no finding has one.
func uniqueSortedFingerprints(findings []finding.Finding) []string {
	seen := map[string]struct{}{}
	for _, evidence := range findings {
		if evidence.Fingerprint != "" {
			seen[evidence.Fingerprint] = struct{}{}
		}
	}
	return sortedStringSet(seen)
}

// sortedStringSet copies the keys of a dedup set into a sorted slice; the set's struct{} values carry no information.
//
// It is shared by uniqueSortedRuleIDs and uniqueSortedFingerprints so both stay consistent rather than each open-coding the same copy and sort.
// values is the dedup set to read; its keys are copied out and the map itself is left unchanged.
// It returns the keys in ascending order, and an empty slice, never nil, when values is empty or nil.
func sortedStringSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

// sortedPillars returns the pillar names from the count map as a sorted string slice for composite metadata.
//
// The per-pillar counts are dropped on purpose, since the composite only needs the set of pillars crossed.
// Converting to strings gives a JSON-friendly list of names rather than a nested map.
// pillars maps each pillar to its finding count, and an empty or nil map gives an empty slice, never nil.
func sortedPillars(pillars map[finding.Pillar]int) []string {
	out := make([]string, 0, len(pillars))
	for pillar := range pillars {
		out = append(out, string(pillar))
	}
	slices.Sort(out)
	return out
}

// firstEvidenceLine picks the earliest positive evidence line for a composite finding, which has no source location of its own.
//
// Stored as primaryLine metadata, it points to evidence without setting the composite's Location.
// Line 0 means missing, not the first line; otherwise a file-level evidence finding with no line info would mask a real line further down.
//
// findings is the composite's evidence, and entries with no Location or a line below 1 are skipped.
// It returns the smallest remaining Location line, or 0 when no finding has a positive line.
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
