package rule

import (
	"fmt"
	"slices"

	"github.com/blundergoat/gruff-go/internal/finding"
)

const (
	hotspotFileMinFindings = 3
	hotspotFileMinPillars  = 2
)

type DesignGodFunctionRule struct{}

func (DesignGodFunctionRule) Definition() Definition {
	return Definition{
		ID:               "design.god-function",
		Title:            "God function",
		Description:      "Flags functions that already have both size and complexity findings, prioritising routines that need structural decomposition.",
		Pillar:           finding.PillarDesign,
		SecondaryPillars: []finding.Pillar{finding.PillarSize, finding.PillarComplexity},
		Severity:         finding.SeverityLow,
		Confidence:       finding.ConfidenceHigh,
		DefaultEnabled:   true,
		Tags:             []string{"composite", "opt-in"},
		Remediation:      "Split the function around cohesive responsibilities, then re-run the size and complexity rules to confirm both signals cleared.",
	}
}

func (DesignGodFunctionRule) AnalyzeFindings(findings []finding.Finding, _ Context) []finding.Finding {
	groups := map[string]*symbolCompositeGroup{}
	for _, evidence := range findings {
		if evidence.File == "" || evidence.Symbol == "" {
			continue
		}
		if evidence.Pillar != finding.PillarSize && evidence.Pillar != finding.PillarComplexity {
			continue
		}
		key := evidence.File + "\x00" + evidence.Symbol
		group := groups[key]
		if group == nil {
			group = &symbolCompositeGroup{file: evidence.File, symbol: evidence.Symbol}
			groups[key] = group
		}
		switch evidence.Pillar {
		case finding.PillarSize:
			group.size = append(group.size, evidence)
		case finding.PillarComplexity:
			group.complexity = append(group.complexity, evidence)
		}
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	out := []finding.Finding{}
	for _, key := range keys {
		group := groups[key]
		if len(group.size) == 0 || len(group.complexity) == 0 {
			continue
		}
		evidence := append(append([]finding.Finding{}, group.size...), group.complexity...)
		metadata := compositeEvidenceMetadata(evidence)
		metadata["sizeFindings"] = len(group.size)
		metadata["complexityFindings"] = len(group.complexity)
		out = append(out, finding.Finding{
			Message:  fmt.Sprintf("function %s combines size and complexity findings", group.symbol),
			File:     group.file,
			Symbol:   group.symbol,
			Metadata: metadata,
		})
	}
	return out
}

type DesignHotspotFileRule struct {
	MinFindings int
	MinPillars  int
}

func (r DesignHotspotFileRule) minFindings() int {
	if r.MinFindings <= 0 {
		return hotspotFileMinFindings
	}
	return r.MinFindings
}

func (r DesignHotspotFileRule) minPillars() int {
	if r.MinPillars <= 0 {
		return hotspotFileMinPillars
	}
	return r.MinPillars
}

func (r DesignHotspotFileRule) Definition() Definition {
	minFindings := r.minFindings()
	minPillars := r.minPillars()
	return Definition{
		ID:             "design.hotspot-file",
		Title:          "Hotspot file",
		Description:    "Flags files with findings across multiple quality pillars, highlighting cross-cutting maintenance hotspots.",
		Pillar:         finding.PillarDesign,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Thresholds: map[string]float64{
			"minFindings": float64(minFindings),
			"minPillars":  float64(minPillars),
		},
		Tags:        []string{"composite", "opt-in"},
		Remediation: "Triage the file as a unit: separate unrelated responsibilities before tuning individual rule thresholds.",
	}
}

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

type symbolCompositeGroup struct {
	file       string
	symbol     string
	size       []finding.Finding
	complexity []finding.Finding
}

type fileCompositeGroup struct {
	file     string
	findings []finding.Finding
	pillars  map[finding.Pillar]int
}

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

func uniqueSortedRuleIDs(findings []finding.Finding) []string {
	seen := map[string]struct{}{}
	for _, evidence := range findings {
		if evidence.RuleID != "" {
			seen[evidence.RuleID] = struct{}{}
		}
	}
	return sortedStringSet(seen)
}

func uniqueSortedFingerprints(findings []finding.Finding) []string {
	seen := map[string]struct{}{}
	for _, evidence := range findings {
		if evidence.Fingerprint != "" {
			seen[evidence.Fingerprint] = struct{}{}
		}
	}
	return sortedStringSet(seen)
}

func sortedStringSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func sortedPillars(pillars map[finding.Pillar]int) []string {
	out := make([]string, 0, len(pillars))
	for pillar := range pillars {
		out = append(out, string(pillar))
	}
	slices.Sort(out)
	return out
}

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
