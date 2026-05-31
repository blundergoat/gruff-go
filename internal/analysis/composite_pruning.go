// Composite-finding pruning. A composite finding (e.g. design.hotspot-file) is
// kept only while at least one of its recorded underlying-evidence fingerprints
// still survives the changed-region filter, so --diff scans never surface a
// composite for code the diff never touched.
package analysis

import "github.com/blundergoat/gruff-go/internal/finding"

// pruneOrphanedComposites drops composite findings whose recorded underlying
// fingerprints are not present among the surviving non-composite findings.
// A composite is identified by a non-empty underlyingFingerprints metadata
// slice; that is the contract composite rules use when emitting evidence.
func pruneOrphanedComposites(findings []finding.Finding) ([]finding.Finding, int) {
	survivingFingerprints := collectNonCompositeFingerprints(findings)
	kept := make([]finding.Finding, 0, len(findings))
	pruned := 0
	for _, candidate := range findings {
		if compositeEvidenceSurvives(candidate, survivingFingerprints) {
			kept = append(kept, candidate)
			continue
		}
		pruned++
	}
	return kept, pruned
}

// collectNonCompositeFingerprints returns the set of fingerprints belonging to
// non-composite findings. Composites are identified by an underlyingFingerprints
// metadata slice and are excluded from the surviving-evidence set.
func collectNonCompositeFingerprints(findings []finding.Finding) map[string]struct{} {
	out := map[string]struct{}{}
	for _, candidate := range findings {
		if _, isComposite := compositeUnderlyingFingerprints(candidate); isComposite {
			continue
		}
		if candidate.Fingerprint != "" {
			out[candidate.Fingerprint] = struct{}{}
		}
	}
	return out
}

// compositeEvidenceSurvives reports whether the candidate should be kept after
// composite pruning. Non-composite findings always survive; composites survive
// only when at least one of their recorded underlying fingerprints is in the
// surviving set.
func compositeEvidenceSurvives(candidate finding.Finding, survivingFingerprints map[string]struct{}) bool {
	underlying, isComposite := compositeUnderlyingFingerprints(candidate)
	if !isComposite {
		return true
	}
	for _, fp := range underlying {
		if _, ok := survivingFingerprints[fp]; ok {
			return true
		}
	}
	return false
}

// compositeUnderlyingFingerprints extracts the recorded underlying fingerprint
// set from a composite finding's metadata. Returns (fingerprints, true) when
// the finding carries an underlyingFingerprints slice. The slice may be empty
// for composites whose evidence had no fingerprints, in which case the
// composite still counts as composite but is treated as orphan-eligible.
func compositeUnderlyingFingerprints(item finding.Finding) ([]string, bool) {
	if item.Metadata == nil {
		return nil, false
	}
	raw, ok := item.Metadata["underlyingFingerprints"]
	if !ok {
		return nil, false
	}
	switch values := raw.(type) {
	case []string:
		return values, true
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if str, ok := value.(string); ok {
				out = append(out, str)
			}
		}
		return out, true
	}
	return nil, false
}
