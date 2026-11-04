// Composite-finding pruning keeps a composite finding only while its underlying evidence survives the changed-region filter.
//
// A composite such as design.hotspot-file records its underlying-evidence fingerprints and stays while at least one of them survives.
// So a --diff scan never shows the user a composite for code the diff never touched.
package analysis

import "github.com/blundergoat/gruff-go/internal/finding"

// pruneOrphanedComposites drops composite findings whose recorded underlying fingerprints are not among the surviving non-composite findings.
//
// A composite is identified by an underlyingFingerprints metadata slice; that is the contract composite rules use when emitting evidence.
//
// It returns the kept findings in input order and the number of composites dropped, which is zero when no composite is orphaned.
// An empty underlyingFingerprints slice still marks a composite, and such a composite is always dropped.
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

// collectNonCompositeFingerprints returns the set of fingerprints belonging to non-composite findings.
//
// Composites, identified by an underlyingFingerprints metadata slice, are excluded, and so is any finding with an empty Fingerprint.
// The set is empty, never nil, when findings holds no fingerprinted non-composite finding, and every composite is then dropped.
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

// compositeEvidenceSurvives reports whether candidate should be kept after composite pruning; false means pruneOrphanedComposites drops it.
//
// Non-composite findings always survive; a composite survives only when at least one of its underlying fingerprints is in the surviving set.
// The survivingFingerprints map is that surviving set, keyed by fingerprint as collectNonCompositeFingerprints builds it.
// A composite whose underlying fingerprint list is empty never survives.
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

// compositeUnderlyingFingerprints extracts the recorded underlying fingerprint set from a composite finding's metadata.
//
// It returns the fingerprints and true when item carries an underlyingFingerprints slice of strings or of any values.
// The slice may be empty for a composite whose evidence had no fingerprints; it still counts as a composite, so pruning drops it.
//
// It returns (nil, false) when item has nil Metadata, lacks the key, or holds a value that is neither a string slice nor an any slice.
// Non-string elements of an any slice are skipped, so the returned slice can be shorter than the stored one.
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
