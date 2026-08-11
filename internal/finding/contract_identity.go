package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// contractNumberPattern strips measured values from fallback identity subjects.
var contractNumberPattern = regexp.MustCompile(`\d+(?:\.\d+)?`)

// ComputeContractStableIdentity returns the hook-contract identity for new-only
// comparisons. It deliberately ignores location and metric values, so a finding
// survives line shifts and measured-count changes while still naming the same
// rule subject.
func (f Finding) ComputeContractStableIdentity() string {
	subject := f.Symbol
	if subject == "" && !hasContractMetricMetadata(f.Metadata) {
		subject = contractNumberPattern.ReplaceAllString(f.Message, "#")
	}
	hasher := sha256.New()
	hasher.Write([]byte(f.RuleID))
	hasher.Write([]byte{0})
	hasher.Write([]byte(f.File))
	hasher.Write([]byte{0})
	hasher.Write([]byte(subject))
	return hex.EncodeToString(hasher.Sum(nil))[:16]
}

// HasContractStableAnchor reports whether line-insensitive matching has a
// semantic subject stronger than a repeated message. Named symbols identify a
// declaration; metric metadata identifies the one measured subject per rule and
// file. A symbol-less, non-metric occurrence remains location-specific.
func (f Finding) HasContractStableAnchor() bool {
	return f.Symbol != "" || hasContractMetricMetadata(f.Metadata)
}

// hasContractMetricMetadata reports whether metadata carries a threshold metric.
func hasContractMetricMetadata(metadata map[string]any) bool {
	if len(metadata) == 0 {
		return false
	}
	if _, ok := metadata["threshold"]; !ok {
		return false
	}
	for _, key := range []string{"lines", "complexity", "depth", "parameters", "measured"} {
		if _, ok := metadata[key]; ok {
			return true
		}
	}
	return false
}
