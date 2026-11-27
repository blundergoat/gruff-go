package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// contractNumberPattern matches integers and decimals in a finding message for the fallback identity subject.
//
// Each match becomes #, so a symbol-less, non-metric finding keeps the same identity when a number in its message changes.
var contractNumberPattern = regexp.MustCompile(`\d+(?:\.\d+)?`)

// ComputeContractStableIdentity returns a 16-hex-character identity that survives line shifts and measured-count changes.
//
// It hashes rule ID, file and subject, and never location or metric values.
// The subject is the symbol; with no symbol and no metric metadata it is the message with every number replaced by #.
// With no symbol but metric metadata the subject is empty, giving one identity per rule and file.
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

// HasContractStableAnchor reports whether line-insensitive matching has a semantic subject stronger than a repeated message.
//
// Named symbols identify a declaration; metric metadata identifies the one measured subject per rule and file.
// A false result means neither a symbol nor metric metadata; ComputeContractStableIdentity then hashes the masked message instead.
func (f Finding) HasContractStableAnchor() bool {
	return f.Symbol != "" || hasContractMetricMetadata(f.Metadata)
}

// hasContractMetricMetadata reports whether metadata carries a threshold metric.
//
// That needs a threshold key plus one of lines, complexity, depth, parameters or measured.
// A nil or empty metadata map gives false, so a symbol-less finding falls back to its message for identity.
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
