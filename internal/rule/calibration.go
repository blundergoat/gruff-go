// Package rule defines the checks users see in gruff-go scan results.
// This file softens default size findings for large Go test fixtures and sorts
// size and complexity findings into the two bands the family contract ratifies.
// Explicit project severity choices remain exactly as users configured them,
// except that a lower-band finding is always an advisory notice.
package rule

import "github.com/blundergoat/gruff-go/internal/finding"

// Size and complexity findings report in two bands (FAMILY-CONTRACT.md section 12,
// "Size and complexity findings in two bands"). A unit under one and a half times
// its limit gets an advisory notice not to grow; at that ratio or above it keeps
// the rule's severity and the advice to split or simplify.
const (
	limitBandKey   = "limitBand"
	limitBandLower = "lower"
	limitBandUpper = "upper"
	upperBandRatio = 1.5
)

// Advice shared by several banded rules. Size rules carry their own upper-band
// advice in their definitions; every complexity rule asks for a simpler path.
const (
	lowerBandFunctionAdvice     = "Do not add to this function; put new code in a new function."
	lowerBandFileAdvice         = "Do not add to this file; put new code in a new file."
	lowerBandParameterAdvice    = "Do not add another parameter to this function."
	simplifyExecutionPathAdvice = "Simplify the execution path: return early, merge branches that lead to the same result, and drop flags that steer later branches. Moving branches into helpers leaves the path as hard to follow."
)

// limitBand names the band a measured value falls in: upper at or above one and a
// half times the limit, compared without rounding, and lower below it.
func limitBand(value, limit int) string {
	if float64(value) >= upperBandRatio*float64(limit) {
		return limitBandUpper
	}
	return limitBandLower
}

// withLimitBand records a size or complexity finding's band in its metadata and
// gives it that band's advice; the registry then makes a lower-band finding advisory.
func withLimitBand(item finding.Finding, value, limit int, lowerAdvice, upperAdvice string) finding.Finding {
	band := limitBand(value, limit)
	item.Metadata[limitBandKey] = band
	item.Remediation = upperAdvice
	if band == limitBandLower {
		item.Remediation = lowerAdvice
	}
	return item
}

// isLowerBandFinding reports whether a finding sits under one and a half times its limit.
func isLowerBandFinding(item finding.Finding) bool {
	band, _ := item.Metadata[limitBandKey].(string)
	return band == limitBandLower
}

// shouldCalibrateTestSizeFinding identifies default test-size results to soften.
// Advisory defaults are already soft; configured severities bypass this path.
func shouldCalibrateTestSizeFinding(item finding.Finding, definition Definition) bool {
	// Only louder defaults need protection from test-fixture size noise.
	if definition.Severity != finding.SeverityWarning && definition.Severity != finding.SeverityError {
		return false
	}
	// Other rule families keep the severity shown in the scan result.
	if definition.ID != "size.file-length" && definition.ID != "size.function-length" {
		return false
	}
	testFile, hasTestFileEvidence := item.Metadata["testFile"].(bool)
	return hasTestFileEvidence && testFile
}
