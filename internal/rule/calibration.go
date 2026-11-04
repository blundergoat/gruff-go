// Package rule defines the checks users see in gruff-go scan results.
//
// This file sorts size and complexity findings into the two bands the family contract ratifies.
// It also picks out default size.file-length and size.function-length findings in Go test files, which become advisory in either band.
//
// Explicit project severity choices remain exactly as users configured them, except that a lower-band finding is always an advisory notice.
package rule

import "github.com/blundergoat/gruff-go/internal/finding"

// Size and complexity findings report in two bands (FAMILY-CONTRACT.md section 12, "Size and complexity findings in two bands").
//
// A unit under one and a half times its limit gets an advisory notice not to grow.
// At or above that ratio it gets the upper-band advice to split or simplify and keeps the rule's severity.
// Default size.file-length and size.function-length findings in Go test files are the exception: they become advisory in either band.
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

// limitBand names the band a measured value falls in relative to its limit, comparing as floats without rounding.
// It returns limitBandUpper, the string upper, when value is at least one and a half times limit, else limitBandLower, the string lower.
func limitBand(value, limit int) string {
	if float64(value) >= upperBandRatio*float64(limit) {
		return limitBandUpper
	}
	return limitBandLower
}

// withLimitBand records a size or complexity finding's band in its metadata and gives it that band's advice.
//
// It passes value and limit to limitBand, stores the band in item.Metadata, and sets Remediation to lowerAdvice or upperAdvice to match.
// The registry then makes a lower-band finding advisory.
//
// It returns the updated copy of item, whose Metadata map is still shared with the item the caller passed in.
// A nil item.Metadata makes the band write panic, so callers must build the finding with a metadata map.
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
// It reads the limitBand metadata entry of item, so an item whose band is missing or not a string gives false.
func isLowerBandFinding(item finding.Finding) bool {
	band, _ := item.Metadata[limitBandKey].(string)
	return band == limitBandLower
}

// shouldCalibrateTestSizeFinding identifies default test-size results to soften to advisory, in either limit band.
//
// Advisory defaults are already soft; configured severities bypass this path.
// It reports true only when definition is the size.file-length or size.function-length rule at warning or error severity,
// and item carries testFile metadata holding the bool true; any other rule, severity, or a missing or non-bool testFile gives false.
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
