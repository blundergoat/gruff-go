// Package rule defines the checks users see in gruff-go scan results.
// This file softens default size findings for large Go test fixtures.
// Explicit project severity choices remain exactly as users configured them.
package rule

import "github.com/blundergoat/gruff-go/internal/finding"

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
