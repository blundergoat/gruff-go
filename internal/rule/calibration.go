// Package rule defines gruff-go's rule registry and analysers.
// This file calibrates size-related findings on Go test files.
package rule

import "github.com/blundergoat/gruff-go/internal/finding"

// shouldCalibrateTestSizeFinding reports whether a size finding on a test file should be down-weighted.
func shouldCalibrateTestSizeFinding(item finding.Finding, definition Definition) bool {
	if definition.Severity != finding.SeverityMedium {
		return false
	}
	if definition.ID != "size.file-length" && definition.ID != "size.function-length" {
		return false
	}
	testFile, ok := item.Metadata["testFile"].(bool)
	return ok && testFile
}
