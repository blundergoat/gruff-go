package rule

import "github.com/blundergoat/gruff-go/internal/finding"

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
