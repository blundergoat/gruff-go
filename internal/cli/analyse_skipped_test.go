package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestAnalyseExplicitAllSkippedInputReportsDiagnostic verifies direct scans of
// skipped metadata paths exit as diagnostics instead of clean zero-file reports.
func TestAnalyseExplicitAllSkippedInputReportsDiagnostic(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".goat-flow/generated.go", "package metadata\n")
	t.Chdir(root)

	var out, errOut bytes.Buffer
	code := Main([]string{"analyse", "--format", "text", ".goat-flow/generated.go"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("exit = %d, want 2\nstderr:\n%s\nstdout:\n%s", code, errOut.String(), out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", errOut.String())
	}
	output := out.String()
	for _, want := range []string{
		"explicit input skipped before parsing",
		"source=default",
		"--include-ignored",
		"exit: 2",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
