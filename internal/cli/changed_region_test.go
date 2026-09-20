// Package cli implements the gruff-go command-line interface.
// This file pins analyse's native changed-region hook surface.
package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
)

// TestAnalyseNoBaselineOverridesBaseline confirms --no-baseline is accepted and
// takes precedence over a supplied --baseline path without changing the rest of
// the scan.
func TestAnalyseNoBaselineOverridesBaseline(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	var baselineOut, baselineErr bytes.Buffer
	if code := Main([]string{"baseline", "--out", "baseline.json", "complex.go"}, &baselineOut, &baselineErr); code != 0 {
		t.Fatalf("baseline exit = %d, stderr = %s, stdout = %s", code, baselineErr.String(), baselineOut.String())
	}

	report := runAnalyseReport(t, "analyse", "--format", "json", "--fail-on", "none", "--baseline", "baseline.json", "--no-baseline", "complex.go")
	if report.Baseline.Applied {
		t.Fatalf("--no-baseline should prevent baseline application; baseline = %#v", report.Baseline)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("--no-baseline findings = %#v, want unsuppressed finding", report.Findings)
	}
}

// TestAnalyseRefusesChangedRangesItCannotScope pins that a range the run cannot
// scope to ends the run rather than widening it to the whole tree. An empty
// value is malformed for the same reason a garbled one is: the caller asked for
// a scoped run and named nothing.
func TestAnalyseRefusesChangedRangesItCannotScope(t *testing.T) {
	for _, ranges := range []string{"=abc", ""} {
		root := t.TempDir()
		writeFile(t, root, "complex.go", complexFixture())
		t.Chdir(root)

		var out, errOut bytes.Buffer
		code := Main([]string{"analyse", "--format", "json", "--fail-on", "none", "--no-baseline", "--changed-ranges", ranges, "complex.go"}, &out, &errOut)
		if code != 2 {
			t.Fatalf("--changed-ranges %q exit = %d, want 2; stdout = %s", ranges, code, out.String())
		}
		var report machineAnalysisReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatalf("--changed-ranges %q published no readable envelope: %v\n%s", ranges, err, out.String())
		}
		if len(report.Diagnostics) != 1 || report.Diagnostics[0].Type != analysis.ChangedRegionDiagnosticType {
			t.Fatalf("--changed-ranges %q diagnostics = %#v, want one %s", ranges, report.Diagnostics, analysis.ChangedRegionDiagnosticType)
		}
		if len(report.Findings) != 0 {
			t.Fatalf("--changed-ranges %q published %d findings beside an unusable scope", ranges, len(report.Findings))
		}
	}
}

// TestAnalyseChangedRangesNoBaselineSuppressedMath pins the agent-hook
// invocation: --no-baseline is accepted, symbol scope keeps only the changed
// function's finding, and suppressedCount balances against the full-file count.
func TestAnalyseChangedRangesNoBaselineSuppressedMath(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "two.go", doubleComplexFixture())
	t.Chdir(root)

	full := runAnalyseReport(t, "analyse", "--format", "json", "--fail-on", "none", "two.go")
	scoped := runAnalyseReport(t, "analyse", "--format", "json", "--fail-on", "none", "--no-baseline", "--changed-ranges", "5-5", "--changed-scope", "symbol", "two.go")

	if len(full.Findings) < 2 {
		t.Fatalf("full scan findings = %#v, want at least two findings for scoping math", full.Findings)
	}
	if scoped.Summary.SuppressedFindings == nil {
		t.Fatalf("scoped report missing suppressedCount: %#v", scoped)
	}
	if len(scoped.Findings) == 0 || len(scoped.Findings) >= len(full.Findings) {
		t.Fatalf("scoped findings = %#v, full findings = %#v; want a strict subset", scoped.Findings, full.Findings)
	}
	if len(scoped.Findings)+*scoped.Summary.SuppressedFindings != len(full.Findings) {
		t.Fatalf("scoped findings %d + suppressedCount %d != full count %d", len(scoped.Findings), *scoped.Summary.SuppressedFindings, len(full.Findings))
	}
	if !strings.Contains(scoped.Diff.Caveat, "changed-region scoped") {
		t.Fatalf("diff caveat = %q, want changed-region scoped warning", scoped.Diff.Caveat)
	}
}

// doubleComplexFixture returns one file with two separately over-complex
// exported functions so changed-region tests can prove one is kept and one is
// suppressed.
func doubleComplexFixture() string {
	return `// Package sample is a test package.
package sample

// RiskyOne is intentionally over the cyclomatic threshold for fixture use.
func RiskyOne(a int) {
	switch a {
	case 1:
		_ = a
	case 2:
		_ = a
	case 3:
		_ = a
	case 4:
		_ = a
	case 5:
		_ = a
	case 6:
		_ = a
	case 7:
		_ = a
	case 8:
		_ = a
	case 9:
		_ = a
	case 10:
		_ = a
	case 11:
		_ = a
	case 12:
		_ = a
	case 13:
		_ = a
	case 14:
		_ = a
	case 15:
		_ = a
	case 16:
		_ = a
	case 17:
		_ = a
	case 18:
		_ = a
	case 19:
		_ = a
	case 20:
		_ = a
	case 21:
		_ = a
	}
}

// RiskyTwo is intentionally over the cyclomatic threshold for fixture use.
func RiskyTwo(a int) {
	switch a {
	case 1:
		_ = a
	case 2:
		_ = a
	case 3:
		_ = a
	case 4:
		_ = a
	case 5:
		_ = a
	case 6:
		_ = a
	case 7:
		_ = a
	case 8:
		_ = a
	case 9:
		_ = a
	case 10:
		_ = a
	case 11:
		_ = a
	case 12:
		_ = a
	case 13:
		_ = a
	case 14:
		_ = a
	case 15:
		_ = a
	case 16:
		_ = a
	case 17:
		_ = a
	case 18:
		_ = a
	case 19:
		_ = a
	case 20:
		_ = a
	case 21:
		_ = a
	}
}
`
}
