// Package cli tests baseline behavior at the command-line gate users run.
// It pins unchanged, mixed, severity-floor, and changed-region journeys so
// one-to-one matching cannot silently alter established exit semantics.
package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestAnalyseBaselineUnchangedOnlyExitsZero verifies reviewed debt remains
// hidden and lets the user's CI command succeed.
func TestAnalyseBaselineUnchangedOnlyExitsZero(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "complex.go", complexFixture())
	t.Chdir(projectRoot)
	generateUserBaseline(t, "baseline.json", "complex.go")

	report, exitCode := runBaselineGateAnalyse(t, "analyse", "--format", "json", "--baseline", "baseline.json", "complex.go")
	// A fully reviewed scan should leave no visible finding or failure exit.
	if exitCode != 0 || len(report.Findings) != 0 {
		t.Fatalf("exit = %d, findings = %#v; want exit 0 and none", exitCode, report.Findings)
	}
	// The UI should report the reviewed finding as exactly one unchanged item.
	if report.Baseline.NewFindings != 0 || report.Baseline.UnchangedFindings != 1 || report.Baseline.ResolvedFindings != 0 {
		t.Fatalf("baseline counts = %#v, want 0/1/0", report.Baseline)
	}
}

// TestAnalyseBaselineMixedFindingsExitOne verifies a newly introduced issue
// still fails CI while the reviewed sibling remains unchanged.
func TestAnalyseBaselineMixedFindingsExitOne(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "reviewed.go", complexFixture())
	t.Chdir(projectRoot)
	generateUserBaseline(t, "baseline.json", "reviewed.go")
	writeFile(t, projectRoot, "new.go", complexFixture())

	report, exitCode := runBaselineGateAnalyse(t, "analyse", "--format", "json", "--baseline", "baseline.json", ".")
	// A new warning should retain the existing finding-gate exit code.
	if exitCode != 1 || report.Summary.ExitCode != 1 {
		t.Fatalf("CLI/report exits = %d/%d, want 1/1", exitCode, report.Summary.ExitCode)
	}
	// One old and one new issue should be visible in the baseline status counts.
	if report.Baseline.NewFindings != 1 || report.Baseline.UnchangedFindings != 1 || len(report.Findings) != 1 {
		t.Fatalf("baseline/report = %#v/%#v, want one new and one unchanged", report.Baseline, report.Findings)
	}
}

// TestAnalyseBaselineSeverityFloorStillApplies verifies baseline matching does
// not invent a second new-findings gate above the user's severity choice.
func TestAnalyseBaselineSeverityFloorStillApplies(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "reviewed.go", complexFixture())
	t.Chdir(projectRoot)
	generateUserBaseline(t, "baseline.json", "reviewed.go")
	writeFile(t, projectRoot, "new.go", complexFixture())

	report, exitCode := runBaselineGateAnalyse(t, "analyse", "--format", "json", "--fail-on", "error", "--baseline", "baseline.json", ".")
	// A new warning remains visible but cannot cross the configured error floor.
	if exitCode != 0 || report.Summary.ExitCode != 0 || len(report.Findings) != 1 {
		t.Fatalf("exit/report/findings = %d/%d/%d, want 0/0/1", exitCode, report.Summary.ExitCode, len(report.Findings))
	}
	// Baseline counts should still distinguish the reviewed and new findings.
	if report.Baseline.NewFindings != 1 || report.Baseline.UnchangedFindings != 1 {
		t.Fatalf("baseline counts = %#v, want one new and one unchanged", report.Baseline)
	}
}

// TestAnalyseDiffAndBaselineSuppressShiftedFinding verifies baseline matching
// happens on the complete scan before the user's changed-region filter.
func TestAnalyseDiffAndBaselineSuppressShiftedFinding(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "complex.go", complexFixture())
	t.Chdir(projectRoot)
	generateUserBaseline(t, "baseline.json", "complex.go")
	shiftedSource := strings.Replace(complexFixture(), "package sample\n", "package sample\n\n// A user added context before the existing function.\n", 1)
	writeFile(t, projectRoot, "complex.go", shiftedSource)

	report, exitCode := runBaselineGateAnalyse(t, "analyse", "--format", "json", "--baseline", "baseline.json", "--changed-ranges", "2-3", "complex.go")
	// A harmless line shift should remain reviewed and keep the diff scan green.
	if exitCode != 0 || len(report.Findings) != 0 {
		t.Fatalf("exit = %d, findings = %#v; want shifted finding suppressed", exitCode, report.Findings)
	}
	// The report should show one unchanged baseline match and an active diff scope.
	if report.Baseline.UnchangedFindings != 1 || report.Baseline.NewFindings != 0 || !report.Diff.Enabled {
		t.Fatalf("baseline/diff = %#v/%#v, want one unchanged in diff mode", report.Baseline, report.Diff)
	}
}

// generateUserBaseline runs the same baseline command documented for users.
// Empty paths are not used here because each journey names its reviewed file.
func generateUserBaseline(t *testing.T, baselinePath string, sourcePaths ...string) {
	t.Helper()
	commandArguments := []string{"baseline", "--no-config", "--out", baselinePath}
	commandArguments = append(commandArguments, sourcePaths...)
	var standardOutput, standardError bytes.Buffer
	// A setup failure would make the following gate result meaningless.
	if exitCode := Main(commandArguments, &standardOutput, &standardError); exitCode != 0 {
		t.Fatalf("baseline exit = %d, stderr = %s, stdout = %s", exitCode, standardError.String(), standardOutput.String())
	}
}

// runBaselineGateAnalyse executes analyse and decodes its JSON even when a
// user-facing finding correctly produces exit 1.
func runBaselineGateAnalyse(t *testing.T, commandArguments ...string) (machineAnalysisReport, int) {
	t.Helper()
	var standardOutput, standardError bytes.Buffer
	exitCode := Main(commandArguments, &standardOutput, &standardError)
	var report machineAnalysisReport
	// Valid gate journeys must always return parseable report JSON.
	if err := json.Unmarshal(standardOutput.Bytes(), &report); err != nil {
		t.Fatalf("analyse %v JSON: %v\nstdout=%s\nstderr=%s", commandArguments, err, standardOutput.String(), standardError.String())
	}
	return report, exitCode
}
