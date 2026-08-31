// Package cli baseline-show tests cover the M24 three-state classification
// surface (new / unchanged / resolved) end to end through the analyse command.
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// seedResolvableBaseline baselines complex.go, then injects a bogus entry that
// no current finding can match (so it classifies as resolved) and adds an
// un-baselined extra.go (so its findings classify as new). It returns the number
// of genuinely baselined findings, which is the expected unchanged count.
func seedResolvableBaseline(t *testing.T, root string) int {
	t.Helper()
	var baseOut, baseErr bytes.Buffer
	if code := Main([]string{"baseline", "--out", "base.json", "complex.go"}, &baseOut, &baseErr); code != 0 {
		t.Fatalf("baseline exit = %d, stderr = %s", code, baseErr.String())
	}
	raw, err := os.ReadFile(filepath.Join(root, "base.json"))
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		RuleID      string `json:"ruleId"`
		File        string `json:"file"`
		Fingerprint string `json:"fingerprint"`
	}
	var file struct {
		SchemaVersion string  `json:"schemaVersion"`
		Findings      []entry `json:"findings"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	baselined := len(file.Findings)
	if baselined == 0 {
		t.Fatal("baseline captured no findings; fixture cannot prove unchanged state")
	}
	file.Findings = append(file.Findings, entry{RuleID: "size.file-length", File: "deleted.go", Fingerprint: "deadbeefdeadbeef"})
	patched, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "base.json"), patched, 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "extra.go", complexFixture())
	return baselined
}

// runAnalyseReport runs analyse with the given args and decodes the JSON report.
func runAnalyseReport(t *testing.T, args ...string) machineAnalysisReport {
	t.Helper()
	var out, errOut bytes.Buffer
	if code := Main(args, &out, &errOut); code != 0 {
		t.Fatalf("analyse %v exit = %d, stderr = %s", args, code, errOut.String())
	}
	var report machineAnalysisReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal %v: %v\n%s", args, err, out.String())
	}
	return report
}

// TestAnalyseBaselineThreeStateShowCounts checks that --baseline-show surfaces
// the new / unchanged / resolved counts and detail arrays, with the resolved
// entry naming the fixed file and the legacy counts staying in lockstep.
func TestAnalyseBaselineThreeStateShowCounts(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)
	baselined := seedResolvableBaseline(t, root)

	b := runAnalyseReport(t, "analyse", "--baseline", "base.json", "--baseline-show", "--format", "json", "--fail-on", "none", ".").Baseline
	if b.NewFindings < 1 || b.UnchangedFindings != baselined || b.ResolvedFindings != 1 {
		t.Fatalf("counts new/unchanged/resolved = %d/%d/%d, want >=1/%d/1", b.NewFindings, b.UnchangedFindings, b.ResolvedFindings, baselined)
	}
	if len(b.Unchanged) != b.UnchangedFindings || len(b.Resolved) != 1 {
		t.Fatalf("detail arrays under --baseline-show: unchanged=%d resolved=%d, want %d and 1", len(b.Unchanged), len(b.Resolved), b.UnchangedFindings)
	}
	if b.Resolved[0].File != "deleted.go" {
		t.Fatalf("resolved entry = %#v, want deleted.go", b.Resolved[0])
	}
	if b.SuppressedFindings != b.UnchangedFindings || b.StaleEntries != b.ResolvedFindings {
		t.Fatalf("legacy counts drifted: suppressed=%d stale=%d vs unchanged=%d resolved=%d", b.SuppressedFindings, b.StaleEntries, b.UnchangedFindings, b.ResolvedFindings)
	}
}

// TestAnalyseBaselineNoShowOmitsArrays checks that without --baseline-show the
// counts are still emitted but the unchanged/resolved detail arrays are omitted,
// so default JSON output stays compact.
func TestAnalyseBaselineNoShowOmitsArrays(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)
	baselined := seedResolvableBaseline(t, root)

	b := runAnalyseReport(t, "analyse", "--baseline", "base.json", "--format", "json", "--fail-on", "none", ".").Baseline
	if b.UnchangedFindings != baselined || b.ResolvedFindings != 1 {
		t.Fatalf("counts must be present without --baseline-show: %#v", b)
	}
	if len(b.Unchanged) != 0 || len(b.Resolved) != 0 {
		t.Fatalf("detail arrays must be omitted without --baseline-show: unchanged=%d resolved=%d", len(b.Unchanged), len(b.Resolved))
	}
}
