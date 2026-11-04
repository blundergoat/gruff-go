// Package cli baseline-show tests cover the three-state classification of analyse --baseline end to end.
//
// Each run sees new, unchanged and resolved findings, with and without --baseline-show, in the JSON report's baseline block.
// A failure means a count, a detail array or a legacy count no longer matches the seeded baseline.
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/baseline"
)

// seedResolvableBaseline builds a baseline whose next analyse run shows all three states: new, unchanged and resolved.
//
// It baselines complex.go, then adds an entry for deleted.go that no current finding can match, so it classifies as resolved.
// It also writes an un-baselined extra.go, so that file's findings classify as new.
//
// root must be the test's current directory and already hold complex.go; base.json is rewritten and extra.go is created under root.
// It returns the number of genuinely baselined findings, which is the expected unchanged count.
// It fails the test instead of returning zero when the baseline captured no findings.
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
	file, err := baseline.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	baselined := 0
	for _, occurrence := range file.Occurrences {
		baselined += occurrence.Count
	}
	if baselined == 0 {
		t.Fatal("baseline captured no findings; fixture cannot prove unchanged state")
	}
	// A reviewed identity for a file that no longer exists is what resolves.
	// It is inserted in identity order so the file stays valid.
	file.Occurrences = append(file.Occurrences, baseline.Occurrence{Identity: "deadbeefdeadbeef", Count: 1, RuleID: "size.file-length", Path: "deleted.go"})
	slices.SortFunc(file.Occurrences, func(left, right baseline.Occurrence) int { return strings.Compare(left.Identity, right.Identity) })
	patched, err := baseline.Marshal(file)
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
// It returns the decoded report only after a zero exit; a non-zero exit or output that does not decode as JSON fails the test.
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

// TestAnalyseBaselineThreeStateShowCounts checks that --baseline-show reports the new, unchanged and resolved counts and detail arrays.
//
// The resolved entry must name deleted.go, and the legacy suppressed and stale counts must equal the unchanged and resolved counts.
func TestAnalyseBaselineThreeStateShowCounts(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)
	baselined := seedResolvableBaseline(t, root)

	b := runAnalyseReport(t, "analyse", "--baseline", "base.json", "--baseline-show", "--format", "json", "--fail-on", "none", ".").Baseline
	// extra.go supplies at least one new finding, and the seeded deleted.go entry is the only resolved one.
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

// TestAnalyseBaselineNoShowOmitsArrays checks that without --baseline-show the counts remain populated and both decoded detail slices are empty.
//
// The length checks cannot tell omitted keys, null and empty arrays apart, so they do not prove the default JSON output leaves the arrays out.
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
