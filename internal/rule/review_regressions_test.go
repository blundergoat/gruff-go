// Package rule tests cover high-impact regression scenarios verified during the 0.6.0 review.
//
// Each test pins a concrete crash, non-determinism, false-positive, or false-negative defect so later refactors cannot reintroduce it.
// Every fixture mirrors realistic Go source a developer or coding agent writes during normal work.
package rule

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	parserpkg "github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// parseReviewFixture parses inline Go source into a parser.Unit ready for direct rule execution in regression tests.
//
// path sets the repo-relative display path, and src is the Go file contents; a syntax error fails the test immediately.
// It returns a populated Unit with Go FileType, AST, FileSet, and parsed Functions so unit and project rules behave like a live scan.
func parseReviewFixture(t *testing.T, path, src string) parserpkg.Unit {
	t.Helper()
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return parserpkg.Unit{
		File:    source.File{Path: path, Type: source.FileTypeGo},
		Source:  src,
		FileSet: fileSet,
		AST:     file,
	}
}

// TestLoopVariableAddressSkipsShadowedZeroArgAppend ensures a shadowing zero-arg append() never panics the scan.
func TestLoopVariableAddressSkipsShadowedZeroArgAppend(t *testing.T) {
	src := `package p
func f(xs []int, append func()) {
	var v int
	for _, v = range xs {
		append()
	}
	_ = v
}
`
	unit := parseReviewFixture(t, "loop.go", src)
	findings := (LoopVariableAddressRule{}).AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want 0 for shadowed zero-arg append", findings)
	}
}

// TestRequestSanitizerCallNameHandlesUnicodeCaseShrinking ensures Kelvin-sign call names never panic or break sanitizer matching.
func TestRequestSanitizerCallNameHandlesUnicodeCaseShrinking(t *testing.T) {
	unsafeSrc := `package p
import ("net/http"; "os")
func KK_x(s string) string { return s }
func h(r *http.Request) {
	p := r.FormValue("p")
	_ = KK_x(p)
	_, _ = os.Open(p)
}
`
	unit := parseReviewFixture(t, "handler.go", unsafeSrc)
	findings := (PathTraversalFileAccessRule{}).AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("path traversal findings = %d, want 1 for unsanitized Kelvin-sign helper", len(findings))
	}

	safeSrc := `package p
import ("net/http"; "os")
func K_safe(s string) string { return s }
func h(r *http.Request) {
	p := K_safe(r.FormValue("p"))
	_, _ = os.Open(p)
}
`
	safeUnit := parseReviewFixture(t, "handler_safe.go", safeSrc)
	safeFindings := (PathTraversalFileAccessRule{}).AnalyzeUnit(safeUnit, Context{})
	if len(safeFindings) != 0 {
		t.Fatalf("path traversal findings = %d, want 0 when Kelvin-sign prefix precedes _safe sanitizer token", len(safeFindings))
	}
}

// TestParallelRangeCaptureDeterministicOrder ensures multi-variable range capture reports the key deterministically on every run.
func TestParallelRangeCaptureDeterministicOrder(t *testing.T) {
	src := `package p
import "testing"
func TestCases(t *testing.T) {
	for k, v := range map[string]string{"a": "b"} {
		t.Run(k, func(t *testing.T) {
			t.Parallel()
			_ = k + v
		})
	}
}
`
	root := t.TempDir()
	// ParallelRangeCaptureRule applies only to pre-Go 1.22 modules, so seed a Go 1.21 go.mod in the scan root.
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/p\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	unit := parseReviewFixture(t, "cases_test.go", src)
	unit.File.AbsPath = filepath.Join(root, "cases_test.go")
	ctx := Context{Root: root}
	rule := ParallelRangeCaptureRule{}
	for run := 0; run < 50; run++ {
		findings := rule.AnalyzeUnit(unit, ctx)
		if len(findings) != 1 {
			t.Fatalf("run %d: findings = %d, want 1", run, len(findings))
		}
		if got := findings[0].Metadata["variable"]; got != "k" {
			t.Fatalf("run %d: variable = %v, want deterministic key \"k\"", run, got)
		}
	}
}

// TestPackageStutterHandlesUnicodeCaseExpansion ensures Unicode case mappings that expand UTF-8 byte length never panic.
func TestPackageStutterHandlesUnicodeCaseExpansion(t *testing.T) {
	src := "package ⱥ\nfunc Ⱥ() {}\n"
	unit := parseReviewFixture(t, "stutter.go", src)
	findings := (PackageStutterRule{}).AnalyzeProject([]parserpkg.Unit{unit}, Context{})
	if len(findings) != 1 {
		t.Fatalf("stutter findings = %d, want 1 without panic", len(findings))
	}
}

// TestURLGuardsDoNotSuppressSinksInsideTheirOwnBodies ensures SSRF and open-redirect sinks inside rejection branches or trim loops remain flagged.
func TestURLGuardsDoNotSuppressSinksInsideTheirOwnBodies(t *testing.T) {
	ssrfSrc := `package p
import ("net/http"; "net/url")
func fetch(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("url")
	parsed, err := url.Parse(raw)
	if err != nil {
		return
	}
	if parsed.Scheme != "https" || parsed.Hostname() != "api.internal" {
		_, _ = http.Get(raw)
		return
	}
}
`
	ssrfUnit := parseReviewFixture(t, "ssrf.go", ssrfSrc)
	ssrfFindings := (RequestControlledURLRule{}).AnalyzeUnit(ssrfUnit, Context{})
	if len(ssrfFindings) != 1 {
		t.Fatalf("SSRF findings inside rejection branch = %d, want 1", len(ssrfFindings))
	}

	redirectSrc := `package p
import ("net/http"; "strings")
func goBack(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("next")
	if !strings.HasPrefix(target, "/account/") {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
}
func trimLoop(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("next")
	target = strings.ReplaceAll(target, "\\", "/")
	for strings.HasPrefix(target, "//") {
		http.Redirect(w, r, target, http.StatusFound)
		target = strings.TrimPrefix(target, "/")
	}
}
func trimLoopSafeAfter(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("next")
	target = strings.ReplaceAll(target, "\\", "/")
	for strings.HasPrefix(target, "//") {
		target = strings.TrimPrefix(target, "/")
	}
	http.Redirect(w, r, target, http.StatusFound)
}
`
	redirectUnit := parseReviewFixture(t, "redirect.go", redirectSrc)
	redirectFindings := (OpenRedirectRule{}).AnalyzeUnit(redirectUnit, Context{})
	if len(redirectFindings) != 2 {
		t.Fatalf("open-redirect findings inside guard/loop bodies = %d, want 2 (safe redirect after completed loop should stay suppressed)", len(redirectFindings))
	}
}

// TestRequestTaintTracksLoopBackEdges ensures loop back-edge re-taint defeats pre-loop clears and flags sinks on iteration 2+.
func TestRequestTaintTracksLoopBackEdges(t *testing.T) {
	clearedBeforeLoop := `package p
import "net/http"
func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
	target = "https://fixed.example.com"
	for i := 0; i < 3; i++ {
		_, _ = http.Get(target)
		target = r.FormValue("next")
	}
}
`
	unit1 := parseReviewFixture(t, "loop1.go", clearedBeforeLoop)
	if got := len((RequestControlledURLRule{}).AnalyzeUnit(unit1, Context{})); got != 1 {
		t.Fatalf("cleared-before-loop findings = %d, want 1", got)
	}

	taintedAfterSinkInLoop := `package p
import "net/http"
func fetch(w http.ResponseWriter, r *http.Request) {
	target := "https://fixed.example.com"
	for i := 0; i < 3; i++ {
		_, _ = http.Get(target)
		target = r.FormValue("next")
	}
}
`
	unit2 := parseReviewFixture(t, "loop2.go", taintedAfterSinkInLoop)
	if got := len((RequestControlledURLRule{}).AnalyzeUnit(unit2, Context{})); got != 1 {
		t.Fatalf("tainted-after-sink-in-loop findings = %d, want 1", got)
	}

	clearedInsideLoop := `package p
import "net/http"
func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
	for i := 0; i < 3; i++ {
		target = "https://fixed.example.com"
		_, _ = http.Get(target)
		target = r.FormValue("next")
	}
}
`
	unit3 := parseReviewFixture(t, "loop3.go", clearedInsideLoop)
	if got := len((RequestControlledURLRule{}).AnalyzeUnit(unit3, Context{})); got != 0 {
		t.Fatalf("cleared-inside-loop findings = %d, want 0", got)
	}
}

// TestPackageLevelRulesRespectReportableAnchorAndIncompleteAST verifies explicit-file anchoring and nil-AST sibling skipping.
func TestPackageLevelRulesRespectReportableAnchorAndIncompleteAST(t *testing.T) {
	a := parseReviewFixture(t, "pkg/a.go", "package my_pkg\nfunc A() {}\n")
	b := parseReviewFixture(t, "pkg/b.go", "package my_pkg\nfunc B() {}\n")
	ctx := Context{ReportableFiles: map[string]struct{}{"pkg/b.go": {}}}

	underscoreFindings := (PackageNameUnderscoreRule{}).AnalyzeProject([]parserpkg.Unit{a, b}, ctx)
	if len(underscoreFindings) != 1 || underscoreFindings[0].File != "pkg/b.go" {
		t.Fatalf("underscore findings = %#v, want 1 anchored to reportable pkg/b.go", underscoreFindings)
	}

	rubric := CommentRubricRule{RequirePackageSummary: true}
	rubricFindings := rubric.AnalyzeProject([]parserpkg.Unit{a, b}, ctx)
	if len(rubricFindings) != 1 || rubricFindings[0].File != "pkg/b.go" {
		t.Fatalf("comment-rubric findings = %#v, want 1 anchored to reportable pkg/b.go", rubricFindings)
	}

	degraded := parserpkg.Unit{File: source.File{Path: "pkg/doc.go", Type: source.FileTypeGo}, Source: "// Package my_pkg docs.\npackage my_pkg\n"}
	if got := (PackageCommentRule{}).AnalyzeProject([]parserpkg.Unit{a, degraded}, Context{}); len(got) != 0 {
		t.Fatalf("package-comment findings with degraded sibling = %#v, want 0", got)
	}
	if got := rubric.AnalyzeProject([]parserpkg.Unit{a, degraded}, Context{}); len(got) != 0 {
		t.Fatalf("comment-rubric findings with degraded sibling = %#v, want 0", got)
	}
}

// TestAssertionPackageHeuristicsAvoidPackageV2FalsePositivesAndFalseSuppressions pins T085, T055/T095, and T096 fixes.
func TestAssertionPackageHeuristicsAvoidPackageV2FalsePositivesAndFalseSuppressions(t *testing.T) {
	v2Src := `package v2
import "testing"
func setup(t *testing.T) { record(t) }
func record(t *testing.T) { t.Log("ok") }
`
	v2Unit := parseReviewFixture(t, "api/v2/handler_test.go", v2Src)
	if got := (HelperMissingTHelperRule{}).AnalyzeUnit(v2Unit, Context{}); len(got) != 0 {
		t.Fatalf("package v2 helper-missing-t-helper findings = %#v, want 0", got)
	}

	sleepDelegated := `package p
import ("testing"; "time")
func noop(t *testing.T) { t.Log("no assertion") }
func TestPoll(t *testing.T) {
	for i := 0; i < 3; i++ {
		if i == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Run("noop", noop)
}
`
	if got := (SleepInTestRule{}).AnalyzeUnit(parseReviewFixture(t, "sleep_test.go", sleepDelegated), Context{}); len(got) != 1 {
		t.Fatalf("delegated t.Run sleep findings = %d, want 1", len(got))
	}

	sleepGomega := `package p
import (
	"testing"
	"time"
	"github.com/onsi/gomega"
)
func TestPoll(t *testing.T) {
	for i := 0; i < 3; i++ {
		if i == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	gomega.RegisterFailHandler(func(string, ...int) {})
}
`
	if got := (SleepInTestRule{}).AnalyzeUnit(parseReviewFixture(t, "gomega_test.go", sleepGomega), Context{}); len(got) != 1 {
		t.Fatalf("RegisterFailHandler sleep findings = %d, want 1", len(got))
	}
}
