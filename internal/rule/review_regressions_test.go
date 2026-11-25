// Package rule tests cover high-impact regression scenarios verified during the 0.6.0 review.
//
// Each test pins a concrete crash, non-determinism, false-positive, or false-negative defect so later refactors cannot reintroduce it.
// Every fixture mirrors realistic Go source a developer or coding agent writes during normal work.
package rule

import (
	"os"
	"path/filepath"
	"strings"
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
	root := t.TempDir()
	absPath := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(absPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	units, diags := parserpkg.Parse([]source.File{{Path: path, AbsPath: absPath, Type: source.FileTypeGo}})
	if len(diags) != 0 || len(units) != 1 {
		t.Fatalf("parse %s: units=%d diags=%#v", path, len(units), diags)
	}
	return units[0]
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

// TestSecurityRuleRegressionsForTaintWorkflowAndArchive covers taint clearing, indentless/flow workflow YAML, and archive zip-slip hardening.
func TestSecurityRuleRegressionsForTaintWorkflowAndArchive(t *testing.T) {
	// Sink precedes target = raw assignment; taintIntroPos must not back-date target to raw's earlier declaration.
	preSink := `package p
import ("net/http")
func handle(r *http.Request) {
	raw := r.FormValue("u")
	target := "https://fixed.example/ok"
	_, _ = http.Get(target)
	target = raw
	_ = target
}
`
	if got := (RequestControlledURLRule{}).AnalyzeUnit(parseReviewFixture(t, "handler.go", preSink), Context{}); len(got) != 0 {
		t.Fatalf("sink-before-reassignment findings = %#v, want 0", got)
	}

	// Range reassignment after clean write must defeat taint clearing.
	rangeRetaint := `package p
import ("net/http")
func handle(r *http.Request) {
	target := r.FormValue("u")
	target = "https://fixed.example/ok"
	for _, target = range r.URL.Query()["u"] {
	}
	_, _ = http.Get(target)
}
`
	if got := (RequestControlledURLRule{}).AnalyzeUnit(parseReviewFixture(t, "handler.go", rangeRetaint), Context{}); len(got) != 1 {
		t.Fatalf("range-retaint findings = %#v, want 1", got)
	}

	// First taint introduction directly from ranging over request values must also flag SSRF.
	rangeIntro := `package p
import ("net/http")
func handle(r *http.Request) {
	for _, target := range r.URL.Query()["u"] {
		_, _ = http.Get(target)
	}
}
`
	if got := (RequestControlledURLRule{}).AnalyzeUnit(parseReviewFixture(t, "handler.go", rangeIntro), Context{}); len(got) != 1 {
		t.Fatalf("range-intro findings = %#v, want 1", got)
	}

	// Indentless workflow sequence, column-0 comments inside on:, and negative nested branch filter checks.
	workflow := "# Note: avoid pull_request_target misuse\n" +
		"name: pull_request_target check\n" +
		"on:\n" +
		"# column-0 comment inside on block\n" +
		"- pull_request_target\n" +
		"jobs:\n" +
		"  deploy:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    steps:\n" +
		"    - if: github.event_name == 'push'\n" +
		"      run: echo ${{ secrets.DEPLOY_TOKEN }}\n"
	wfUnit := parserpkg.Unit{File: source.File{Path: ".github/workflows/ci.yml", Type: source.FileTypeText}, Source: workflow}
	prFindings := (GitHubActionsPullRequestTargetRule{}).AnalyzeUnit(wfUnit, Context{})
	if len(prFindings) != 1 || prFindings[0].Location.Line != 5 {
		t.Fatalf("pull_request_target findings = %#v, want 1 at line 5", prFindings)
	}
	if secretFindings := (GitHubActionsSecretsInPRRule{}).AnalyzeUnit(wfUnit, Context{}); len(secretFindings) != 0 {
		t.Fatalf("indentless guarded step secret findings = %#v, want 0", secretFindings)
	}
	branchFilter := "on:\n  push:\n    branches:\n      - fix-pull_request_target-bug\njobs:\n  b:\n    steps:\n      - run: echo ok\n"
	if got := (GitHubActionsPullRequestTargetRule{}).AnalyzeUnit(parserpkg.Unit{File: wfUnit.File, Source: branchFilter}, Context{}); len(got) != 0 {
		t.Fatalf("branch filter pull_request_target findings = %#v, want 0", got)
	}

	// Flow mappings and flow sequences split over lines still name pull_request_target, while a nested filter value inside one does not.
	steps := "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
	flowCases := []struct {
		name     string
		on       string
		wantLine int
	}{
		{name: "inline flow mapping", on: "on: {pull_request_target: {types: [opened]}}\n", wantLine: 1},
		{name: "multi-line flow sequence", on: "on: [push,\n  pull_request_target]\n", wantLine: 2},
		{name: "flow sequence under on block", on: "on:\n  [push, pull_request_target]\n", wantLine: 2},
		{name: "comment mentioning trigger before real line", on: "on: [push, # pull_request_target\n  pull_request_target]\n", wantLine: 2},
		{name: "nested branch filter in flow mapping", on: "on: {push: {branches: [pull_request_target]}}\n", wantLine: 0},
	}
	for _, tc := range flowCases {
		got := (GitHubActionsPullRequestTargetRule{}).AnalyzeUnit(parserpkg.Unit{File: wfUnit.File, Source: tc.on + steps}, Context{})
		if (tc.wantLine == 0 && len(got) != 0) || (tc.wantLine > 0 && (len(got) != 1 || got[0].Location.Line != tc.wantLine)) {
			t.Fatalf("%s: pull_request_target findings = %#v, want line %d", tc.name, got, tc.wantLine)
		}
	}

	assertArchiveTraversalHardening(t)
}

// assertArchiveTraversalHardening covers Clean-only, wrapped entry names, unrelated Contains filters, ignored Rel, and stdlib IsLocal guards.
func assertArchiveTraversalHardening(t *testing.T) {
	t.Helper()
	cases := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "bare Clean without containment",
			src:  "package p\nimport (\"archive/zip\"; \"path/filepath\")\nfunc extract(file *zip.File, dest string) {\n\ttarget := filepath.Join(dest, file.Name)\n\tclean := filepath.Clean(target)\n\t_ = clean\n}\n",
			want: 1,
		},
		{
			name: "wrapped Clean inside Join entry arg",
			src:  "package p\nimport (\"archive/zip\"; \"path/filepath\")\nfunc extract(file *zip.File, dest string) {\n\ttarget := filepath.Join(dest, filepath.Clean(file.Name))\n\t_ = target\n}\n",
			want: 1,
		},
		{
			name: "unrelated MkdirAll err Contains does not suppress",
			src:  "package p\nimport (\"archive/zip\"; \"os\"; \"path/filepath\"; \"strings\")\nfunc extract(file *zip.File, dest string) {\n\ttarget := filepath.Join(dest, file.Name)\n\terr := os.MkdirAll(filepath.Dir(target), 0o755)\n\tif err != nil && strings.Contains(err.Error(), \"perm\") {\n\t\treturn\n\t}\n}\n",
			want: 1,
		},
		{
			name: "ignored Rel result does not suppress",
			src:  "package p\nimport (\"archive/zip\"; \"fmt\"; \"path/filepath\")\nfunc extract(file *zip.File, dest string) {\n\ttarget := filepath.Join(dest, file.Name)\n\trel, _ := filepath.Rel(dest, target)\n\tfmt.Println(rel)\n}\n",
			want: 1,
		},
		{
			name: "entry-name Contains filter without a parent-directory check does not suppress",
			src:  "package p\nimport (\"archive/zip\"; \"os\"; \"path/filepath\"; \"strings\")\nfunc extract(file *zip.File, dest string) {\n\tif strings.Contains(file.Name, \"__MACOSX\") {\n\t\treturn\n\t}\n\ttarget := filepath.Join(dest, file.Name)\n\t_, _ = os.Create(target)\n}\n",
			want: 1,
		},
		{
			name: "joined-target Contains filter without a parent-directory check does not suppress",
			src:  "package p\nimport (\"archive/zip\"; \"os\"; \"path/filepath\"; \"strings\")\nfunc extract(file *zip.File, dest string) {\n\ttarget := filepath.Join(dest, file.Name)\n\tif strings.Contains(target, \"__MACOSX\") {\n\t\treturn\n\t}\n\t_, _ = os.Create(target)\n}\n",
			want: 1,
		},
		{
			name: "entry-name Contains parent-directory check suppresses",
			src:  "package p\nimport (\"archive/zip\"; \"path/filepath\"; \"strings\")\nfunc extract(file *zip.File, dest string) {\n\tif strings.Contains(file.Name, \"..\") {\n\t\treturn\n\t}\n\ttarget := filepath.Join(dest, file.Name)\n\t_ = target\n}\n",
			want: 0,
		},
		{
			name: "stdlib filepath.IsLocal guard suppresses",
			src:  "package p\nimport (\"archive/zip\"; \"path/filepath\")\nfunc extract(file *zip.File, dest string) {\n\tif !filepath.IsLocal(file.Name) {\n\t\treturn\n\t}\n\ttarget := filepath.Join(dest, file.Name)\n\t_ = target\n}\n",
			want: 0,
		},
	}
	for _, tc := range cases {
		if got := (ArchivePathTraversalRule{}).AnalyzeUnit(parseReviewFixture(t, "zip.go", tc.src), Context{}); len(got) != tc.want {
			t.Fatalf("%s: findings = %#v, want %d", tc.name, got, tc.want)
		}
	}
}

// TestSizeDocsAndStyleRuleRegressions covers init() keys, multiline var funcs, FuncLit args, rationales, empty blocks, receivers, and panic.
func TestSizeDocsAndStyleRuleRegressions(t *testing.T) {
	// First init() carries a data-only keyed literal (discounted below cap) while the second is long with FuncLit (flagged).
	dataFields := strings.Repeat("\t\tA: 1,\n", 10)
	longBody := strings.Repeat("\t\tx++\n", 10)
	src := "package p\ntype Data struct{ A int }\ntype Cmd struct{ Run func() }\nfunc regData(d Data) {}\nfunc reg(c Cmd) {}\n" +
		"func init() {\n\tregData(Data{\n" + dataFields + "\t})\n}\n" +
		"func init() {\n\treg(Cmd{\n\t\tRun: func() {\n\t\t\tx := 0\n" + longBody + "\t\t\t_ = x\n\t\t},\n\t})\n}\n" +
		"var multiline =\n\tfunc() {\n\t\tregData(Data{\n" + dataFields + "\t\t})\n\t}\n"
	gotLen := (FunctionLengthRule{MaxLines: 8}).AnalyzeUnit(parseReviewFixture(t, "init.go", src), Context{})
	if len(gotLen) != 1 || gotLen[0].Symbol != "init" {
		t.Fatalf("function-length findings = %#v, want exactly 1 on second init()", gotLen)
	}

	// Multiline /* ... */ rationale above #nosec passes, while bare #nosec G101,G204 fails.
	suppSrc := "package p\nfunc f() {\n/*\nIntentional fixture for validation.\n*/\n// #nosec G101\n_ = 1\n// #nosec G101,G204\n_ = 2\n}\n"
	suppFindings := (SuppressionWithoutRationaleRule{}).AnalyzeUnit(parseReviewFixture(t, "s.go", suppSrc), Context{})
	if len(suppFindings) != 1 || suppFindings[0].Location.Line != 8 {
		t.Fatalf("suppression findings = %#v, want 1 at line 8", suppFindings)
	}

	// Single-line commented empty block if ok {/* intentional */} stays quiet.
	if got := (EmptyBlockRule{}).AnalyzeUnit(parseReviewFixture(t, "e.go", "package p\nfunc f(ok bool) { if ok {/* intentional */} }\n"), Context{}); len(got) != 0 {
		t.Fatalf("commented single-line empty block findings = %#v, want 0", got)
	}

	// Parenthesized receiver (*T) resolves to T in naming.receiver-consistency.
	recvSrc := "package p\ntype T struct{}\nfunc (t (*T)) A() {}\nfunc (other *T) B() {}\n"
	if got := (ReceiverConsistencyRule{}).AnalyzeProject([]parserpkg.Unit{parseReviewFixture(t, "r.go", recvSrc)}, Context{}); len(got) != 1 {
		t.Fatalf("paren receiver findings = %#v, want 1", got)
	}

	// Locally shadowed panic callback does not trigger dead-code.unreachable-code, while builtin panic still does.
	panicSrc := "package p\nfunc shadowed(panic func(string)) {\n\tpanic(\"logged\")\n\t_ = 1\n}\nfunc real() {\n\tpanic(\"boom\")\n\t_ = 2\n}\n"
	if got := (UnreachableCodeRule{}).AnalyzeUnit(parseReviewFixture(t, "panic.go", panicSrc), Context{}); len(got) != 1 {
		t.Fatalf("unreachable-code panic findings = %#v, want 1 (real panic only)", got)
	}
}
