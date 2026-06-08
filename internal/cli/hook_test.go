package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestHookCapabilitiesAdvertiseContract pins the §4 negotiation payload.
func TestHookCapabilitiesAdvertiseContract(t *testing.T) {
	for _, args := range [][]string{
		{"--capabilities"},
		{"hook", "--capabilities", "--format", "json"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Main(args, &out, &errOut); code != 0 {
				t.Fatalf("%v exit = %d, stderr = %s", args, code, errOut.String())
			}
			var got hookCapabilities
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatalf("capabilities json: %v\n%s", err, out.String())
			}
			if got.ContractVersion != hookContractVersion || !got.Supports.NewOnly || !got.Supports.ScopeField {
				t.Fatalf("capabilities = %#v, want gruff.hook.v1 with newOnly/scope support", got)
			}
			if got.Flags.ChangedRanges != "--changed-ranges" || got.Flags.Diff != "--diff" || got.Flags.Baseline != "--baseline" {
				t.Fatalf("flags = %#v", got.Flags)
			}
			if got.FlagOrder != "flags-before-path" {
				t.Fatalf("flagOrder = %q, want flags-before-path for Go flag parser", got.FlagOrder)
			}
		})
	}
}

// TestHookChangedRegionOmitsFileScopeWithoutAnchorResidual covers B1 and B2.
func TestHookChangedRegionOmitsFileScopeWithoutAnchorResidual(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "long.go", hookLongFixture(510))
	t.Chdir(root)

	full, code := runHookReport(t, "hook", "--format", "json", "--no-config", "long.go")
	if code != 0 {
		t.Fatalf("full hook exit = %d", code)
	}
	size := requireHookFinding(t, full, "size.file-length")
	if size.Scope != "file" {
		t.Fatalf("size.file-length scope = %q, want file", size.Scope)
	}

	anchor, code := runHookReport(t, "hook", "--format", "json", "--no-config", "--changed-ranges", "501-501", "long.go")
	if code != 0 {
		t.Fatalf("changed hook exit = %d", code)
	}
	if findHookFinding(anchor, "size.file-length") != nil {
		t.Fatalf("file-scope finding survived changed-region anchor edit: %#v", anchor.Findings)
	}
	if anchor.Suppressed.Count == 0 {
		t.Fatalf("suppressed.count = 0, want file-scope drop counted")
	}

	line, code := runHookReport(t, "hook", "--format", "json", "--no-config", "--changed-ranges", "7-7", "long.go")
	if code != 0 {
		t.Fatalf("line hook exit = %d", code)
	}
	shell := requireHookFinding(t, line, "security.shell-command")
	if shell.Scope != "line" || shell.Line == nil || *shell.Line != 7 {
		t.Fatalf("shell finding = %#v, want line-scope at line 7", shell)
	}
}

// TestHookFindingFieldsMetadataEnumsAndAdvisoryExit covers B4, B5, B6, and B10.
func TestHookFindingFieldsMetadataEnumsAndAdvisoryExit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "long.go", hookLongFixture(510))
	t.Chdir(root)

	payload, code := runHookReport(t, "hook", "--format", "json", "--no-config", "long.go")
	if code != 0 {
		t.Fatalf("hook with findings exit = %d, want advisory exit 0", code)
	}
	if len(payload.Findings) == 0 {
		t.Fatal("hook findings empty, want conformance fixture findings")
	}
	for _, item := range payload.Findings {
		if item.Remediation == "" {
			t.Fatalf("%s remediation is empty", item.RuleID)
		}
		if item.StableIdentity == "" {
			t.Fatalf("%s stableIdentity is empty", item.RuleID)
		}
		if !validHookSeverity(item.Severity) || !validHookScope(item.Scope) {
			t.Fatalf("finding has invalid enums: %#v", item)
		}
	}
	size := requireHookFinding(t, payload, "size.file-length")
	if size.Metadata["measured"] != float64(510) || size.Metadata["threshold"] != float64(500) ||
		size.Metadata["unit"] != "lines" || size.Metadata["direction"] != "above" {
		t.Fatalf("size metadata = %#v, want measured/threshold/unit/direction", size.Metadata)
	}
}

// TestHookStableIdentityAndBaselineNewOnly covers B3 for baseline new-only.
func TestHookStableIdentityAndBaselineNewOnly(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	writeFile(t, root, "long.go", hookLongFixture(510))
	first, _ := runHookReport(t, "hook", "--format", "json", "--no-config", "long.go")
	firstSize := requireHookFinding(t, first, "size.file-length")
	writeFile(t, root, "long.go", hookLongFixture(511))
	grown, _ := runHookReport(t, "hook", "--format", "json", "--no-config", "long.go")
	grownSize := requireHookFinding(t, grown, "size.file-length")
	if firstSize.StableIdentity != grownSize.StableIdentity {
		t.Fatalf("stableIdentity changed with measured value: %q != %q", firstSize.StableIdentity, grownSize.StableIdentity)
	}
	if firstSize.Fingerprint == grownSize.Fingerprint {
		t.Fatalf("fingerprint should remain allowed to move when message/count changes")
	}

	var baselineOut, baselineErr bytes.Buffer
	if code := Main([]string{"baseline", "--no-config", "--out", "baseline.json", "long.go"}, &baselineOut, &baselineErr); code != 0 {
		t.Fatalf("baseline exit = %d, stderr = %s", code, baselineErr.String())
	}
	writeFile(t, root, "long.go", hookLongFixture(512))
	baselined, _ := runHookReport(t, "hook", "--format", "json", "--no-config", "--baseline", "baseline.json", "long.go")
	if findHookFinding(baselined, "size.file-length") != nil {
		t.Fatalf("baseline new-only re-surfaced grown file-length finding: %#v", baselined.Findings)
	}

	writeFile(t, root, "short.go", hookLongFixture(500))
	var shortBaseOut, shortBaseErr bytes.Buffer
	if code := Main([]string{"baseline", "--no-config", "--out", "short-baseline.json", "short.go"}, &shortBaseOut, &shortBaseErr); code != 0 {
		t.Fatalf("short baseline exit = %d, stderr = %s", code, shortBaseErr.String())
	}
	writeFile(t, root, "short.go", hookLongFixture(501))
	newOnly, _ := runHookReport(t, "hook", "--format", "json", "--no-config", "--baseline", "short-baseline.json", "short.go")
	if findHookFinding(newOnly, "size.file-length") == nil {
		t.Fatalf("newly crossing file-length finding not returned: %#v", newOnly.Findings)
	}
}

// TestHookDiffNewOnlyUsesStableIdentity covers B3 for git diff new-only.
func TestHookDiffNewOnlyUsesStableIdentity(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	hookRunGit(t, root, "init", "-q")
	hookRunGit(t, root, "config", "user.email", "test@example.test")
	hookRunGit(t, root, "config", "user.name", "test")

	writeFile(t, root, "long.go", hookLongFixture(510))
	hookRunGit(t, root, "add", "long.go")
	hookRunGit(t, root, "commit", "-q", "-m", "long baseline")
	writeFile(t, root, "long.go", hookLongFixture(511))
	grown, code := runHookReport(t, "hook", "--format", "json", "--no-config", "--diff", "HEAD", "long.go")
	if code != 0 {
		t.Fatalf("grown diff hook exit = %d", code)
	}
	if findHookFinding(grown, "size.file-length") != nil {
		t.Fatalf("diff new-only re-surfaced existing file-length finding: %#v", grown.Findings)
	}

	writeFile(t, root, "short.go", hookLongFixture(500))
	hookRunGit(t, root, "add", "short.go")
	hookRunGit(t, root, "commit", "-q", "-m", "short baseline")
	writeFile(t, root, "short.go", hookLongFixture(501))
	newlyCrossed, code := runHookReport(t, "hook", "--format", "json", "--no-config", "--diff", "HEAD", "short.go")
	if code != 0 {
		t.Fatalf("new diff hook exit = %d", code)
	}
	if findHookFinding(newlyCrossed, "size.file-length") == nil {
		t.Fatalf("diff new-only did not return newly crossing file-length finding: %#v", newlyCrossed.Findings)
	}
}

// TestHookReportsIgnoredPathsAndConfigErrors covers B7 and B8.
func TestHookReportsIgnoredPathsAndConfigErrors(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gruff-go.yaml", "schemaVersion: gruff-go.config.v0.1\npaths:\n  ignore:\n    - \"ignored/**\"\n")
	writeFile(t, root, "ignored/skip.go", "// Package ignored is a test fixture.\npackage ignored\n")
	t.Chdir(root)

	ignored, code := runHookReport(t, "hook", "--format", "json", "ignored/skip.go")
	if code != 0 {
		t.Fatalf("ignored hook exit = %d", code)
	}
	if len(ignored.Ignored.Paths) != 1 || ignored.Ignored.Paths[0].Path != "ignored/skip.go" ||
		ignored.Ignored.Paths[0].Source != "config" || ignored.Ignored.Paths[0].Pattern != "ignored/**" {
		t.Fatalf("ignored paths = %#v", ignored.Ignored.Paths)
	}

	writeFile(t, root, ".gruff-go.yaml", "schemaVersion: gruff-go.config.v9\n")
	invalid, code := runHookReport(t, "hook", "--format", "json", ".")
	if code != 2 {
		t.Fatalf("invalid config exit = %d, want 2", code)
	}
	if invalid.Config.SchemaOK || invalid.Config.Error == nil || !strings.Contains(*invalid.Config.Error, "gruff-go init --force") {
		t.Fatalf("config state = %#v, want schemaOk false with remediation", invalid.Config)
	}
}

// runHookReport executes the CLI and decodes gruff.hook.v1 JSON.
func runHookReport(t *testing.T, args ...string) (hookReport, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Main(args, &out, &errOut)
	if out.Len() == 0 {
		t.Fatalf("hook %v produced no stdout; exit=%d stderr=%s", args, code, errOut.String())
	}
	var payload hookReport
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("hook json %v: %v\nstdout=%s\nstderr=%s", args, err, out.String(), errOut.String())
	}
	return payload, code
}

// requireHookFinding returns a named finding or fails the test.
func requireHookFinding(t *testing.T, payload hookReport, ruleID string) hookFinding {
	t.Helper()
	item := findHookFinding(payload, ruleID)
	if item == nil {
		t.Fatalf("missing finding %s in %#v", ruleID, payload.Findings)
	}
	return *item
}

// findHookFinding returns the first finding for a rule ID.
func findHookFinding(payload hookReport, ruleID string) *hookFinding {
	for index := range payload.Findings {
		if payload.Findings[index].RuleID == ruleID {
			return &payload.Findings[index]
		}
	}
	return nil
}

// validHookSeverity checks the closed severity enum.
func validHookSeverity(severity finding.Severity) bool {
	switch severity {
	case finding.SeverityAdvisory, finding.SeverityWarning, finding.SeverityError:
		return true
	default:
		return false
	}
}

// validHookScope checks the closed scope enum.
func validHookScope(scope string) bool {
	switch scope {
	case "line", "symbol", "file", "project":
		return true
	default:
		return false
	}
}

// hookLongFixture builds a file with both line-scope and file-scope findings.
func hookLongFixture(lines int) string {
	var builder strings.Builder
	builder.WriteString("// Package sample is a test package.\n")
	builder.WriteString("package sample\n\n")
	builder.WriteString("import \"os/exec\"\n\n")
	builder.WriteString("func Risky() {\n")
	builder.WriteString("    exec.Command(\"sh\", \"-c\", \"echo hi\").Run()\n")
	builder.WriteString("}\n")
	for line := 9; line <= lines; line++ {
		fmt.Fprintf(&builder, "// filler %03d\n", line)
	}
	return builder.String()
}

// hookRunGit runs git commands for diff new-only tests.
func hookRunGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
}

// TestHookFixtureLineCount verifies generated source keeps the exact requested physical length.
func TestHookFixtureLineCount(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "long.go", hookLongFixture(510))
	data, err := os.ReadFile(filepath.Join(root, "long.go"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "\n"); got != 510 {
		t.Fatalf("hookLongFixture lines = %d, want 510", got)
	}
}

// TestHookMetadataDirection pins B5 `direction`: ceiling rules report "above" and
// the floor rule (comment-rubric package summary) reports "below". A wrong
// direction inverts the remediation signal for any metadata consumer.
func TestHookMetadataDirection(t *testing.T) {
	above := hookMetadata("size.file-length", map[string]any{"lines": 510, "threshold": 500})
	if above["direction"] != "above" || above["measured"] != 510 || above["threshold"] != 500 || above["unit"] != "lines" {
		t.Fatalf("ceiling metadata = %#v, want measured 510 above threshold 500 lines", above)
	}
	below := hookMetadata("docs.comment-rubric", map[string]any{"kind": "package", "lines": 1, "threshold": 2})
	if below["direction"] != "below" {
		t.Fatalf("floor metadata = %#v, want direction below (measured 1 < threshold 2)", below)
	}
}

// TestHookScopeAndDirectionRuleIDsExist guards the hook layer's hardcoded rule-ID
// tables against registry drift: a renamed or removed rule must not silently
// leave hookScope / hookThresholdDirection pointing at a dead ID.
func TestHookScopeAndDirectionRuleIDsExist(t *testing.T) {
	registry, _, _, err := configuredRegistry("", true)
	if err != nil {
		t.Fatalf("configuredRegistry: %v", err)
	}
	known := map[string]bool{}
	for _, definition := range registry.Definitions() {
		known[definition.ID] = true
	}
	for id := range hookFileScopeRuleIDs {
		if !known[id] {
			t.Errorf("hookFileScopeRuleIDs references unknown rule %q", id)
		}
	}
	for id := range hookBelowThresholdRuleIDs {
		if !known[id] {
			t.Errorf("hookBelowThresholdRuleIDs references unknown rule %q", id)
		}
	}
}

// TestHookDiffUnstagedBaseIsIndexNotHead verifies `--diff unstaged` measures
// new-only against the index (the working tree's true base), not HEAD: an
// unstaged edit that newly crosses a file-level threshold surfaces, while a
// crossing already staged into the index does not resurface.
func TestHookDiffUnstagedBaseIsIndexNotHead(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	hookRunGit(t, root, "init", "-q")
	hookRunGit(t, root, "config", "user.email", "test@example.test")
	hookRunGit(t, root, "config", "user.name", "test")

	writeFile(t, root, "f.go", hookLongFixture(500))
	hookRunGit(t, root, "add", "f.go")
	hookRunGit(t, root, "commit", "-q", "-m", "short baseline")

	// An unstaged edit crosses the threshold: new vs the index, so it surfaces.
	writeFile(t, root, "f.go", hookLongFixture(510))
	surfaced, code := runHookReport(t, "hook", "--format", "json", "--no-config", "--diff", "unstaged", "f.go")
	if code != 0 {
		t.Fatalf("unstaged surface hook exit = %d", code)
	}
	if findHookFinding(surfaced, "size.file-length") == nil {
		t.Fatalf("unstaged edit that newly crossed file-length did not surface: %#v", surfaced.Findings)
	}

	// Stage that crossing, then edit further unstaged. The crossing now lives in
	// the index, so an unstaged-scoped run must NOT resurface it (a HEAD base would,
	// since HEAD is still the short version).
	hookRunGit(t, root, "add", "f.go")
	writeFile(t, root, "f.go", hookLongFixture(511))
	staged, code := runHookReport(t, "hook", "--format", "json", "--no-config", "--diff", "unstaged", "f.go")
	if code != 0 {
		t.Fatalf("unstaged staged-base hook exit = %d", code)
	}
	if findHookFinding(staged, "size.file-length") != nil {
		t.Fatalf("unstaged new-only used HEAD not the index; staged file-length resurfaced: %#v", staged.Findings)
	}
}
