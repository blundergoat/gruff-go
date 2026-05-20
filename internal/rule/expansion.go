// Package rule defines gruff-go's rule registry and analysers.
// This file implements the expansion rule pack (package name, dead code, security, test quality).
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// skipTodoMarkers are case-insensitive substrings we treat as evidence that a
// `t.Skip(...)` is debt rather than a legitimate environment-not-ready guard.
var skipTodoMarkers = []string{"todo", "fixme", "xxx", "hack", "wip"}

// PackageNameUnderscoreRule flags Go package names that contain underscores.
type PackageNameUnderscoreRule struct{}

// Definition declares the naming.package-underscore rule under the naming pillar with low severity and high confidence.
func (PackageNameUnderscoreRule) Definition() Definition {
	return Definition{
		ID:             "naming.package-underscore",
		Title:          "Package name contains underscore",
		Description:    "Flags Go package names that use underscores instead of short lowercase words.",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"go-style", "opt-in"},
		Remediation:    "Rename the package to a short lowercase name without underscores.",
	}
}

// AnalyzeProject emits one finding per Go package whose name contains an underscore.
func (PackageNameUnderscoreRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	type packageState struct {
		name string
		file string
		line int
	}
	packages := map[string]packageState{}
	for _, unit := range units {
		if unit.AST == nil || !strings.Contains(unit.AST.Name.Name, "_") {
			continue
		}
		line := 1
		if unit.FileSet != nil {
			line = unit.FileSet.Position(unit.AST.Name.Pos()).Line
		}
		key := filepath.Dir(unit.File.Path) + ":" + unit.AST.Name.Name
		state := packages[key]
		if state.file == "" || unit.File.Path < state.file {
			state = packageState{name: unit.AST.Name.Name, file: unit.File.Path, line: line}
		}
		packages[key] = state
	}
	findings := []finding.Finding{}
	for _, state := range packages {
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("package name %q contains an underscore", state.name),
			File:     state.file,
			Location: &finding.Location{Line: state.line},
			Metadata: map[string]any{"package": state.name},
		})
	}
	return findings
}

// EmptyBlockRule flags empty control-flow blocks that indicate unfinished or dead code.
type EmptyBlockRule struct{}

// Definition declares the dead-code.empty-block rule that flags empty if/for/switch/select bodies under the dead-code pillar.
func (EmptyBlockRule) Definition() Definition {
	return Definition{
		ID:             "dead-code.empty-block",
		Title:          "Empty control-flow block",
		Description:    "Flags empty control-flow blocks that usually indicate unfinished or unnecessary code.",
		Pillar:         finding.PillarDeadCode,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"opt-in"},
		Remediation:    "Remove the empty block or add the intended implementation.",
	}
}

// AnalyzeUnit emits findings for every empty control-flow block in the unit.
func (EmptyBlockRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		block, ok := node.(*ast.BlockStmt)
		if !ok || len(block.List) != 0 || !isControlFlowBlock(unit.AST, block) {
			return true
		}
		position := unit.FileSet.Position(block.Lbrace)
		findings = append(findings, finding.Finding{
			Message:  "empty control-flow block",
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
		})
		return true
	})
	return findings
}

// ShellCommandRule flags exec.Command calls that invoke a shell interpreter.
type ShellCommandRule struct{}

// Definition declares the security.shell-command rule that flags exec.Command sh/-c style invocations with medium severity.
func (ShellCommandRule) Definition() Definition {
	return Definition{
		ID:               "security.shell-command",
		Title:            "Shell command execution",
		Description:      "Flags exec.Command calls that invoke a shell interpreter with command strings.",
		Pillar:           finding.PillarSecurity,
		SecondaryPillars: []finding.Pillar{finding.PillarSensitiveData},
		Severity:         finding.SeverityMedium,
		Confidence:       finding.ConfidenceMedium,
		DefaultEnabled:   true,
		Tags:             []string{"opt-in", "security"},
		Remediation:      "Call the target executable directly and pass arguments without shell interpretation.",
	}
}

// AnalyzeUnit emits findings for exec.Command calls that pass shell interpreter arguments.
func (ShellCommandRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !isExecCommandCall(call) || !usesShellCommand(call) {
			return true
		}
		position := unit.FileSet.Position(call.Pos())
		findings = append(findings, finding.Finding{
			Message:  "exec.Command invokes a shell interpreter",
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
		})
		return true
	})
	return findings
}

// SkippedTestRule flags Go tests that call t.Skip, t.Skipf, or t.SkipNow.
type SkippedTestRule struct{}

// Definition declares the test-quality.skipped-test rule that fires when t.Skip, t.Skipf, or t.SkipNow appears in any _test.go file.
func (SkippedTestRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.skipped-test",
		Title:          "Skipped test",
		Description:    "Flags Go tests that call t.Skip, t.Skipf, or t.SkipNow.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"opt-in", "tests"},
		Remediation:    "Remove the skip or document and track the condition outside the test body.",
	}
}

// AnalyzeUnit emits findings for skip-call sites inside Go test files.
//
// A skip is considered legitimate (and therefore not flagged) when it is reachable
// only through a conditional control-flow construct (if/for/switch/range/select),
// since that pattern is the standard way to guard integration tests on missing
// infrastructure. Skips inside a conditional are still flagged when their message
// includes a TODO/FIXME-style marker so debt is not hidden behind a runtime check.
//
// Skip calls are only counted when invoked on a name that this file declared as
// a *testing.T/B/F parameter. Third-party APIs that happen to expose a method
// named Skip/Skipf/SkipNow (queue clients, table iterators, fuzzers from other
// libraries) live in test files too, and matching purely on the selector name
// produces systematic false positives there.
func (SkippedTestRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") {
		return nil
	}
	testingPackages := testingPackageNames(unit.AST)
	testingReceivers := collectFileTestingReceivers(unit.AST, testingPackages)
	conditionalRegions := conditionalBodyRanges(unit.AST)
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !isTestingSkipCall(call, testingReceivers) {
			return true
		}
		conditional := isPosInsideAny(call.Pos(), call.End(), conditionalRegions)
		if conditional && !skipMessageMentionsDebt(call) {
			return true
		}
		position := unit.FileSet.Position(call.Pos())
		findings = append(findings, finding.Finding{
			Message:  "test contains a skip call",
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
		})
		return true
	})
	return findings
}

// collectFileTestingReceivers gathers every parameter name across the file's
// function declarations and nested function literals whose declared type is
// *testing.T/B/F. The skipped-test rule only treats Skip/Skipf/SkipNow calls
// on these names as testing skips.
func collectFileTestingReceivers(file *ast.File, testingPackages map[string]bool) map[string]bool {
	receivers := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Type == nil || fn.Type.Params == nil {
			continue
		}
		collectTestingFieldNames(fn.Type.Params.List, testingPackages, receivers)
		if fn.Body != nil {
			collectNestedTestingReceivers(fn.Body, testingPackages, receivers)
		}
	}
	return receivers
}

// posRange is a half-open byte/position interval [start, end] inclusive on both
// ends because ast.Node.End() points at one past the last character but token.Pos
// comparison still works.
type posRange struct {
	start token.Pos
	end   token.Pos
}

// conditionalBodyRanges collects the positional extents of every
// control-flow body in the file. A `t.Skip(...)` whose call site falls inside
// one of these ranges is reachable only when the condition holds, so we treat
// it as a deliberate environment guard rather than test debt.
func conditionalBodyRanges(file *ast.File) []posRange {
	out := []posRange{}
	ast.Inspect(file, func(node ast.Node) bool {
		switch stmt := node.(type) {
		case *ast.IfStmt:
			if stmt.Body != nil {
				out = append(out, posRange{stmt.Body.Pos(), stmt.Body.End()})
			}
			if stmt.Else != nil {
				out = append(out, posRange{stmt.Else.Pos(), stmt.Else.End()})
			}
		case *ast.ForStmt:
			if stmt.Body != nil {
				out = append(out, posRange{stmt.Body.Pos(), stmt.Body.End()})
			}
		case *ast.RangeStmt:
			if stmt.Body != nil {
				out = append(out, posRange{stmt.Body.Pos(), stmt.Body.End()})
			}
		case *ast.SwitchStmt:
			if stmt.Body != nil {
				out = append(out, posRange{stmt.Body.Pos(), stmt.Body.End()})
			}
		case *ast.TypeSwitchStmt:
			if stmt.Body != nil {
				out = append(out, posRange{stmt.Body.Pos(), stmt.Body.End()})
			}
		case *ast.SelectStmt:
			if stmt.Body != nil {
				out = append(out, posRange{stmt.Body.Pos(), stmt.Body.End()})
			}
		}
		return true
	})
	return out
}

// isPosInsideAny reports whether the supplied [start, end] range is fully
// contained in any of the candidate ranges.
func isPosInsideAny(start, end token.Pos, ranges []posRange) bool {
	for _, r := range ranges {
		if r.start <= start && end <= r.end {
			return true
		}
	}
	return false
}

// skipMessageMentionsDebt returns true when any string-literal argument to the
// skip call carries a TODO/FIXME/XXX/HACK/WIP marker (case-insensitive). These
// markers indicate the skip is documenting work to come, not infrastructure
// availability, so we keep flagging them even when conditionally reachable.
func skipMessageMentionsDebt(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		literal, ok := stringLiteral(arg)
		if !ok {
			continue
		}
		lower := strings.ToLower(literal)
		for _, marker := range skipTodoMarkers {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}
	return false
}

// isControlFlowBlock reports whether the block is the body of an if/for/switch/select construct.
func isControlFlowBlock(file *ast.File, block *ast.BlockStmt) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		if found || node == nil {
			return false
		}
		switch current := node.(type) {
		case *ast.IfStmt:
			found = current.Body == block
		case *ast.ForStmt:
			found = current.Body == block
		case *ast.RangeStmt:
			found = current.Body == block
		case *ast.SwitchStmt:
			found = current.Body == block
		case *ast.TypeSwitchStmt:
			found = current.Body == block
		case *ast.SelectStmt:
			found = current.Body == block
		}
		return !found
	})
	return found
}

// isExecCommandCall reports whether the call expression is exec.Command(...).
func isExecCommandCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Command" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && receiver.Name == "exec"
}

// usesShellCommand reports whether an exec.Command call invokes a shell interpreter.
func usesShellCommand(call *ast.CallExpr) bool {
	if len(call.Args) < 2 {
		return false
	}
	shell, ok := stringLiteral(call.Args[0])
	if !ok || !isShellInterpreter(shell) {
		return false
	}
	flag, ok := stringLiteral(call.Args[1])
	if !ok {
		return false
	}
	return flag == "-c" || flag == "/C"
}

// isShellInterpreter reports whether a string names a known shell interpreter binary.
func isShellInterpreter(value string) bool {
	switch value {
	case "sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh":
		return true
	default:
		return false
	}
}

// isTestingSkipCall reports whether the call is a Skip variant invoked on a
// known testing receiver name. The receiver set is built from the enclosing
// file's *testing.T/B/F parameter names; selectors on other receivers do not
// count, so a third-party API's `.Skip()` method is not misreported.
func isTestingSkipCall(call *ast.CallExpr, testingReceivers map[string]bool) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch selector.Sel.Name {
	case "Skip", "Skipf", "SkipNow":
	default:
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	return testingReceivers[ident.Name]
}

// stringLiteral returns the unquoted contents of a basic string literal.
func stringLiteral(expr ast.Expr) (string, bool) {
	literal, ok := expr.(*ast.BasicLit)
	if !ok {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return value, true
}
