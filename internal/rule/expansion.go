package rule

import (
	"fmt"
	"go/ast"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

type PackageNameUnderscoreRule struct{}

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

type EmptyBlockRule struct{}

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

type ShellCommandRule struct{}

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

type SkippedTestRule struct{}

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

func (SkippedTestRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !isTestingSkipCall(call) {
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

func isExecCommandCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Command" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && receiver.Name == "exec"
}

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

func isShellInterpreter(value string) bool {
	switch value {
	case "sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh":
		return true
	default:
		return false
	}
}

func isTestingSkipCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch selector.Sel.Name {
	case "Skip", "Skipf", "SkipNow":
		return true
	default:
		return false
	}
}

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
