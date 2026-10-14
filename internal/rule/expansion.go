// Package rule defines gruff-go's rule registry and analysers.
// This file implements package-name, dead-code, and security rules.
// Its findings explain code changes users can make before the next scan.
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

// PackageNameUnderscoreRule flags Go package names that contain underscores.
type PackageNameUnderscoreRule struct{}

// Definition declares the naming.package-underscore rule under the naming pillar with advisory severity and high confidence.
func (PackageNameUnderscoreRule) Definition() Definition {
	return Definition{
		ID:             "naming.package-underscore",
		Title:          "Package name contains underscore",
		Description:    "Flags Go package names that use underscores instead of short lowercase words.",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: false,
		Tags:           []string{"go-style"},
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
		if isExternalTestPackageName(unit.AST.Name.Name, unit.File.Path) {
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

// isExternalTestPackageName reports whether package name is the idiomatic
// black-box test shape `foo_test`. The production package name part must still
// be underscore-free; `bad_pkg_test` remains in scope for the rule.
func isExternalTestPackageName(name, filePath string) bool {
	if !strings.HasSuffix(filePath, "_test.go") || !strings.HasSuffix(name, "_test") {
		return false
	}
	base := strings.TrimSuffix(name, "_test")
	return base != "" && !strings.Contains(base, "_")
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
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		// "Remove the empty block" was dropped: the rule sees an empty body, not whether the
		// surrounding branch is still needed, and deleting a branch on that advice can change
		// behaviour. Since the narrowing of 2026-09-07 every reported block is a conditional
		// arm, so the useful advice is to fill it in or say why it is empty.
		Remediation: "Add the intended implementation, or leave a comment saying why the branch is deliberately empty.",
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
		// A comment in the braces is the author documenting the emptiness.
		if blockSpanHasComment(unit.AST, block) {
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
		Severity:         finding.SeverityWarning,
		Confidence:       finding.ConfidenceMedium,
		DefaultEnabled:   true,
		Tags:             []string{"security"},
		Remediation:      "Call the target executable directly and pass arguments without shell interpretation.",
		FalsePositiveShapes: []FalsePositiveShape{{
			Shape:      "Intentional shell orchestration whose interpreter and command text are fixed and reviewed can still look like injection-prone execution.",
			Mitigation: "Call the target executable directly where possible, or disable the rule for the reviewed path when shell syntax is required.",
		}},
	}
}

// AnalyzeUnit emits findings for exec.Command calls that pass shell interpreter arguments.
func (ShellCommandRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	execPackages := packageImportNames(unit.AST, "os/exec", "exec")
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		shellArgOffset, isExecCommand := execCommandShellArgOffset(call, execPackages)
		if !isExecCommand || !usesShellCommand(call, shellArgOffset) {
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

// isControlFlowBlock reports whether an empty block is an unfinished body rather than a
// construct whose emptiness is the point.
//
// Three constructs were removed from this predicate on 2026-09-07, each because its empty
// form is a deliberate Go idiom rather than missing code:
//
//   - A `for` with a header does its work in that header. `for i := 0; advance(i); i++ {}`
//     iterates deliberately with nothing in the body, so only a bare `for {}` still counts.
//   - `for range ch {}` drains a channel, and `for range ticker.C {}` waits on one. The
//     emptiness is the behaviour.
//   - `select {}` blocks the goroutine forever, which is how a program parks its main.
//
// `if`, `switch` and type-switch bodies stay: an empty one of those is a branch that was
// written and never filled in, which is what this rule exists to find.
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
			// A header carries the loop's work; only a bare infinite loop has an empty body
			// with nothing else to it.
			found = current.Body == block && current.Init == nil && current.Cond == nil && current.Post == nil
		case *ast.SwitchStmt:
			found = current.Body == block
		case *ast.TypeSwitchStmt:
			found = current.Body == block
		}
		return !found
	})
	return found
}

// blockSpanHasComment reports whether any comment sits between the block's braces.
//
// A block written as `if err != nil { // handled upstream }` is documented, not unfinished:
// the author said why it is empty. The Go parser already retains comments
// (`internal/parser/parser.go`, search: `stdparser.ParseComments`), so this needs no parser
// change and no second pass over the source.
func blockSpanHasComment(file *ast.File, block *ast.BlockStmt) bool {
	for _, group := range file.Comments {
		if group.Pos() > block.Lbrace && group.End() < block.Rbrace {
			return true
		}
	}
	return false
}

// execCommandShellArgOffset reports whether call invokes os/exec Command or
// CommandContext and returns the argument offset where the executable appears.
func execCommandShellArgOffset(call *ast.CallExpr, execPackages map[string]bool) (int, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return 0, false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !execPackages[receiver.Name] {
		return 0, false
	}
	switch selector.Sel.Name {
	case "Command":
		return 0, true
	case "CommandContext":
		return 1, true
	default:
		return 0, false
	}
}

// usesShellCommand reports whether an exec.Command call invokes a shell interpreter.
func usesShellCommand(call *ast.CallExpr, shellArgOffset int) bool {
	if len(call.Args) <= shellArgOffset+1 {
		return false
	}
	shell, ok := stringLiteral(call.Args[shellArgOffset])
	if !ok || !isShellInterpreter(shell) {
		return false
	}
	flag, ok := stringLiteral(call.Args[shellArgOffset+1])
	if !ok {
		return false
	}
	return isShellCommandFlag(flag)
}

// isShellInterpreter reports whether a string names a known shell interpreter binary.
func isShellInterpreter(value string) bool {
	normalized := strings.ReplaceAll(value, "\\", "/")
	name := strings.ToLower(filepath.Base(normalized))
	switch name {
	case "sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return true
	default:
		return false
	}
}

// isShellCommandFlag reports whether a shell flag consumes the following
// argument as command text rather than a direct executable argument.
func isShellCommandFlag(value string) bool {
	switch strings.ToLower(value) {
	case "-c", "-lc", "/c", "-command":
		return true
	default:
		return false
	}
}

// packageImportNames returns the local identifiers that import a package path,
// excluding blank and dot imports because selector-based rules cannot use them.
func packageImportNames(file *ast.File, importPath string, defaultName string) map[string]bool {
	names := map[string]bool{}
	for _, imported := range file.Imports {
		if imported.Path == nil {
			continue
		}
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil || path != importPath {
			continue
		}
		if imported.Name == nil {
			names[defaultName] = true
			continue
		}
		switch imported.Name.Name {
		case ".", "_":
			continue
		default:
			names[imported.Name.Name] = true
		}
	}
	return names
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
