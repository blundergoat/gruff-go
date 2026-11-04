// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds the naming.package-underscore, dead-code.empty-block and security.shell-command rules.
// Their findings explain code changes users can make before the next scan.
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

// PackageNameUnderscoreRule flags Go package names that contain underscores, as rule naming.package-underscore.
//
// It ships disabled, so its findings appear only when the user's configuration enables it.
// Black-box test packages such as foo_test in _test.go files are left alone.
type PackageNameUnderscoreRule struct{}

// Definition declares the naming.package-underscore rule under the naming pillar with advisory severity and high confidence.
// It returns the same populated Definition on every call, disabled by default and tagged go-style, with a rename remediation.
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
//
// units holds every parsed file of the scan; files without an AST and external test packages such as foo_test in _test.go files are skipped.
// It returns one finding per directory and package name, at the package clause of the lexically first file, or line 1 without a FileSet.
//
// The result is empty but non-nil when nothing matches, and its order follows map iteration rather than file order.
func (PackageNameUnderscoreRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	type packageState struct {
		name string
		file string
		line int
	}
	underscorePackages := map[string]packageState{}
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
		state := underscorePackages[key]
		// Keeping the lexically first file pins each finding to the same location on every scan, whatever order the files arrive in.
		if state.file == "" || unit.File.Path < state.file {
			state = packageState{name: unit.AST.Name.Name, file: unit.File.Path, line: line}
		}
		underscorePackages[key] = state
	}
	findings := []finding.Finding{}
	for _, state := range underscorePackages {
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("package name %q contains an underscore", state.name),
			File:     state.file,
			Location: &finding.Location{Line: state.line},
			Metadata: map[string]any{"package": state.name},
		})
	}
	return findings
}

// isExternalTestPackageName reports whether package name is the idiomatic black-box test shape foo_test, which the rule leaves alone.
//
// filePath must end in _test.go as well, so a foo_test package declared in any other file stays in scope; name is the declared package name.
// The part before _test must be non-empty and underscore-free, so bad_pkg_test and a bare _test are still reported.
func isExternalTestPackageName(name, filePath string) bool {
	if !strings.HasSuffix(filePath, "_test.go") || !strings.HasSuffix(name, "_test") {
		return false
	}
	base := strings.TrimSuffix(name, "_test")
	return base != "" && !strings.Contains(base, "_")
}

// EmptyBlockRule flags empty control-flow blocks that indicate unfinished or dead code, as rule dead-code.empty-block.
//
// It reports empty if, switch and type-switch bodies and bare for loops; a comment inside the braces marks the emptiness as deliberate.
type EmptyBlockRule struct{}

// Definition declares the dead-code.empty-block rule that flags empty if, bare for, switch and type-switch bodies under the dead-code pillar.
// It returns the same populated Definition on every call: advisory severity, medium confidence, enabled by default.
func (EmptyBlockRule) Definition() Definition {
	return Definition{
		ID:             "dead-code.empty-block",
		Title:          "Empty control-flow block",
		Description:    "Flags empty control-flow blocks that usually indicate unfinished or unnecessary code.",
		Pillar:         finding.PillarDeadCode,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		// Deleting an empty branch can change behaviour, so the remediation never recommends deletion.
		//
		// The rule sees an empty body, not whether the surrounding branch is still needed.
		// Reported bodies are bare infinite loops and empty if, switch and type-switch bodies, so the advice is to fill the body in or explain it.
		Remediation: "Add the intended implementation, or leave a comment saying why the branch is deliberately empty.",
	}
}

// AnalyzeUnit emits findings for every empty control-flow block in one parsed file.
//
// unit is that file; only bodies isControlFlowBlock accepts count, and braces holding a comment mark the emptiness as deliberate.
// It returns one finding per remaining block at its opening brace, nil without an AST or FileSet, and an empty slice when none remain.
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

// ShellCommandRule flags exec.Command calls that invoke a shell interpreter, as rule security.shell-command.
//
// It matches exec.Command and exec.CommandContext only with a literal shell name and command flag, such as exec.Command("sh", "-c", script).
type ShellCommandRule struct{}

// Definition declares the security.shell-command rule that flags exec.Command sh/-c style invocations with warning severity and medium confidence.
// It returns the same populated Definition on every call, enabled by default, with PillarSensitiveData as a secondary pillar.
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

// AnalyzeUnit emits findings for exec.Command and exec.CommandContext calls that start a shell with command text.
//
// unit is one parsed file; calls count only through its os/exec import names, with string-literal shell and command-flag arguments.
// It returns one finding per matching call, nil when the unit has no AST or FileSet, and an empty slice when nothing matches.
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

// isControlFlowBlock reports whether block is an if, bare for, switch or type-switch body, the bodies this rule checks for unfinished code.
//
// Empty range and select bodies are idioms that drain or wait on channels or park a goroutine, and a for header can carry the loop's work.
// An empty if, switch or type-switch body can indicate an unfinished branch, which this rule exists to find.
//
// file is the whole parsed source, searched for the statement whose body is block; the walk stops at the first match.
// It returns false when no if, bare for, switch or type-switch statement in file has block as its body, so an empty else branch is not counted.
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
			// A header carries the loop's work, so only a bare infinite loop has an empty body with nothing else to it.
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

// blockSpanHasComment reports whether any comment sits between the braces of block.
//
// A block written as if err != nil { // handled upstream } is documented, not unfinished: the author said why it is empty.
// The Go parser already keeps comments (internal/parser/parser.go, search stdparser.ParseComments), so no parser change or second pass is needed.
//
// file supplies the comment groups, compared by position with the braces of block; a group counts only when it lies strictly inside them.
func blockSpanHasComment(file *ast.File, block *ast.BlockStmt) bool {
	for _, group := range file.Comments {
		if group.Pos() > block.Lbrace && group.End() < block.Rbrace {
			return true
		}
	}
	return false
}

// execCommandShellArgOffset reports whether call invokes os/exec Command or CommandContext and returns the argument offset of the executable.
//
// execPackages holds the local names the file imports os/exec under; any other receiver or call shape gives 0 and false.
// The offset is 0 for Command and 1 for CommandContext, whose first argument is the context.
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

// usesShellCommand reports whether an exec.Command call starts a shell that runs command text rather than a program.
//
// shellArgOffset is the argument index of the executable in call, 0 for Command and 1 for CommandContext.
// It is true only when that argument is a literal shell name and the next is a literal command flag; fewer arguments give false.
func usesShellCommand(call *ast.CallExpr, shellArgOffset int) bool {
	if len(call.Args) <= shellArgOffset+1 {
		return false
	}
	shell, ok := stringLiteral(call.Args[shellArgOffset])
	// A shell name held in a variable is not read, so exec.Command(shell, "-c", script) goes unreported.
	if !ok || !isShellInterpreter(shell) {
		return false
	}
	flag, ok := stringLiteral(call.Args[shellArgOffset+1])
	if !ok {
		return false
	}
	return isShellCommandFlag(flag)
}

// isShellInterpreter reports whether value names a known shell interpreter binary.
//
// value may be a path in either slash style; only its lower-cased base name is compared.
// The known names are sh, bash, zsh, cmd, powershell and pwsh, plus cmd.exe, powershell.exe and pwsh.exe; anything else gives false.
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

// isShellCommandFlag reports whether a shell flag makes the next argument command text rather than a direct executable argument.
// value is compared case-insensitively against -c, -lc, /c and -command; any other value gives false.
func isShellCommandFlag(value string) bool {
	switch strings.ToLower(value) {
	case "-c", "-lc", "/c", "-command":
		return true
	default:
		return false
	}
}

// packageImportNames returns the local identifiers under which file imports importPath, for rules that match calls through a selector.
//
// file supplies the import specs, importPath is the unquoted path to match, and defaultName is the key recorded for an unaliased import.
// Blank and dot imports are left out because no selector can use them; the map is empty, never nil, when no usable name remains.
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

// stringLiteral returns the unquoted contents of a basic string literal, such as a shell name or a panic message.
//
// expr qualifies only as a basic literal that strconv.Unquote accepts, so rune literals pass too while number literals do not.
// For any other expression the result is an empty string and false.
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
