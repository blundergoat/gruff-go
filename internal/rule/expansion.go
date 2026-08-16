// Package rule defines gruff-go's rule registry and analysers.
// This file implements package-name, dead-code, security, and test rules.
// Its findings explain code changes users can make before the next scan.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// skipDebtMarkers introduce work that should not stay hidden behind a test guard.
// Matching is case-insensitive and anchored by skipMessageLineIntroducesDebt.
var skipDebtMarkers = []string{"todo", "fixme", "xxx", "hack", "wip"}

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

// SkippedTestRule finds test skips that can hide unfinished coverage.
// Conditional environment guards stay quiet unless their message introduces debt.
// Users can remove the skip or track the condition outside the test body.
type SkippedTestRule struct{}

// Definition declares the test-quality.skipped-test rule that fires when t.Skip, t.Skipf, or t.SkipNow appears in any _test.go file.
func (SkippedTestRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.skipped-test",
		Title:          "Skipped test",
		Description:    "Flags Go tests that call t.Skip, t.Skipf, or t.SkipNow.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"tests"},
		Remediation:    "Remove the skip or document and track the condition outside the test body.",
		FalsePositiveShapes: []FalsePositiveShape{{
			Shape:      "A legitimate conditional skip reason whose first physical line begins with TODO/FIXME-style product terminology.",
			Mitigation: "Put explanatory words before the quoted marker, or disable the rule for that path when the external wording must stay first.",
		}},
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
	conditionalRegions := conditionalBodyRanges(unit.AST)
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		receivers := testingReceiverNames(fn, testingPackages)
		findings = append(findings, skippedTestFindingsInBlock(unit, fn.Body, testingPackages, receivers, conditionalRegions)...)
	}
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

// skipMessageMentionsDebt reports whether a literal skip message introduces debt.
// Prose mentions stay quiet; a marker may introduce any physical message line.
func skipMessageMentionsDebt(call *ast.CallExpr) bool {
	// Only literal text can provide reliable marker evidence to the user.
	for _, argument := range call.Args {
		messageText, isLiteral := stringLiteral(argument)
		// A dynamic message cannot prove that the checked-in test carries marker debt.
		if !isLiteral {
			continue
		}
		// Multiline reasons may introduce the actionable marker after explanatory text.
		for _, messageLine := range strings.Split(messageText, "\n") {
			// An introduced marker keeps the conditional skip visible in the report.
			if skipMessageLineIntroducesDebt(messageLine) {
				return true
			}
		}
	}
	return false
}

// skipMessageLineIntroducesDebt matches a leading marker after optional space or a list bullet.
// Delimiters distinguish real debt from prose names such as TODOs or todo-without-tracking.
func skipMessageLineIntroducesDebt(messageLine string) bool {
	messageBody := trimOptionalSkipMessageBullet(strings.TrimSpace(messageLine))
	lowerMessageBody := strings.ToLower(messageBody)
	// Check the shared vocabulary without treating a mid-sentence word as an introduced marker.
	for _, debtMarker := range skipDebtMarkers {
		markerSuffix, startsWithMarker := strings.CutPrefix(lowerMessageBody, debtMarker)
		// A different leading word means this marker is only prose, if it appears at all.
		if !startsWithMarker {
			continue
		}
		return hasSkipDebtMarkerDelimiter(markerSuffix)
	}
	return false
}

// trimOptionalSkipMessageBullet removes a conventional bullet before a marker.
// A hyphenated word without following space remains ordinary message text.
func trimOptionalSkipMessageBullet(messageBody string) string {
	// Empty and one-character messages cannot contain a bullet plus a marker.
	if len(messageBody) < 2 {
		return messageBody
	}
	// Only common list bullets opt into the marker position that follows.
	if !strings.ContainsRune("-*+", rune(messageBody[0])) {
		return messageBody
	}
	textAfterBullet := messageBody[1:]
	firstRune, _ := utf8.DecodeRuneInString(textAfterBullet)
	// `-TODO` is not a list item, so the leading hyphen remains meaningful text.
	if !unicode.IsSpace(firstRune) {
		return messageBody
	}
	return strings.TrimSpace(textAfterBullet)
}

// hasSkipDebtMarkerDelimiter accepts punctuation used by real leading markers.
// A hyphen counts only at the end or before space, keeping hyphenated names quiet.
func hasSkipDebtMarkerDelimiter(markerSuffix string) bool {
	// A bare marker is enough to tell the user the guarded test is deferred work.
	if markerSuffix == "" {
		return true
	}
	delimiter, delimiterWidth := utf8.DecodeRuneInString(markerSuffix)
	// Owners, labels, and space-continuation messages are conventional marker forms.
	if delimiter == ':' || delimiter == '(' || unicode.IsSpace(delimiter) {
		return true
	}
	// Other continuations, such as the `s` in TODOs, are ordinary words.
	if delimiter != '-' {
		return false
	}
	textAfterHyphen := markerSuffix[delimiterWidth:]
	// A terminal hyphen is an explicit marker delimiter rather than a word continuation.
	if textAfterHyphen == "" {
		return true
	}
	nextRune, _ := utf8.DecodeRuneInString(textAfterHyphen)
	return unicode.IsSpace(nextRune)
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
