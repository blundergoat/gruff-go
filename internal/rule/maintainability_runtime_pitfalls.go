// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds more parser-only maintainability checks: defer in loops, library fatal exits and range variable addresses that may escape.
// Each check reads syntax only, so a finding marks a likely hazard rather than a proven one.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// DeferInLoopRule flags defer statements directly inside loop bodies, as rule maintainability.defer-in-loop.
//
// A deferred call runs only when the enclosing function returns, so defer f.Close() in a loop keeps every file open until then.
type DeferInLoopRule struct{}

// Definition declares the maintainability.defer-in-loop rule for delayed loop cleanup.
// It returns the same populated Definition on every call: maintainability pillar, advisory severity, high confidence, enabled by default.
func (DeferInLoopRule) Definition() Definition {
	return Definition{
		ID:             "maintainability.defer-in-loop",
		Title:          "Defer in loop",
		Description:    "Flags defer statements directly inside loops, where cleanup is delayed until the enclosing function returns.",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"lifecycle"},
		Remediation:    "Move the loop body into a helper function or close the resource explicitly before the next iteration.",
	}
}

// AnalyzeUnit emits findings for defers inside the lexical loop bodies of each function and method declaration in one parsed file.
//
// unit is that file; ctx goes to shouldSkipGeneratedUnit, which can skip the whole unit.
// It returns one finding per defer reached inside a for or range loop, and nil when the unit is skipped or lacks an AST or FileSet.
func (DeferInLoopRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || shouldSkipGeneratedUnit(unit, ctx) {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		findings = append(findings, deferInLoopBlock(unit, fn.Body, functionName(fn), 0)...)
	}
	return findings
}

// LogFatalLibraryRule flags process termination from reusable library code, as rule maintainability.log-fatal-library.
//
// It reports log.Fatal, log.Fatalf, log.Fatalln and os.Exit calls; cmd paths, main packages, tests, testdata and example paths are exempt.
type LogFatalLibraryRule struct{}

// Definition declares the maintainability.log-fatal-library rule for process exits outside commands.
// It returns the same populated Definition on every call: maintainability pillar, advisory severity, high confidence, enabled by default.
func (LogFatalLibraryRule) Definition() Definition {
	return Definition{
		ID:             "maintainability.log-fatal-library",
		Title:          "Library fatal exit",
		Description:    "Flags log.Fatal and os.Exit calls outside command entrypoints and tests.",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"errors", "lifecycle"},
		Remediation:    "Return an error to the caller and let command/bootstrap code decide whether to terminate the process.",
	}
}

// AnalyzeUnit emits findings for direct log.Fatal* and os.Exit calls in reusable production code.
//
// unit is skipped as a test, testdata, example, main-package or cmd file; ctx goes to shouldSkipGeneratedUnit, which can skip it too.
// It returns one finding per call with the enclosing function and rendered callee, and nil when skipped or neither log nor os is imported.
func (LogFatalLibraryRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) || unit.AST.Name.Name == "main" || isBootstrapPath(unit.File.Path) || shouldSkipGeneratedUnit(unit, ctx) {
		return nil
	}
	logPackages := packageImportNames(unit.AST, "log", "log")
	osPackages := packageImportNames(unit.AST, "os", "os")
	if len(logPackages) == 0 && len(osPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := fatalLibraryCallName(call, logPackages, osPackages)
			if !ok {
				return true
			}
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "library code terminates the process instead of returning an error",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   functionName(fn),
				Metadata: map[string]any{"call": name},
			})
			return true
		})
	}
	return findings
}

// LoopVariableAddressRule flags the address of a range variable taken where it may outlive the iteration.
//
// It checks = range loops always, and := range loops only when the module language version still gives them one shared variable.
// Matching is syntactic: a return, field, index or dereference store, send, or append argument counts without proof that the pointer escapes.
type LoopVariableAddressRule struct{}

// Definition declares the maintainability.loop-variable-address rule for range-copy pointer hazards.
// It returns the same populated Definition on every call: maintainability pillar, advisory severity, medium confidence, enabled by default.
func (LoopVariableAddressRule) Definition() Definition {
	return Definition{
		ID:             "maintainability.loop-variable-address",
		Title:          "Range variable address escapes",
		Description:    "Flags storing, returning, or appending the address of a range variable copy.",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"loops"},
		Remediation:    "Take the address of the indexed collection element, or copy the value into a deliberately scoped variable before storing its address.",
	}
}

// AnalyzeUnit emits findings when a range variable address appears in a shape that can keep it beyond the iteration.
//
// unit is one parsed file whose top-level function bodies are walked; ctx feeds shouldSkipGeneratedUnit and usesLegacyRangeLoopVariables.
// It returns one finding per matched shape in a checked range loop, and nil when the unit is skipped or lacks an AST or FileSet.
//
// Range loops declared with := are checked only when usesLegacyRangeLoopVariables says they share one variable; = range loops always are.
// Shapes match by syntax alone: assigning to a plain local variable is not one, and a matched store is not proven to outlive the iteration.
// A zero-argument call named append in a checked loop body, such as a shadowing local function, panics with slice bounds out of range.
func (LoopVariableAddressRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || shouldSkipGeneratedUnit(unit, ctx) {
		return nil
	}
	legacyDeclarationSemantics := usesLegacyRangeLoopVariables(unit, ctx)
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		findings = append(findings, loopVariableAddressBlock(unit, fn.Body, functionName(fn), legacyDeclarationSemantics)...)
	}
	return findings
}

// deferInLoopBlock walks one function body while intentionally treating function literals as a new defer scope.
//
// unit supplies the path and positions, symbol names the enclosing function, and loopDepth counts the for and range loops around block.
// It returns one finding per defer met at a positive loopDepth, recursing one level deeper into loop bodies; a nil block gives nil.
//
// If, else, switch, type-switch and select bodies keep the same depth.
// Function literals, labeled statements, bare blocks and else-if branches are not entered, so defers reached only through them go unreported.
func deferInLoopBlock(unit parser.Unit, block *ast.BlockStmt, symbol string, loopDepth int) []finding.Finding {
	if block == nil {
		return nil
	}
	findings := []finding.Finding{}
	for _, stmt := range block.List {
		switch value := stmt.(type) {
		case *ast.DeferStmt:
			if loopDepth > 0 {
				position := unit.FileSet.Position(value.Defer)
				findings = append(findings, finding.Finding{
					Message:  "defer inside loop delays cleanup until function return",
					File:     unit.File.Path,
					Location: &finding.Location{Line: position.Line, Column: position.Column},
					Symbol:   symbol,
				})
			}
		case *ast.ForStmt:
			findings = append(findings, deferInLoopBlock(unit, value.Body, symbol, loopDepth+1)...)
		case *ast.RangeStmt:
			findings = append(findings, deferInLoopBlock(unit, value.Body, symbol, loopDepth+1)...)
		case *ast.IfStmt:
			findings = append(findings, deferInLoopBlock(unit, value.Body, symbol, loopDepth)...)
			if elseBlock, ok := value.Else.(*ast.BlockStmt); ok {
				findings = append(findings, deferInLoopBlock(unit, elseBlock, symbol, loopDepth)...)
			}
		case *ast.SwitchStmt:
			findings = append(findings, deferInLoopCaseClauses(unit, value.Body, symbol, loopDepth)...)
		case *ast.TypeSwitchStmt:
			findings = append(findings, deferInLoopCaseClauses(unit, value.Body, symbol, loopDepth)...)
		case *ast.SelectStmt:
			findings = append(findings, deferInLoopCommClauses(unit, value.Body, symbol, loopDepth)...)
		}
	}
	return findings
}

// deferInLoopCaseClauses walks switch and type-switch case bodies for defer-in-loop findings.
//
// body is the switch or type-switch body whose case clauses are walked at loopDepth, with unit and symbol passed through for each finding.
// It returns the findings from every clause, nil when body is nil, and an empty slice when no clause holds a reported defer.
func deferInLoopCaseClauses(unit parser.Unit, body *ast.BlockStmt, symbol string, loopDepth int) []finding.Finding {
	if body == nil {
		return nil
	}
	findings := []finding.Finding{}
	for _, stmt := range body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		findings = append(findings, deferInLoopStmtList(unit, clause.Body, symbol, loopDepth)...)
	}
	return findings
}

// deferInLoopCommClauses walks select case bodies for defer-in-loop findings.
//
// body is the select body whose comm clauses are walked at loopDepth, with unit and symbol passed through for each finding.
// It returns the findings from every clause, nil when body is nil, and an empty slice when no clause holds a reported defer.
func deferInLoopCommClauses(unit parser.Unit, body *ast.BlockStmt, symbol string, loopDepth int) []finding.Finding {
	if body == nil {
		return nil
	}
	findings := []finding.Finding{}
	for _, stmt := range body.List {
		clause, ok := stmt.(*ast.CommClause)
		if !ok {
			continue
		}
		findings = append(findings, deferInLoopStmtList(unit, clause.Body, symbol, loopDepth)...)
	}
	return findings
}

// deferInLoopStmtList wraps a statement list as a block for recursive traversal.
//
// stmts is a clause body walked as a block at loopDepth, with unit and symbol passed through for each finding.
// It returns the findings deferInLoopBlock gives for that block, never nil and empty when stmts holds no reported defer.
func deferInLoopStmtList(unit parser.Unit, stmts []ast.Stmt, symbol string, loopDepth int) []finding.Finding {
	return deferInLoopBlock(unit, &ast.BlockStmt{List: stmts}, symbol, loopDepth)
}

// fatalLibraryCallName returns the rendered fatal call when it is a direct standard-library process exit.
//
// logPackages and osPackages hold the import names of log and os; call must be Exit on an os name or Fatal, Fatalf or Fatalln on a log name.
// Any other call gives an empty string and false.
func fatalLibraryCallName(call *ast.CallExpr, logPackages, osPackages map[string]bool) (string, bool) {
	if selectorCallMatches(call, osPackages, "Exit") {
		return formatExpr(call.Fun), true
	}
	for _, name := range []string{"Fatal", "Fatalf", "Fatalln"} {
		if selectorCallMatches(call, logPackages, name) {
			return formatExpr(call.Fun), true
		}
	}
	return "", false
}

// loopVariableAddressBlock walks one function body for range variable addresses, applying the language-version gate only to := range loops.
//
// legacyDeclarationSemantics says whether := range loops still share one variable across iterations; when false, those loops are skipped.
// Range loops that assign existing variables with = are always checked, and range loops without variables are skipped.
//
// unit and symbol go into each finding; it returns the findings of every checked range loop in body, nested ones included, or an empty slice.
// A zero-argument call named append in a checked loop body, such as a shadowing local function, panics with slice bounds out of range.
func loopVariableAddressBlock(unit parser.Unit, body *ast.BlockStmt, symbol string, legacyDeclarationSemantics bool) []finding.Finding {
	findings := []finding.Finding{}
	ast.Inspect(body, func(node ast.Node) bool {
		rangeStmt, ok := node.(*ast.RangeStmt)
		if !ok {
			return true
		}
		if rangeStmt.Tok == token.DEFINE && !legacyDeclarationSemantics {
			return true
		}
		rangeVars := rangeVariableNames(rangeStmt)
		if len(rangeVars) == 0 {
			return true
		}
		findings = append(findings, rangeVariableAddressFindings(unit, rangeStmt.Body, symbol, rangeVars)...)
		return true
	})
	return findings
}

// rangeVariableAddressFindings emits findings for range variable addresses in shapes that can let them outlive the iteration.
//
// body is one range loop body and rangeVars its variable names; unit and symbol go into each finding.
// It returns one finding per bare &name of a range variable that is returned, stored into a field, index or dereference, sent, or appended.
//
// Matching is by syntax alone: a parenthesized address is missed, append means any call by that name, and a store is not proven to escape.
// Nested function literals and range loops are not entered, and the result is an empty slice when nothing matches.
// A zero-argument call named append, such as a shadowing local function, panics with slice bounds out of range.
func rangeVariableAddressFindings(unit parser.Unit, body *ast.BlockStmt, symbol string, rangeVars map[string]bool) []finding.Finding {
	findings := []finding.Finding{}
	ast.Inspect(body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.FuncLit:
			return false
		// An outer loop variable's address taken inside an inner range loop is missed: the inner loop's own pass checks only its own variables.
		case *ast.RangeStmt:
			return false
		case *ast.ReturnStmt:
			for _, result := range value.Results {
				if name, ok := addressOfRangeVariable(result, rangeVars); ok {
					findings = append(findings, loopVariableAddressFinding(unit, result, symbol, name, "return"))
				}
			}
		case *ast.AssignStmt:
			for index, rhs := range value.Rhs {
				if index >= len(value.Lhs) || !assignmentStoresAddress(value.Lhs[index]) {
					continue
				}
				if name, ok := addressOfRangeVariable(rhs, rangeVars); ok {
					findings = append(findings, loopVariableAddressFinding(unit, rhs, symbol, name, "store"))
				}
			}
		case *ast.SendStmt:
			if name, ok := addressOfRangeVariable(value.Value, rangeVars); ok {
				findings = append(findings, loopVariableAddressFinding(unit, value.Value, symbol, name, "send"))
			}
		case *ast.CallExpr:
			if !isBuiltinAppendCall(value) {
				return true
			}
			// A zero-argument call named append, such as a shadowing local function, panics here with slice bounds out of range.
			for _, arg := range value.Args[1:] {
				if name, ok := addressOfRangeVariable(arg, rangeVars); ok {
					findings = append(findings, loopVariableAddressFinding(unit, arg, symbol, name, "append"))
				}
			}
		}
		return true
	})
	return findings
}

// assignmentStoresAddress reports whether lhs is a field, index or dereference target, the assignment shapes the rule treats as a store.
// Target lifetime is not checked, so a field of a holder declared inside the loop body still counts as a store.
func assignmentStoresAddress(lhs ast.Expr) bool {
	switch lhs.(type) {
	case *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr:
		return true
	default:
		return false
	}
}

// addressOfRangeVariable reports whether expr is &<range-variable>.
// rangeVars holds the loop's variable names; on a match it gives the variable name and true, otherwise an empty string and false.
func addressOfRangeVariable(expr ast.Expr, rangeVars map[string]bool) (string, bool) {
	unary, ok := expr.(*ast.UnaryExpr)
	if !ok || unary.Op.String() != "&" {
		return "", false
	}
	ident, ok := unary.X.(*ast.Ident)
	if !ok || !rangeVars[ident.Name] {
		return "", false
	}
	return ident.Name, true
}

// isBuiltinAppendCall reports whether call has the unqualified callee name append, without resolving shadowing.
// A local function named append matches too, which is how a zero-argument call reaches the panic in rangeVariableAddressFindings.
func isBuiltinAppendCall(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "append"
}

// loopVariableAddressFinding builds the finding for one matched range variable address.
//
// It returns a finding located at expr in the file of unit, with symbol as its enclosing function; the value is always populated.
// variable names the range variable in the message and metadata, and context labels the matched syntax: return, store, send or append.
func loopVariableAddressFinding(unit parser.Unit, expr ast.Expr, symbol string, variable string, context string) finding.Finding {
	position := unit.FileSet.Position(expr.Pos())
	return finding.Finding{
		Message:  fmt.Sprintf("range variable %q address escapes the iteration", variable),
		File:     unit.File.Path,
		Location: &finding.Location{Line: position.Line, Column: position.Column},
		Symbol:   symbol,
		Metadata: map[string]any{
			"variable": variable,
			"context":  context,
		},
	}
}
