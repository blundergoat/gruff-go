// Package rule defines gruff-go's rule registry and analysers.
// This file implements additional parser-only maintainability checks.
package rule

import (
	"fmt"
	"go/ast"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// DeferInLoopRule flags defer statements directly inside loop bodies.
type DeferInLoopRule struct{}

// Definition declares the maintainability.defer-in-loop rule for delayed loop cleanup.
func (DeferInLoopRule) Definition() Definition {
	return Definition{
		ID:             "maintainability.defer-in-loop",
		Title:          "Defer in loop",
		Description:    "Flags defer statements directly inside loops, where cleanup is delayed until the enclosing function returns.",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"lifecycle"},
		Remediation:    "Move the loop body into a helper function or close the resource explicitly before the next iteration.",
	}
}

// AnalyzeUnit emits findings for defers inside the lexical loop body of one function.
func (DeferInLoopRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || hasGeneratedHeader(unit.Source) {
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

// LogFatalLibraryRule flags process termination from reusable library code.
type LogFatalLibraryRule struct{}

// Definition declares the maintainability.log-fatal-library rule for process exits outside commands.
func (LogFatalLibraryRule) Definition() Definition {
	return Definition{
		ID:             "maintainability.log-fatal-library",
		Title:          "Library fatal exit",
		Description:    "Flags log.Fatal and os.Exit calls outside command entrypoints and tests.",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"errors", "lifecycle"},
		Remediation:    "Return an error to the caller and let command/bootstrap code decide whether to terminate the process.",
	}
}

// AnalyzeUnit emits findings for direct log.Fatal* and os.Exit calls in reusable production code.
func (LogFatalLibraryRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) || unit.AST.Name.Name == "main" || isBootstrapPath(unit.File.Path) || hasGeneratedHeader(unit.Source) {
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

// LoopVariableAddressRule flags addresses of range variable copies that escape the iteration.
type LoopVariableAddressRule struct{}

// Definition declares the maintainability.loop-variable-address rule for range-copy pointer hazards.
func (LoopVariableAddressRule) Definition() Definition {
	return Definition{
		ID:             "maintainability.loop-variable-address",
		Title:          "Range variable address escapes",
		Description:    "Flags storing, returning, or appending the address of a range variable copy.",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"loops"},
		Remediation:    "Take the address of the indexed collection element, or copy the value into a deliberately scoped variable before storing its address.",
	}
}

// AnalyzeUnit emits findings when a range variable address is stored beyond the iteration.
func (LoopVariableAddressRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || hasGeneratedHeader(unit.Source) {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		findings = append(findings, loopVariableAddressBlock(unit, fn.Body, functionName(fn))...)
	}
	return findings
}

// deferInLoopBlock walks one function body while intentionally treating function literals as a new defer scope.
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

// deferInLoopCaseClauses walks switch case bodies for defer-in-loop findings.
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
func deferInLoopStmtList(unit parser.Unit, stmts []ast.Stmt, symbol string, loopDepth int) []finding.Finding {
	return deferInLoopBlock(unit, &ast.BlockStmt{List: stmts}, symbol, loopDepth)
}

// fatalLibraryCallName returns the rendered fatal call when it is a direct standard-library process exit.
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

// loopVariableAddressBlock walks one function body looking for escaping addresses inside range loops.
func loopVariableAddressBlock(unit parser.Unit, body *ast.BlockStmt, symbol string) []finding.Finding {
	findings := []finding.Finding{}
	ast.Inspect(body, func(node ast.Node) bool {
		rangeStmt, ok := node.(*ast.RangeStmt)
		if !ok {
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

// rangeVariableAddressFindings emits findings for range variable addresses in known escaping contexts.
func rangeVariableAddressFindings(unit parser.Unit, body *ast.BlockStmt, symbol string, rangeVars map[string]bool) []finding.Finding {
	findings := []finding.Finding{}
	ast.Inspect(body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.FuncLit:
			return false
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

// assignmentStoresAddress reports whether lhs stores a pointer into an existing aggregate or dereferenced target.
func assignmentStoresAddress(lhs ast.Expr) bool {
	switch lhs.(type) {
	case *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr:
		return true
	default:
		return false
	}
}

// addressOfRangeVariable reports whether expr is &<range-variable>.
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

// isBuiltinAppendCall reports whether call invokes the predeclared append function.
func isBuiltinAppendCall(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "append"
}

// loopVariableAddressFinding builds a finding for an escaping range variable address.
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
