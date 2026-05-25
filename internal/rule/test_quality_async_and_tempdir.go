// Package rule defines gruff-go's rule registry and analysers.
// This file implements additional parser-only test-quality checks.
package rule

import (
	"go/ast"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// FatalInGoroutineRule flags testing fatal control-flow calls inside goroutines.
type FatalInGoroutineRule struct{}

// Definition declares the test-quality.fatal-in-goroutine rule for unsafe test failure flow.
func (FatalInGoroutineRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.fatal-in-goroutine",
		Title:          "Fatal call in goroutine",
		Description:    "Flags t.Fatal, t.Fatalf, and t.FailNow calls inside goroutines where they do not stop the parent test safely.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"tests"},
		Remediation:    "Report the error back to the parent goroutine and fail the test from the parent with t.Fatal or t.Fatalf.",
	}
}

// AnalyzeUnit emits findings for fatal testing calls inside go func bodies.
func (FatalInGoroutineRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") || hasGeneratedHeader(unit.Source) {
		return nil
	}
	testingPackages := testingPackageNames(unit.AST)
	if len(testingPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		receivers := testingReceiverNames(fn, testingPackages)
		if len(receivers) == 0 {
			continue
		}
		findings = append(findings, fatalInGoroutineFindings(unit, fn.Body, functionName(fn), testingPackages, receivers)...)
	}
	return findings
}

// TempDirMisuseRule flags os.MkdirTemp("", ...) in tests that can use t.TempDir.
type TempDirMisuseRule struct{}

// Definition declares the test-quality.tempdir-misuse rule for per-test temporary directories.
func (TempDirMisuseRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.tempdir-misuse",
		Title:          "Test temp dir misuse",
		Description:    "Flags os.MkdirTemp and ioutil.TempDir calls in tests when t.TempDir is available.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"tests"},
		Remediation:    "Use t.TempDir() for per-test isolation and automatic cleanup.",
	}
}

// AnalyzeUnit emits findings for empty-parent temporary directories inside test scopes.
func (TempDirMisuseRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") || hasGeneratedHeader(unit.Source) {
		return nil
	}
	testingPackages := testingPackageNames(unit.AST)
	if len(testingPackages) == 0 {
		return nil
	}
	packages := tempDirPackages{
		os:     packageImportNames(unit.AST, "os", "os"),
		ioutil: packageImportNames(unit.AST, "io/ioutil", "ioutil"),
	}
	if len(packages.os) == 0 && len(packages.ioutil) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		receivers := testingHandlesForFunc(fn, testingPackages)
		if len(receivers) == 0 {
			continue
		}
		scan := tempDirScan{
			unit:            unit,
			symbol:          functionName(fn),
			testingPackages: testingPackages,
			packages:        packages,
		}
		findings = append(findings, tempDirMisuseFindings(scan, fn.Body, receivers)...)
	}
	return findings
}

// tempDirPackages groups import aliases for temporary-directory helpers.
type tempDirPackages struct {
	os     map[string]bool
	ioutil map[string]bool
}

// tempDirScan carries stable context while recursing through nested test scopes.
type tempDirScan struct {
	unit            parser.Unit
	symbol          string
	testingPackages map[string]bool
	packages        tempDirPackages
}

// fatalInGoroutineFindings walks one test function for go func bodies that call fatal testing methods.
func fatalInGoroutineFindings(unit parser.Unit, body *ast.BlockStmt, symbol string, testingPackages map[string]bool, receivers map[string]bool) []finding.Finding {
	findings := []finding.Finding{}
	ast.Inspect(body, func(node ast.Node) bool {
		if funcLit, ok := node.(*ast.FuncLit); ok && funcLit.Body != body {
			scoped := scopedReceiversForFuncType(receivers, funcLit.Type, testingPackages)
			findings = append(findings, fatalInGoroutineFindings(unit, funcLit.Body, symbol, testingPackages, scoped)...)
			return false
		}
		goStmt, ok := node.(*ast.GoStmt)
		if !ok || goStmt.Call == nil {
			return true
		}
		lit, ok := goStmt.Call.Fun.(*ast.FuncLit)
		if !ok || lit.Body == nil {
			return true
		}
		scoped := scopedReceiversForFuncType(receivers, lit.Type, testingPackages)
		if call := firstFatalControlCall(lit.Body, scoped); call != nil {
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "testing fatal call runs inside a goroutine",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   symbol,
				Metadata: map[string]any{"call": formatExpr(call.Fun)},
			})
		}
		return true
	})
	return findings
}

// firstFatalControlCall returns the first t.Fatal/Fatalf/FailNow call in body.
func firstFatalControlCall(body *ast.BlockStmt, receivers map[string]bool) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(body, func(node ast.Node) bool {
		if found != nil {
			return false
		}
		if funcLit, ok := node.(*ast.FuncLit); ok && funcLit.Body != body {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isFatalControlCall(call, receivers) {
			found = call
			return false
		}
		return true
	})
	return found
}

// isFatalControlCall reports whether call stops test execution on a known testing receiver.
func isFatalControlCall(call *ast.CallExpr, receivers map[string]bool) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !receivers[receiver.Name] {
		return false
	}
	switch selector.Sel.Name {
	case "Fatal", "Fatalf", "FailNow":
		return true
	default:
		return false
	}
}

// testingHandlesForFunc returns testing handles that can provide TempDir.
func testingHandlesForFunc(fn *ast.FuncDecl, testingPackages map[string]bool) map[string]bool {
	receivers := testingReceiverNames(fn, testingPackages)
	for name := range testingHelperReceiverNames(fn, testingPackages) {
		receivers[name] = true
	}
	return receivers
}

// tempDirMisuseFindings walks one test function for empty-parent temporary directories.
func tempDirMisuseFindings(scan tempDirScan, body *ast.BlockStmt, receivers map[string]bool) []finding.Finding {
	findings := []finding.Finding{}
	ast.Inspect(body, func(node ast.Node) bool {
		if funcLit, ok := node.(*ast.FuncLit); ok && funcLit.Body != body {
			scoped := scopedTestingHandlesForFuncType(receivers, funcLit.Type, scan.testingPackages)
			findings = append(findings, tempDirMisuseFindings(scan, funcLit.Body, scoped)...)
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok || len(receivers) == 0 {
			return true
		}
		name, ok := emptyParentTempDirCall(call, scan.packages)
		if !ok {
			return true
		}
		position := scan.unit.FileSet.Position(call.Pos())
		findings = append(findings, finding.Finding{
			Message:  "test creates a temp directory without t.TempDir cleanup",
			File:     scan.unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Symbol:   scan.symbol,
			Metadata: map[string]any{"call": name},
		})
		return true
	})
	return findings
}

// scopedTestingHandlesForFuncType applies nested function parameters to inherited testing handles.
func scopedTestingHandlesForFuncType(parent map[string]bool, fnType *ast.FuncType, testingPackages map[string]bool) map[string]bool {
	scoped := copyReceiverNames(parent)
	if fnType == nil || fnType.Params == nil {
		return scoped
	}
	for _, field := range fnType.Params.List {
		if isTestingHelperReceiverType(field.Type, testingPackages) {
			addTestingFieldNames(field, scoped)
			continue
		}
		removeFieldNames(field, scoped)
	}
	return scoped
}

// emptyParentTempDirCall reports os.MkdirTemp("", ...) or ioutil.TempDir("", ...).
func emptyParentTempDirCall(call *ast.CallExpr, packages tempDirPackages) (string, bool) {
	if len(call.Args) < 1 || !isEmptyStringExpr(call.Args[0]) {
		return "", false
	}
	switch {
	case selectorCallMatches(call, packages.os, "MkdirTemp"):
		return "os.MkdirTemp", true
	case selectorCallMatches(call, packages.ioutil, "TempDir"):
		return "ioutil.TempDir", true
	default:
		return "", false
	}
}

// isEmptyStringExpr reports whether expr is the literal empty string.
func isEmptyStringExpr(expr ast.Expr) bool {
	value, ok := stringLiteral(expr)
	return ok && value == ""
}
