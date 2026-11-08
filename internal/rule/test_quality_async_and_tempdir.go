// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds two parser-only test-quality checks for _test.go files: test-quality.fatal-in-goroutine and test-quality.tempdir-misuse.
// They flag fatal testing calls made inside goroutines and temporary directories created without t.TempDir.
package rule

import (
	"go/ast"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// FatalInGoroutineRule flags t.Fatal, t.Fatalf and t.FailNow called inside a goroutine that a test starts.
//
// These calls exit only the goroutine that makes them, so the test function keeps running past the failure.
// Only go statements that start a function literal are checked, so go helper(t) is not followed into helper.
type FatalInGoroutineRule struct{}

// Definition declares the test-quality.fatal-in-goroutine rule for unsafe test failure flow.
// It returns the same fixed metadata on every call: an advisory, high-confidence, default-enabled test-quality rule with its remediation text.
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

// AnalyzeUnit flags fatal testing calls inside go func literals in one parsed test file.
//
// unit must be a parsed _test.go file importing testing, and ctx is consulted to skip generated units; any other unit gives nil.
// It returns findings from top-level functions with *testing.T, *testing.B or *testing.F parameters, or an empty slice when none fire.
// A helper that takes only testing.TB is not checked here, unlike in test-quality.tempdir-misuse.
func (FatalInGoroutineRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") || shouldSkipGeneratedUnit(unit, ctx) {
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

// TempDirMisuseRule flags os.MkdirTemp("", ...) and ioutil.TempDir("", ...) in tests that could use t.TempDir instead.
//
// t.TempDir removes the directory when the test ends; these calls leave cleanup to the test, so a missed RemoveAll leaves files behind.
// Only a literal empty parent argument is flagged, so a call given a directory or a variable is left alone.
type TempDirMisuseRule struct{}

// Definition declares the test-quality.tempdir-misuse rule for per-test temporary directories.
// It returns the same fixed metadata on every call: an advisory, high-confidence, default-enabled test-quality rule with its remediation text.
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

// AnalyzeUnit flags empty-parent temporary directories created inside the test functions of one parsed test file.
//
// unit must be a parsed _test.go file that imports testing and os or io/ioutil, and ctx is consulted to skip generated units.
// It returns findings from top-level functions with a *testing.T, *testing.B, *testing.F or testing.TB parameter.
// The result is nil when unit is out of scope and an empty slice when no call fires.
func (TempDirMisuseRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") || shouldSkipGeneratedUnit(unit, ctx) {
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
//
// unit supplies the file path and positions, body is the block to walk, and symbol is the top-level function name recorded on each finding.
// receivers names the testing handles in scope; each nested function literal is walked recursively with handles rescoped using testingPackages.
// It returns one finding per go statement whose literal body makes a fatal call on an in-scope handle, or an empty slice when none do.
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
		// Only the first fatal call in each goroutine is reported, so fixing it can reveal another on the next run.
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
//
// receivers names the testing handles the call must be made on, and nested function literals inside body are not searched.
// The result is nil when no such call is found.
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

// isFatalControlCall reports whether call ends the calling goroutine through a known testing handle.
// receivers names the known testing handles, and the call must be Fatal, Fatalf or FailNow selected directly on one of them.
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
//
// fn is the function inspected and testingPackages the local testing import names; the result merges its testing and testing-helper handle names.
// The map has no entries when fn has no such handle.
func testingHandlesForFunc(fn *ast.FuncDecl, testingPackages map[string]bool) map[string]bool {
	receivers := testingReceiverNames(fn, testingPackages)
	for name := range testingHelperReceiverNames(fn, testingPackages) {
		receivers[name] = true
	}
	return receivers
}

// tempDirMisuseFindings walks one test function for empty-parent temporary directories.
//
// scan carries the unit, symbol, testing import names and temp-dir package aliases, and body is the block to walk.
// receivers names the testing handles in scope and is rescoped for each nested function literal, which is walked recursively.
// It returns one finding per empty-parent temp-dir call made while a handle is in scope, or an empty slice when none are found.
func tempDirMisuseFindings(scan tempDirScan, body *ast.BlockStmt, receivers map[string]bool) []finding.Finding {
	findings := []finding.Finding{}
	ast.Inspect(body, func(node ast.Node) bool {
		if funcLit, ok := node.(*ast.FuncLit); ok && funcLit.Body != body {
			scoped := scopedTestingHandlesForFuncType(receivers, funcLit.Type, scan.testingPackages)
			findings = append(findings, tempDirMisuseFindings(scan, funcLit.Body, scoped)...)
			return false
		}
		call, ok := node.(*ast.CallExpr)
		// If a closure's parameters hide every inherited handle and add no testing handle, its temp-dir calls are not flagged.
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
//
// parent holds the inherited handle names and is copied rather than changed, and fnType is the nested function literal's signature.
// A parameter typed as a testing handle under testingPackages is added, and any other parameter removes a handle of the same name.
// It returns the updated copy, an unchanged copy of parent when fnType is nil or has no parameters; it is empty when no handle survives.
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
//
// call is the call expression to check and packages holds the os and io/ioutil import aliases; the first argument must be the literal empty string.
// The result is the matched helper name, os.MkdirTemp or ioutil.TempDir, with true, or an empty name and false otherwise.
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
