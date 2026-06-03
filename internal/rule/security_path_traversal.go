// Package rule defines gruff-go's rule registry and analysers.
// This file implements a parser-only path-traversal check that traces
// request-controlled values into filesystem and file-serving sinks.
package rule

import (
	"go/ast"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// pathSanitizerWords name the same-function containment evidence that makes a
// request-controlled path safe: filepath.Clean/Rel/IsLocal/Base, a basename
// reduction, or a project containment helper. Each entry is matched at a call-name
// token boundary (see callNameMatchesAny), so "safe" matches safePath but not
// unsafePath.
var pathSanitizerWords = []string{"clean", "rel", "islocal", "base", "safe", "sanit", "within", "contain", "validate", "verif", "allow"}

// PathTraversalFileAccessRule flags request-derived values used as a filesystem
// path without nearby containment evidence.
type PathTraversalFileAccessRule struct{}

// Definition declares the security.path-traversal-file-access rule for bounded
// same-function path-traversal evidence.
func (PathTraversalFileAccessRule) Definition() Definition {
	return Definition{
		ID:             "security.path-traversal-file-access",
		Title:          "Path traversal in file access",
		Description:    "Flags request-derived values passed to filesystem or file-serving sinks without nearby filepath.Clean, Rel, IsLocal, basename, or containment evidence (possible path traversal). Uses bounded same-function evidence and candidate wording.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"filesystem", "security", "path-traversal"},
		Remediation:    "Constrain request-derived paths with filepath.Clean plus a containment check (filepath.Rel/IsLocal) or reduce them to a basename before opening files.",
	}
}

// AnalyzeUnit emits findings for request-controlled filesystem paths without containment.
func (PathTraversalFileAccessRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	httpPackages := packageImportNames(unit.AST, "net/http", "http")
	if len(httpPackages) == 0 {
		return nil
	}
	osPackages := packageImportNames(unit.AST, "os", "os")
	ioutilPackages := packageImportNames(unit.AST, "io/ioutil", "ioutil")
	findings := []finding.Finding{}
	forEachRequestFunc(unit.AST, httpPackages, func(scope *requestTaintScope, body *ast.BlockStmt) {
		ast.Inspect(body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			pathIndex, sink, ok := filePathSinkArg(call, osPackages, ioutilPackages, httpPackages)
			if !ok || pathIndex >= len(call.Args) {
				return true
			}
			pathArg := call.Args[pathIndex]
			source, ok := scope.exprHasRequest(pathArg, call.Pos())
			if !ok {
				return true
			}
			if scope.argHasInlineSanitizer(pathArg, pathSanitizerWords) || bodyHasSanitizingCall(body, scope.sanitizerValueNames(pathArg), pathSanitizerWords, call.Pos()) {
				return true
			}
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "request-controlled value used as filesystem path without containment check (possible path traversal)",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Metadata: map[string]any{"sink": sink, "source": source},
			})
			return true
		})
	})
	return findings
}

// filePathSinkArg reports the path argument index and sink label for filesystem
// and file-serving calls whose first (or ServeFile's third) argument is a path.
func filePathSinkArg(call *ast.CallExpr, osPackages, ioutilPackages, httpPackages map[string]bool) (int, string, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return 0, "", false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok {
		return 0, "", false
	}
	if osPackages[receiver.Name] && osFileSinkNames[selector.Sel.Name] {
		return 0, receiver.Name + "." + selector.Sel.Name, true
	}
	if ioutilPackages[receiver.Name] && ioutilFileSinkNames[selector.Sel.Name] {
		return 0, receiver.Name + "." + selector.Sel.Name, true
	}
	if httpPackages[receiver.Name] && selector.Sel.Name == "ServeFile" {
		return 2, receiver.Name + ".ServeFile", true
	}
	return 0, "", false
}

// osFileSinkNames are os package functions whose first argument is a filesystem
// path that path traversal can abuse.
var osFileSinkNames = map[string]bool{
	"Open": true, "OpenFile": true, "ReadFile": true, "Create": true,
	"WriteFile": true, "Stat": true, "Lstat": true, "Remove": true,
	"RemoveAll": true, "Mkdir": true, "MkdirAll": true, "ReadDir": true,
	"Truncate": true, "Readlink": true,
}

// ioutilFileSinkNames are io/ioutil functions whose first argument is a path.
var ioutilFileSinkNames = map[string]bool{
	"ReadFile": true, "WriteFile": true, "ReadDir": true,
}
