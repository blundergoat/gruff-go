// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements a parser-only path-traversal check that traces request-controlled values into filesystem and file-serving sinks.
// A handler that hands r.FormValue output to os.Open or http.ServeFile with no containment check gets an advisory finding at that call.
package rule

import (
	"go/ast"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// pathSanitizerWords lists call-name stems treated as same-function containment evidence for suppressing path findings.
//
// Only the call name is checked, not what the helper does, so a safePath helper that returns its input unchanged still hides the finding.
// The stems cover filepath.Rel, IsLocal and Base, basename reductions, and project containment or validation helpers.
//
// filepath.Clean is intentionally excluded: normalising a path does not prove it stayed under the intended base directory.
// Each entry is matched at a call-name token boundary (see callNameMatchesAny), so "safe" matches safePath but not unsafePath.
var pathSanitizerWords = []string{"rel", "islocal", "base", "safe", "sanit", "within", "contain", "validate", "verif", "allow"}

// PathTraversalFileAccessRule flags request-derived values used as a filesystem path without nearby containment evidence.
//
// It only looks inside request functions in files that import net/http, and skips files outside production code paths.
// Evidence is a call whose name matches pathSanitizerWords, so each finding is a candidate for review, not proof of traversal.
type PathTraversalFileAccessRule struct{}

// Definition declares the security.path-traversal-file-access rule for bounded same-function path-traversal evidence.
//
// It returns a fixed Definition with advisory severity, medium confidence and DefaultEnabled true; it sets no Options.
func (PathTraversalFileAccessRule) Definition() Definition {
	return Definition{
		ID:             "security.path-traversal-file-access",
		Title:          "Path traversal in file access",
		Description:    "Flags request-derived values passed to filesystem or file-serving sinks without nearby filepath.Rel, IsLocal, basename, or containment evidence (possible path traversal). Uses bounded same-function evidence and candidate wording.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"filesystem", "security", "path-traversal"},
		Remediation:    "Constrain request-derived paths with filepath.Clean plus a containment check (filepath.Rel/IsLocal) or reduce them to a basename before opening files.",
	}
}

// AnalyzeUnit emits findings for request-controlled filesystem paths without containment.
//
// Inside each request function body in unit it flags sink calls whose path argument carries request data and lacks sanitizer evidence.
// It returns one finding per flagged call with sink and source metadata, and an empty slice when no call is flagged.
// It returns nil for a non-production path, a unit without AST or file set, or a file that imports net/http only as dot or blank, or not at all.
//
// It can panic during sanitizer checks when a Unicode call name's lowercase form is shorter than an original token offset.
func (PathTraversalFileAccessRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	httpPackages := packageImportNames(unit.AST, "net/http", "http")
	// Files that do not import net/http under a usable name are skipped, so a helper file that only receives a path string is never checked.
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
			// A sink call missing its path argument, such as os.Open() with no argument, is skipped so the scan does not read past the argument list.
			if !ok || pathIndex >= len(call.Args) {
				return true
			}
			pathArg := call.Args[pathIndex]
			source, ok := scope.exprHasRequest(pathArg, call.Pos())
			if !ok {
				return true
			}
			// A sanitizer-named call on the path, inline or earlier in this body, suppresses the finding even if the helper checks nothing.
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

// filePathSinkArg reports the path argument index and sink label for a filesystem or file-serving call.
//
// The index is 0 for the os and io/ioutil sinks and 2 for ServeFile, whose third argument is the path.
// The maps osPackages, ioutilPackages and httpPackages hold the names under which the file imports os, io/ioutil and net/http.
// The sink label joins that import name and the function name with a dot; any other call gives 0, an empty label and false.
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

// osFileSinkNames are os package functions whose first argument is a filesystem path that path traversal can abuse.
//
// A request-controlled first argument to any of them, such as os.Remove or os.MkdirAll, raises a finding without containment evidence.
// Other os calls that take paths, such as Rename, Chmod or Symlink, are not listed, so this rule never flags them.
var osFileSinkNames = map[string]bool{
	"Open": true, "OpenFile": true, "ReadFile": true, "Create": true,
	"WriteFile": true, "Stat": true, "Lstat": true, "Remove": true,
	"RemoveAll": true, "Mkdir": true, "MkdirAll": true, "ReadDir": true,
	"Truncate": true, "Readlink": true,
}

// ioutilFileSinkNames are io/ioutil functions whose first argument is a path.
//
// Older code calling ioutil.ReadFile, WriteFile or ReadDir with a request-controlled path is flagged the same way as the os versions.
var ioutilFileSinkNames = map[string]bool{
	"ReadFile": true, "WriteFile": true, "ReadDir": true,
}
