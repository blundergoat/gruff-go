// Package rule defines gruff-go's rule registry and analysers.
// This file implements shared parser-only detection of request-controlled
// expressions, used by the request-driven application-security sink rules.
package rule

import (
	"go/ast"
	"go/token"
	"strings"
)

// requestTaintedMembers names the *http.Request fields and methods that expose
// caller-controlled input. An access rooted at a request parameter that passes
// through one of these members is treated as request-controlled; benign members
// such as Method, Context, or RemoteAddr are intentionally excluded.
var requestTaintedMembers = map[string]bool{
	"URL": true, "RawQuery": true, "Path": true, "RawPath": true,
	"Fragment": true, "Opaque": true, "RequestURI": true, "Host": true,
	"Header": true, "Form": true, "PostForm": true, "MultipartForm": true,
	"Body": true, "Trailer": true,
	"FormValue": true, "PostFormValue": true, "FormFile": true,
	"PathValue": true, "Cookie": true, "Referer": true, "UserAgent": true,
}

// requestTaintScope carries the per-function evidence the request-driven rules
// share: names bound to *http.Request parameters, locals tainted from those
// requests, and the imported aliases of the string-builder packages whose calls
// propagate taint.
type requestTaintScope struct {
	requests     map[string]bool
	tainted      map[string]bool
	fmtPkgs      map[string]bool
	stringsPkgs  map[string]bool
	filepathPkgs map[string]bool
	pathPkgs     map[string]bool
	ioPkgs       map[string]bool
	ioutilPkgs   map[string]bool
}

// forEachRequestFunc invokes visit for every function body in the file that
// declares an *http.Request parameter, covering both top-level handlers and
// closures registered with mux.HandleFunc. Each body is analysed under its own
// bounded same-function scope.
func forEachRequestFunc(file *ast.File, httpPkgs map[string]bool, visit func(scope *requestTaintScope, body *ast.BlockStmt)) {
	ast.Inspect(file, func(node ast.Node) bool {
		switch fn := node.(type) {
		case *ast.FuncDecl:
			if fn.Body == nil {
				return true
			}
			if scope, ok := newRequestTaintScope(file, fn.Type, fn.Body, httpPkgs); ok {
				visit(scope, fn.Body)
			}
		case *ast.FuncLit:
			if scope, ok := newRequestTaintScope(file, fn.Type, fn.Body, httpPkgs); ok {
				visit(scope, fn.Body)
			}
		}
		return true
	})
}

// newRequestTaintScope builds request-controlled evidence for one function body,
// given the file's net/http aliases. It returns ok=false when the function has
// no *http.Request parameter so callers skip cheaply.
func newRequestTaintScope(file *ast.File, funcType *ast.FuncType, body *ast.BlockStmt, httpPkgs map[string]bool) (*requestTaintScope, bool) {
	requests := requestParamNames(funcType, httpPkgs)
	if len(requests) == 0 || body == nil {
		return nil, false
	}
	scope := &requestTaintScope{
		requests:     requests,
		tainted:      map[string]bool{},
		fmtPkgs:      packageImportNames(file, "fmt", "fmt"),
		stringsPkgs:  packageImportNames(file, "strings", "strings"),
		filepathPkgs: packageImportNames(file, "path/filepath", "filepath"),
		pathPkgs:     packageImportNames(file, "path", "path"),
		ioPkgs:       packageImportNames(file, "io", "io"),
		ioutilPkgs:   packageImportNames(file, "io/ioutil", "ioutil"),
	}
	scope.collectTaintedVars(body)
	return scope, true
}

// requestParamNames returns the parameter names declared as *http.Request on a
// function type, mirroring httpRequestParamNames for closures that carry only an
// *ast.FuncType.
func requestParamNames(funcType *ast.FuncType, httpPkgs map[string]bool) map[string]bool {
	out := map[string]bool{}
	if funcType == nil || funcType.Params == nil {
		return out
	}
	for _, field := range funcType.Params.List {
		if !isHTTPRequestPointer(field.Type, httpPkgs) {
			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" {
				out[name.Name] = true
			}
		}
	}
	return out
}

// collectTaintedVars records locals whose value derives from request-controlled
// input, propagating only through string builders, conversions, and concatenation
// so passing a value into an unknown helper (which may sanitise it) does not taint
// the result. Two passes settle simple out-of-order assignments.
func (s *requestTaintScope) collectTaintedVars(body *ast.BlockStmt) {
	for pass := 0; pass < 2; pass++ {
		ast.Inspect(body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			switch stmt := node.(type) {
			case *ast.AssignStmt:
				for i, lhs := range stmt.Lhs {
					ident, ok := lhs.(*ast.Ident)
					if !ok || ident.Name == "_" || i >= len(stmt.Rhs) {
						continue
					}
					if s.directRequestExpr(stmt.Rhs[i]) {
						s.tainted[ident.Name] = true
					}
				}
			case *ast.ValueSpec:
				for i, name := range stmt.Names {
					if name.Name == "_" || i >= len(stmt.Values) {
						continue
					}
					if s.directRequestExpr(stmt.Values[i]) {
						s.tainted[name.Name] = true
					}
				}
			}
			return true
		})
	}
}

// directRequestExpr reports whether expr is request-controlled through the
// restricted propagation set (request accessors, tainted locals, string-builder
// calls, conversions, and + concatenation). Arbitrary calls return false so a
// sanitising helper breaks the chain.
func (s *requestTaintScope) directRequestExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return s.directRequestExpr(e.X)
	case *ast.StarExpr:
		return s.directRequestExpr(e.X)
	case *ast.Ident:
		return s.tainted[e.Name]
	case *ast.BinaryExpr:
		return e.Op == token.ADD && (s.directRequestExpr(e.X) || s.directRequestExpr(e.Y))
	case *ast.CallExpr:
		if _, ok := s.requestAccessLabel(e); ok {
			return true
		}
		if arg, ok := conversionArg(e); ok {
			return s.directRequestExpr(arg)
		}
		if s.isStringBuilderCall(e) || s.isReaderConsumer(e) {
			for _, arg := range e.Args {
				if s.directRequestExpr(arg) {
					return true
				}
			}
		}
		return false
	case *ast.SelectorExpr, *ast.IndexExpr:
		_, ok := s.requestAccessLabel(e)
		return ok
	}
	return false
}

// exprHasRequest walks expr for any request access or tainted local and returns a
// short source label for finding metadata. Unlike directRequestExpr it descends
// into arbitrary calls, so callers pair it with sanitizer checks to suppress
// values that a recognised sanitiser already cleaned.
func (s *requestTaintScope) exprHasRequest(expr ast.Expr) (string, bool) {
	label := ""
	ast.Inspect(expr, func(node ast.Node) bool {
		if label != "" {
			return false
		}
		current, ok := node.(ast.Expr)
		if !ok {
			return true
		}
		if found, ok := s.requestAccessLabel(current); ok {
			label = found
			return false
		}
		if ident, ok := current.(*ast.Ident); ok && s.tainted[ident.Name] {
			label = ident.Name
			return false
		}
		return true
	})
	return label, label != ""
}

// requestAccessLabel reports whether expr reads request-controlled data and, if
// so, returns a short root.member label (for example "r.FormValue").
func (s *requestTaintScope) requestAccessLabel(expr ast.Expr) (string, bool) {
	root, members := flattenChain(expr)
	if root == "" || !s.requests[root] {
		return "", false
	}
	for _, member := range members {
		if requestTaintedMembers[member] {
			return root + "." + members[0], true
		}
	}
	return "", false
}

// isStringBuilderCall reports whether call is one of the concatenating/formatting
// calls (fmt.Sprint*, strings.Join, path[/filepath].Join) that carry taint from
// their arguments into the result.
func (s *requestTaintScope) isStringBuilderCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch selector.Sel.Name {
	case "Sprintf", "Sprint", "Sprintln":
		return s.fmtPkgs[receiver.Name]
	case "Join":
		return s.stringsPkgs[receiver.Name] || s.filepathPkgs[receiver.Name] || s.pathPkgs[receiver.Name]
	}
	return false
}

// isReaderConsumer reports whether call drains a reader into bytes via
// io.ReadAll, io.ReadFull, or ioutil.ReadAll, so reading a request body carries
// the request taint onto the resulting bytes.
func (s *requestTaintScope) isReaderConsumer(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch selector.Sel.Name {
	case "ReadAll":
		return s.ioPkgs[receiver.Name] || s.ioutilPkgs[receiver.Name]
	case "ReadFull":
		return s.ioPkgs[receiver.Name]
	}
	return false
}

// flattenChain reduces a selector/call/index chain to its root identifier name
// and the ordered member names accessed on it, so request access can be matched
// structurally without rendering source text.
func flattenChain(expr ast.Expr) (string, []string) {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name, nil
	case *ast.SelectorExpr:
		root, members := flattenChain(e.X)
		return root, append(members, e.Sel.Name)
	case *ast.CallExpr:
		return flattenChain(e.Fun)
	case *ast.IndexExpr:
		return flattenChain(e.X)
	case *ast.IndexListExpr:
		return flattenChain(e.X)
	case *ast.ParenExpr:
		return flattenChain(e.X)
	case *ast.StarExpr:
		return flattenChain(e.X)
	default:
		return "", nil
	}
}

// conversionArg returns the inner expression of a string(x) or []byte(x)
// conversion so taint propagates across the common byte/string round-trips.
func conversionArg(call *ast.CallExpr) (ast.Expr, bool) {
	if len(call.Args) != 1 {
		return nil, false
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		if fun.Name == "string" {
			return call.Args[0], true
		}
	case *ast.ArrayType:
		if ident, ok := fun.Elt.(*ast.Ident); ok && ident.Name == "byte" {
			return call.Args[0], true
		}
	}
	return nil, false
}

// identNames collects every identifier name appearing in expr, used to check
// whether a later sanitiser call references the same value.
func identNames(expr ast.Expr) map[string]bool {
	names := map[string]bool{}
	ast.Inspect(expr, func(node ast.Node) bool {
		if ident, ok := node.(*ast.Ident); ok && ident.Name != "_" {
			names[ident.Name] = true
		}
		return true
	})
	return names
}

// bodyHasSanitizingCall reports whether the function body contains a call whose
// name matches one of words and that references one of the value identifiers,
// treating a recognised validator/cleaner as same-function sanitizer evidence.
func bodyHasSanitizingCall(body *ast.BlockStmt, valueNames map[string]bool, words []string) bool {
	if len(valueNames) == 0 {
		return false
	}
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok || !callNameMatchesAny(call, words) {
			return true
		}
		if nodeUsesAnyIdent(call, valueNames) {
			found = true
			return false
		}
		return true
	})
	return found
}

// argHasInlineSanitizer reports whether the request-controlled value inside arg
// is wrapped directly by a sanitiser-named call, covering the inline
// sanitize(r.FormValue(...)) shape that carries no intermediate variable.
func (s *requestTaintScope) argHasInlineSanitizer(arg ast.Expr, words []string) bool {
	found := false
	ast.Inspect(arg, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok || !callNameMatchesAny(call, words) {
			return true
		}
		if _, ok := s.exprHasRequest(call); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

// callNameMatchesAny reports whether the call's function name, lowercased,
// contains any of the sanitizer words.
func callNameMatchesAny(call *ast.CallExpr, words []string) bool {
	name := strings.ToLower(callName(call))
	if name == "" {
		return false
	}
	for _, word := range words {
		if strings.Contains(name, word) {
			return true
		}
	}
	return false
}
