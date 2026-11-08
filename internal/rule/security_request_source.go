// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements shared parser-only detection of request-controlled expressions for the request-driven application-security sink rules.
// exprHasRequest also gives a short source label, such as r.FormValue, for finding metadata.
package rule

import (
	"go/ast"
	"go/token"
	"strings"
	"unicode"
)

// requestTaintedMembers names the request fields, methods and nested URL members that expose caller-controlled input.
//
// An access rooted at a request parameter that passes through one of these members is treated as request-controlled.
// Benign members such as Method, Context or RemoteAddr are intentionally excluded, so reading only them is not request input.
var requestTaintedMembers = map[string]bool{
	"URL": true, "RawQuery": true, "Path": true, "RawPath": true,
	"Fragment": true, "Opaque": true, "RequestURI": true, "Host": true,
	"Header": true, "Form": true, "PostForm": true, "MultipartForm": true,
	"Body": true, "Trailer": true,
	"FormValue": true, "PostFormValue": true, "FormFile": true,
	"PathValue": true, "Cookie": true, "Referer": true, "UserAgent": true,
}

// requestTaintScope carries the per-function evidence shared by request-driven rules.
//
// It holds lexical request and taint bindings, helper import aliases, and parsed-URL bindings that keep caller-controlled destinations.
// A new scope is built for each handler body, so taint found in one handler never marks values in another.
type requestTaintScope struct {
	functionType      *ast.FuncType
	requestNames      map[string]bool
	requestBindings   map[*ast.Object]bool
	taintedBindings   map[*ast.Object]bool
	fmtPkgs           map[string]bool
	stringsPkgs       map[string]bool
	filepathPkgs      map[string]bool
	pathPkgs          map[string]bool
	netURLPkgs        map[string]bool
	parsedURLBindings map[*ast.Object]bool
	ioPkgs            map[string]bool
	ioutilPkgs        map[string]bool
	// firstTaintPos records, per tainted binding, the position of the earliest assignment that introduced request-controlled data.
	// Sinks consult it so a value counts as tainted only at a sink after its taint, not at a use before a later request assignment.
	firstTaintPos map[*ast.Object]token.Pos
	// body is the analysed function body. Sinks walk it to find writes that
	// replace a tainted value with request-free data before the sink runs.
	body *ast.BlockStmt
}

// forEachRequestFunc invokes visit for every function body in file with a named, non-blank *http.Request parameter.
//
// This covers top-level handlers and closures such as those registered with mux.HandleFunc; a nested handler closure is visited separately.
// Each body gets a separate taint scope; sanitizer-call searches also inspect nested closures and can count calls that never execute.
//
// httpPkgs holds the net/http import names of file, used to recognise request parameters; declarations without a body are skipped.
// visit receives each scope together with the body it was built from.
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

// newRequestTaintScope builds the request-controlled evidence for one function body, given the file's net/http aliases.
//
// funcType is searched for request parameters using httpPkgs, and file supplies the helper package import aliases the scope recognises.
// It returns nil and false when no named, non-blank *http.Request parameter is found or body is nil, so callers skip that body.
// Otherwise it returns the scope and true, with collectTaintedVars already run over body.
func newRequestTaintScope(file *ast.File, funcType *ast.FuncType, body *ast.BlockStmt, httpPkgs map[string]bool) (*requestTaintScope, bool) {
	requestNames, requestBindings := requestParameters(funcType, httpPkgs)
	if len(requestNames) == 0 || body == nil {
		return nil, false
	}
	scope := &requestTaintScope{
		functionType:      funcType,
		requestNames:      requestNames,
		requestBindings:   requestBindings,
		taintedBindings:   map[*ast.Object]bool{},
		fmtPkgs:           packageImportNames(file, "fmt", "fmt"),
		stringsPkgs:       packageImportNames(file, "strings", "strings"),
		filepathPkgs:      packageImportNames(file, "path/filepath", "filepath"),
		pathPkgs:          packageImportNames(file, "path", "path"),
		netURLPkgs:        packageImportNames(file, "net/url", "url"),
		parsedURLBindings: map[*ast.Object]bool{},
		ioPkgs:            packageImportNames(file, "io", "io"),
		ioutilPkgs:        packageImportNames(file, "io/ioutil", "ioutil"),
		firstTaintPos:     map[*ast.Object]token.Pos{},
		body:              body,
	}
	scope.collectTaintedVars(body)
	return scope, true
}

// requestParameters returns the names and lexical bindings of funcType's *http.Request parameters.
//
// Names support sanitizer filtering; bindings stop a shadowed local from inheriting request-control status.
// Parameters of funcType are matched against httpPkgs, the file's import names for net/http, and blank names are skipped.
// A nil funcType or parameter list gives two empty, non-nil maps; a name without a resolved object is recorded only in the names map.
func requestParameters(funcType *ast.FuncType, httpPkgs map[string]bool) (map[string]bool, map[*ast.Object]bool) {
	requestNames := map[string]bool{}
	requestBindings := map[*ast.Object]bool{}
	// A missing parameter list means this function cannot be a request handler.
	if funcType == nil || funcType.Params == nil {
		return requestNames, requestBindings
	}
	// A function with no named, non-blank *http.Request parameter leaves both maps empty, so forEachRequestFunc never visits it.
	for _, field := range funcType.Params.List {
		// Other parameter types do not expose caller-controlled HTTP input.
		if !isHTTPRequestPointer(field.Type, httpPkgs) {
			continue
		}
		// Each named request keeps its own binding inside the function.
		for _, name := range field.Names {
			// Blank request parameters cannot be referenced by a sink expression.
			if name.Name != "_" {
				requestNames[name.Name] = true
				if name.Obj != nil {
					requestBindings[name.Obj] = true
				}
			}
		}
	}
	return requestNames, requestBindings
}

// collectTaintedVars records locals in body whose value derives from request-controlled input.
//
// Taint flows only through the transparent operations directRequestExpr knows, such as string builders, conversions and concatenation.
// Passing a value into an unknown helper, which may sanitise it, leaves the result untainted.
//
// body is walked twice so simple out-of-order assignments settle, without entering nested function literals.
// Only plain identifier targets of assignments and value specs are marked.
func (s *requestTaintScope) collectTaintedVars(body *ast.BlockStmt) {
	for pass := 0; pass < 2; pass++ {
		ast.Inspect(body, func(node ast.Node) bool {
			// Locals assigned inside a closure are not tracked here; a closure with its own request parameter gets its own scope.
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			switch stmt := node.(type) {
			case *ast.AssignStmt:
				for i, lhs := range stmt.Lhs {
					ident, ok := lhs.(*ast.Ident)
					// With one call feeding several targets, as in data, err := io.ReadAll(r.Body), only the first target can become tainted.
					if !ok || ident.Name == "_" || i >= len(stmt.Rhs) {
						continue
					}
					if s.directRequestExpr(stmt.Rhs[i]) {
						s.markTaintedAt(ident, s.taintIntroPos(stmt.Rhs[i], ident.Pos()))
						if s.isParsedURLExpr(stmt.Rhs[i]) {
							s.markParsedURLBinding(ident)
						}
					}
				}
			case *ast.ValueSpec:
				for i, name := range stmt.Names {
					if name.Name == "_" || i >= len(stmt.Values) {
						continue
					}
					if s.directRequestExpr(stmt.Values[i]) {
						s.markTaintedAt(name, s.taintIntroPos(stmt.Values[i], name.Pos()))
						if s.isParsedURLExpr(stmt.Values[i]) {
							s.markParsedURLBinding(name)
						}
					}
				}
			}
			return true
		})
	}
}

// directRequestExpr follows request input through known transparent operations.
//
// It reports whether expr is a request access or tainted local, or reaches one through parentheses, a dereference, or an addition operand.
// Conversions, path Clean, URL syntax parses, string builders and reader drains pass taint through, as does stringifying a parsed request URL.
// Any other call, such as an unknown helper that may sanitize its argument, reports false.
func (s *requestTaintScope) directRequestExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return s.directRequestExpr(e.X)
	case *ast.StarExpr:
		return s.directRequestExpr(e.X)
	case *ast.Ident:
		return e.Obj != nil && s.taintedBindings[e.Obj]
	case *ast.BinaryExpr:
		return e.Op == token.ADD && (s.directRequestExpr(e.X) || s.directRequestExpr(e.Y))
	case *ast.CallExpr:
		if _, ok := s.requestAccessLabel(e); ok {
			return true
		}
		if arg, ok := conversionArg(e); ok {
			return s.directRequestExpr(arg)
		}
		if arg, ok := s.pathCleanArg(e); ok {
			return s.directRequestExpr(arg)
		}
		// Keep a parsed user URL visible until the URL rule finds destination guards.
		if parsedURLInput, isSyntaxParse := s.urlSyntaxParseArg(e); isSyntaxParse {
			return s.directRequestExpr(parsedURLInput)
		}
		// Converting a parsed request URL back to text preserves its destination.
		if _, isParsedString := s.parsedURLStringReceiver(e); isParsedString {
			return true
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

// pathCleanArg returns the argument of a path.Clean or filepath.Clean call, so request taint flows through Clean.
//
// Clean normalises syntax but does not remove attacker control: it keeps a leading ../, so callers still need a containment check.
// call must have exactly one argument and a Clean selector on an unshadowed path or filepath import; otherwise it returns nil and false.
func (s *requestTaintScope) pathCleanArg(call *ast.CallExpr) (ast.Expr, bool) {
	if len(call.Args) != 1 {
		return nil, false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Clean" {
		return nil, false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || (!isImportedPackageIdentifier(receiver, s.filepathPkgs) && !isImportedPackageIdentifier(receiver, s.pathPkgs)) {
		return nil, false
	}
	return call.Args[0], true
}

// exprHasRequest walks expr for any request access or tainted local and returns a short source label for finding metadata.
//
// Unlike directRequestExpr it descends into arbitrary calls; some callers suppress findings based on sanitizer call names.
// A request access always counts; a tainted local counts at a valid sinkPos only if tainted earlier and not cleared first.
// Clearing needs a dominating request-free write, and an invalid sinkPos skips both checks.
//
// The label is the request access, such as r.FormValue, or the local's name; an empty label and false mean expr holds neither.
func (s *requestTaintScope) exprHasRequest(expr ast.Expr, sinkPos token.Pos) (string, bool) {
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
		if ident, ok := current.(*ast.Ident); ok && s.taintedBefore(ident, sinkPos) {
			label = ident.Name
			return false
		}
		return true
	})
	return label, label != ""
}

// requestAccessLabel reports whether expr reads request-controlled data and, if so, returns a short root.member label such as r.FormValue.
//
// A requestTaintedMembers entry anywhere in the chain counts, so r.URL.Query() is request input while r.Context() is not.
// The label names the first member after the request parameter, so r.URL.Query().Get(...) gives r.URL; it is empty when the result is false.
func (s *requestTaintScope) requestAccessLabel(expr ast.Expr) (string, bool) {
	root, members := flattenChain(expr)
	// A bare request identifier does not expose a caller-controlled member.
	if root == nil || len(members) == 0 {
		return "", false
	}
	if !s.isRequestIdentifier(root) {
		return "", false
	}
	for _, member := range members {
		if requestTaintedMembers[member] {
			return root.Name + "." + members[0], true
		}
	}
	return "", false
}

// isRequestIdentifier reports whether identifier is the handler's request parameter; a nil identifier reports false.
//
// Resolved syntax uses lexical identity, so a local that shadows the request name is not request input.
// Malformed partial Go falls back to the declared request name because no binding is available.
func (s *requestTaintScope) isRequestIdentifier(identifier *ast.Ident) bool {
	// Missing syntax cannot identify a request parameter.
	if identifier == nil {
		return false
	}
	// A resolved shadow must not inherit request status from its spelling.
	if identifier.Obj != nil {
		return s.requestBindings[identifier.Obj]
	}
	return s.requestNames[identifier.Name]
}

// isStringBuilderCall reports whether call is fmt.Sprintf, Sprint or Sprintln, or strings, path or filepath Join, on an unshadowed import.
// A true result carries taint from any argument into the built string; every other call, including methods on locals, reports false.
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
		return isImportedPackageIdentifier(receiver, s.fmtPkgs)
	case "Join":
		return isImportedPackageIdentifier(receiver, s.stringsPkgs) ||
			isImportedPackageIdentifier(receiver, s.filepathPkgs) ||
			isImportedPackageIdentifier(receiver, s.pathPkgs)
	}
	return false
}

// isReaderConsumer reports whether call is io.ReadAll, io.ReadFull or ioutil.ReadAll on an unshadowed import; any other call reports false.
//
// A true result lets reading a request body carry the request taint onto the resulting bytes.
// For io.ReadFull that marks the first assignment target, the byte count, while the filled buffer stays untainted.
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
		return isImportedPackageIdentifier(receiver, s.ioPkgs) || isImportedPackageIdentifier(receiver, s.ioutilPkgs)
	case "ReadFull":
		return isImportedPackageIdentifier(receiver, s.ioPkgs)
	}
	return false
}

// isImportedPackageIdentifier reports whether identifier names one of packageAliases and still refers to that import.
//
// go/parser leaves an import reference unresolved, so a resolved identifier is a shadow: http := localClient{} must not read as net/http.
// packageAliases holds the accepted import names; a nil identifier, or one resolved to a local object, reports false.
func isImportedPackageIdentifier(identifier *ast.Ident, packageAliases map[string]bool) bool {
	// A resolved identifier is a declared shadow, not the imported package.
	if identifier == nil || identifier.Obj != nil {
		return false
	}
	return packageAliases[identifier.Name]
}

// flattenChain reduces a selector, call or index chain to its root identifier and ordered member names, keeping lexical binding data.
//
// It returns the root of expr and its member names from the root outward, so r.URL.Query() yields r with URL then Query.
// A chain with no identifier root gives a nil root but still returns any selector names above it, and a bare identifier gives a nil member slice.
func flattenChain(expr ast.Expr) (*ast.Ident, []string) {
	switch e := expr.(type) {
	case *ast.Ident:
		return e, nil
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
		return nil, nil
	}
}

// conversionArg returns the inner expression of a string(x) or byte-slice conversion, so taint survives byte and string round-trips.
// call needs exactly one argument and the identifier string or a byte slice or array type as its function; otherwise it returns nil and false.
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

// identNames collects every identifier name in expr, so a later sanitiser call can be matched to the same value.
//
// It returns a non-nil set of those names, excluding the blank identifier, and an empty set when expr has none.
// Package and member names count too, so filepath.Join(dir, name) gives filepath, Join, dir and name.
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

// sanitizerValueNames returns the identifiers in arg that a sanitizer call must reference to count as evidence for this sink.
//
// The *http.Request parameter names are removed, so an auth or CSRF check such as validate(r) cannot suppress a real finding.
// Such a check does not prove that the specific URL or path value at the sink was constrained.
//
// The result is empty when arg names nothing but the request, and bodyHasSanitizingCall then finds no sanitizer evidence.
func (s *requestTaintScope) sanitizerValueNames(arg ast.Expr) map[string]bool {
	names := identNames(arg)
	for requestName := range s.requestNames {
		delete(names, requestName)
	}
	return names
}

// bodyHasSanitizingCall reports whether body contains a call whose name matches one of words and that references one of valueNames.
//
// A match counts as sanitizer evidence, which lets a recognised validator or cleaner of the sink's value suppress the finding.
// The walk also enters nested function literals, so a matching call inside a closure that never runs still counts.
//
// An empty valueNames reports false at once, and when beforePos is valid only calls positioned before it count, so a later cleaner is ignored.
// With non-empty valueNames and words, a call name in body that shrinks in bytes when lowercased can make callNameMatchesAny panic.
func bodyHasSanitizingCall(body *ast.BlockStmt, valueNames map[string]bool, words []string, beforePos token.Pos) bool {
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
		// A validator or cleaner only cleanses the value if it runs before the sink; a call at or after beforePos does not count for this sink.
		// Before means earlier in the source, so a validator in a branch that never reaches the sink still counts.
		if beforePos.IsValid() && call.Pos() >= beforePos {
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

// argHasInlineSanitizer reports whether any sanitiser-named call inside arg wraps request-controlled input, as in sanitize(r.FormValue(...)).
//
// This covers the inline shape that carries no intermediate variable; one wrapped input is enough, even beside an unwrapped request value.
// A call in arg counts when its name matches one of words and exprHasRequest finds request-controlled input inside it.
// exprHasRequest gets token.NoPos, an invalid sinkPos, so a tainted local counts without its ordering checks.
//
// With non-empty words, a call name in arg whose lowercase form is shorter than an original token offset can cause a slice bounds panic.
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
		if _, ok := s.exprHasRequest(call, token.NoPos); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

// callNameMatchesAny reports whether any camelCase or snake_case token of call's function name starts with a sanitizer stem in words.
//
// Token-boundary matching lets sanit match sanitize and islocal match IsLocal, but never reads safe out of unsafe or base out of database.
// Each stem in words is compared unchanged against the lowercased name, so a stem must itself be lowercase to match.
//
// A call for which callName finds no name reports false.
// A name that shrinks in bytes when lowercased, such as one with a Kelvin sign, can panic at a later token offset when words is non-empty.
func callNameMatchesAny(call *ast.CallExpr, words []string) bool {
	name := callName(call)
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	for _, start := range identifierTokenStarts(name) {
		for _, word := range words {
			if strings.HasPrefix(lower[start:], word) {
				return true
			}
		}
	}
	return false
}

// identifierTokenStarts returns the byte offsets where a new token begins in name, so sanitizer stems anchor to word boundaries.
//
// Tokens start at the name's first character, after an underscore, hyphen or dot, and at each lower-or-digit to upper camelCase step.
// The result is nil for an empty name or one made only of separators.
func identifierTokenStarts(name string) []int {
	var starts []int
	prevSep := true
	var prev rune
	for i, r := range name {
		if r == '_' || r == '-' || r == '.' {
			prevSep = true
			prev = r
			continue
		}
		if prevSep || (unicode.IsUpper(r) && (unicode.IsLower(prev) || unicode.IsDigit(prev))) {
			starts = append(starts, i)
		}
		prevSep = false
		prev = r
	}
	return starts
}
