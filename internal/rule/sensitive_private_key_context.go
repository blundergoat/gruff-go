// Package rule checks source evidence before deciding whether a PEM header is a credential warning.
// This file handles Go syntax for the private-key rule when a developer defines a parser pattern or strips a delimiter.
// Only the exact matched literal can be exempted; a second header or authored key body still reaches the scanner.
// If parsing is unavailable, the developer keeps the warning for review.
package rule

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/blundergoat/gruff-go/internal/parser"
)

// privateKeyMarkerCandidate identifies one PEM header found in a developer's Go source.
// Its byte span ties a possible exemption to one parsed literal, even when a line contains other headers.
// The source unit supplies the AST and file positions; without them, the rule keeps the warning.
type privateKeyMarkerCandidate struct {
	unit   parser.Unit
	marker string
	start  int
	end    int
}

// isGoPrivateKeyParserMarker accepts a matched header only when parsed Go code uses that exact literal as a native pattern or delimiter.
// The scan keeps warning when a file has no AST, as happens when a Go file exceeds the configured deep-scan budget.
func isGoPrivateKeyParserMarker(unit parser.Unit, marker string, matchStart int, matchEnd int) bool {
	// Without parsed syntax, a header may be embedded key material that the developer needs to inspect.
	if unit.AST == nil || unit.FileSet == nil {
		return false
	}
	regexpImports := packageImportNames(unit.AST, "regexp", "regexp")
	stringsImports := packageImportNames(unit.AST, "strings", "strings")
	callerParameters := functionParameterObjects(unit.AST)
	candidate := privateKeyMarkerCandidate{unit: unit, marker: marker, start: matchStart, end: matchEnd}
	matchedParserMarker := false
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		// Once the matched literal is proven harmless, other source nodes cannot change this match's decision.
		if matchedParserMarker {
			return false
		}
		call, isCall := node.(*ast.CallExpr)
		// Only a call that owns the matched literal can explain why this header appears in source.
		if !isCall {
			return true
		}
		matchedParserMarker = isNativePrivateKeyMarkerCall(candidate, call, regexpImports, stringsImports) ||
			isCallerProvidedPrivateKeyRewrap(candidate, call, callerParameters, stringsImports)
		return !matchedParserMarker
	})
	return matchedParserMarker
}

// isNativePrivateKeyMarkerCall recognizes a standard-library regexp pattern or string delimiter argument that contains only the matched marker.
// A similarly named local value or a marker in another argument leaves the warning visible.
func isNativePrivateKeyMarkerCall(candidate privateKeyMarkerCandidate, call *ast.CallExpr,
	regexpImports map[string]bool, stringsImports map[string]bool) bool {
	selector, isSelector := call.Fun.(*ast.SelectorExpr)
	// An unqualified or computed call does not prove which parser operation uses the header.
	if !isSelector {
		return false
	}
	packageName, isPackageName := selector.X.(*ast.Ident)
	// A local receiver can have the same method name as the standard library.
	if !isPackageName || packageName.Obj != nil {
		return false
	}
	// A standalone regexp header pattern names a format and contains no private-key body.
	if regexpImports[packageName.Name] && len(call.Args) == 1 &&
		(selector.Sel.Name == "Compile" || selector.Sel.Name == "MustCompile") {
		return isExactPrivateKeyMarkerLiteral(candidate, call.Args[0])
	}
	// A string operation may use the header as its delimiter, never as the source value being processed.
	if stringsImports[packageName.Name] {
		switch selector.Sel.Name {
		case "ReplaceAll":
			if len(call.Args) == 3 {
				return isExactPrivateKeyMarkerLiteral(candidate, call.Args[1])
			}
		case "TrimPrefix", "TrimSuffix":
			if len(call.Args) == 2 {
				return isExactPrivateKeyMarkerLiteral(candidate, call.Args[1])
			}
		}
	}
	return false
}

// isExactPrivateKeyMarkerLiteral requires the candidate's source span to fall inside one complete string literal with no authored body.
// A developer who places a second header or key bytes beside the marker still receives a finding for that source.
func isExactPrivateKeyMarkerLiteral(candidate privateKeyMarkerCandidate, expression ast.Expr) bool {
	literal, isLiteral := expression.(*ast.BasicLit)
	// Joined strings or non-string expressions can hide body text, so they keep the warning.
	if !isLiteral || literal.Kind != token.STRING {
		return false
	}
	literalStart := candidate.unit.FileSet.Position(literal.Pos()).Offset
	literalEnd := candidate.unit.FileSet.Position(literal.End()).Offset
	// The exact header being judged must belong to this literal, even when another header shares its source line.
	if candidate.start < literalStart+1 || candidate.end > literalEnd-1 {
		return false
	}
	value, isString := stringLiteral(literal)
	// An undecodable literal cannot prove that it contains only a delimiter.
	if !isString {
		return false
	}
	return value == candidate.marker || value == candidate.marker+"\n" || value == candidate.marker+`\n`
}

// isCallerProvidedPrivateKeyRewrap keeps a header quiet when a function wraps its caller's PEM payload in matching delimiters.
// The byte-slice expression must have the exact header, one parameter and the matching footer, with no authored key body.
func isCallerProvidedPrivateKeyRewrap(candidate privateKeyMarkerCandidate, call *ast.CallExpr,
	callerParameters map[*ast.Object]bool, stringsImports map[string]bool) bool {
	byteSlice, isSlice := call.Fun.(*ast.ArrayType)
	// The observed re-wrap is a byte-slice conversion; an unrelated call does not establish delimiter use.
	if !isSlice || byteSlice.Len != nil || len(call.Args) != 1 {
		return false
	}
	byteName, isByteName := byteSlice.Elt.(*ast.Ident)
	// A shadowed byte type could give this expression a different role.
	if !isByteName || byteName.Name != "byte" || byteName.Obj != nil {
		return false
	}
	withFooter, hasFooter := call.Args[0].(*ast.BinaryExpr)
	// A complete wrapper ends with a matching footer after the caller's payload.
	if !hasFooter || withFooter.Op != token.ADD {
		return false
	}
	withPayload, hasPayload := withFooter.X.(*ast.BinaryExpr)
	// The source must put the isolated opening marker immediately before the caller's payload.
	if !hasPayload || withPayload.Op != token.ADD ||
		!isExactPrivateKeyMarkerLiteral(candidate, withPayload.X) {
		return false
	}
	header, isHeader := stringLiteral(withPayload.X)
	// The opening marker needs a real line break before the supplied payload.
	if !isHeader || header != candidate.marker+"\n" {
		return false
	}
	payload, isIdentifier := withPayload.Y.(*ast.Ident)
	// A literal or unrelated local value could contain authored key material; the bounded wrapper starts with a function parameter.
	if !isIdentifier || payload.Obj == nil || !callerParameters[payload.Obj] {
		return false
	}
	// A parameter overwritten with authored body text is no longer caller-supplied, so the header must warn.
	if !isCallerDerivedPrivateKeyPayload(candidate, call, payload, stringsImports) {
		return false
	}
	footer, isFooter := stringLiteral(withFooter.Y)
	// A different or absent closing marker leaves the source ambiguous for the developer.
	if !isFooter {
		return false
	}
	return footer == "\n"+strings.Replace(candidate.marker, "-----BEGIN ", "-----END ", 1)
}

// isCallerDerivedPrivateKeyPayload permits only a prior standard-library strip of the same marker from the caller's parameter.
// Any other write or address escape before the wrapper leaves the payload's origin uncertain and keeps the warning.
func isCallerDerivedPrivateKeyPayload(candidate privateKeyMarkerCandidate, rewrap *ast.CallExpr, payload *ast.Ident,
	stringsImports map[string]bool) bool {
	callerDerived := true
	ast.Inspect(candidate.unit.AST, func(node ast.Node) bool {
		// Once the payload origin is uncertain, later source cannot restore this match's exemption.
		if !callerDerived {
			return false
		}
		switch change := node.(type) {
		case *ast.AssignStmt:
			// An assignment before the wrapper can replace the caller's bytes with authored source text.
			if change.Pos() >= rewrap.Pos() {
				return true
			}
			for _, left := range change.Lhs {
				name, isName := left.(*ast.Ident)
				// Only writes to this parameter can change the payload used by the wrapper.
				if !isName || name.Obj != payload.Obj {
					continue
				}
				callerDerived = change.Tok == token.ASSIGN && len(change.Lhs) == 1 && len(change.Rhs) == 1 &&
					isCallerMarkerStrip(change.Rhs[0], payload.Obj, candidate.marker, stringsImports)
				return callerDerived
			}
		case *ast.RangeStmt:
			// A range target can overwrite the same name without an ordinary assignment statement.
			if change.Pos() < rewrap.Pos() && (isPrivateKeyPayloadName(change.Key, payload.Obj) ||
				isPrivateKeyPayloadName(change.Value, payload.Obj)) {
				callerDerived = false
				return false
			}
		case *ast.UnaryExpr:
			// Passing the parameter's address away before wrapping makes its value impossible to prove with parser-only evidence.
			if change.Op == token.AND && change.Pos() < rewrap.Pos() && isPrivateKeyPayloadName(change.X, payload.Obj) {
				callerDerived = false
				return false
			}
		}
		return true
	})
	return callerDerived
}

// isPrivateKeyPayloadName checks whether an expression names the same caller parameter used by the PEM wrapper.
func isPrivateKeyPayloadName(expression ast.Expr, binding *ast.Object) bool {
	name, isName := expression.(*ast.Ident)
	return isName && name.Obj == binding
}

// isCallerMarkerStrip recognizes a native string operation that only removes the opening marker from caller-supplied text.
// An unrelated replacement or a shadowed package may introduce authored data and keeps the warning.
func isCallerMarkerStrip(expression ast.Expr, binding *ast.Object, marker string, stringsImports map[string]bool) bool {
	call, isCall := expression.(*ast.CallExpr)
	// Only a direct native string call establishes that the parameter remains caller-derived.
	if !isCall {
		return false
	}
	selector, isSelector := call.Fun.(*ast.SelectorExpr)
	// A method on an unrelated object is not a standard-library delimiter operation.
	if !isSelector {
		return false
	}
	packageName, isPackageName := selector.X.(*ast.Ident)
	// A shadowed or absent import cannot prove what the operation does to the payload.
	if !isPackageName || packageName.Obj != nil || !stringsImports[packageName.Name] || len(call.Args) < 2 ||
		!isPrivateKeyPayloadName(call.Args[0], binding) {
		return false
	}
	delimiter, isDelimiter := stringLiteral(call.Args[1])
	// The strip must remove this marker, rather than adding or substituting other text.
	if !isDelimiter || delimiter != marker {
		return false
	}
	// ReplaceAll is safe only with an empty replacement; the trim calls have no replacement argument.
	if selector.Sel.Name == "ReplaceAll" && len(call.Args) == 3 {
		replacement, isReplacement := stringLiteral(call.Args[2])
		return isReplacement && replacement == ""
	}
	return len(call.Args) == 2 && (selector.Sel.Name == "TrimPrefix" || selector.Sel.Name == "TrimSuffix")
}

// functionParameterObjects identifies caller-supplied names in parsed Go functions for the bounded PEM re-wrap check.
// The wrapper also checks prior writes before it treats that parameter as caller-derived.
func functionParameterObjects(file *ast.File) map[*ast.Object]bool {
	parameters := map[*ast.Object]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		functionType, isFunction := node.(*ast.FuncType)
		// A type or expression outside a function cannot supply a caller's key bytes.
		if !isFunction || functionType.Params == nil {
			return true
		}
		for _, field := range functionType.Params.List {
			for _, name := range field.Names {
				// The parser's object identity separates a parameter from a same-named local value.
				if name.Obj != nil {
					parameters[name.Obj] = true
				}
			}
		}
		return true
	})
	return parameters
}
