// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds the function-length helpers that count only code-bearing lines and discount test tables and keyed call literals.
// Without those discounts a table-driven test, or a run of calls passing keyed structs, would read as a long function.
package rule

import (
	"go/ast"
	"go/scanner"
	"go/token"
	"strings"
)

// funcDeclsBySymbol indexes the declarations measuredFuncDecls yields by symbol, spelled as in parser.Function and parser.FuncDeclSymbol.
//
// These are top-level function declarations and function literals assigned to package-level vars.
// It returns a map from each symbol to its declaration in file, the parsed source, and an empty non-nil map when file is nil or has no function.
// When two declarations share a symbol, the one measuredFuncDecls yields last is kept.
func funcDeclsBySymbol(file *ast.File) map[string]*ast.FuncDecl {
	out := map[string]*ast.FuncDecl{}
	for _, fn := range measuredFuncDecls(file) {
		out[functionName(fn)] = fn
	}
	return out
}

// lineRange is an inclusive span of 1-based source lines that function-length counting discounts.
// It marks a test-table fixture, or the lines after the opening brace of a keyed literal passed to a call.
type lineRange struct {
	start int
	end   int
}

// tableFixtureLineRanges returns the test-table data ranges inside a function, so case matrices do not dominate test function length.
//
// Anonymous struct slices, and slices or arrays assigned to common table names such as tests or cases, count as fixture data.
// fset maps literal brace positions to line numbers, and fn is the function whose assignments and var declarations are searched.
// Each range covers the opening to closing brace lines; the result is nil when fset, fn or its body is nil, and empty when nothing qualifies.
func tableFixtureLineRanges(fset *token.FileSet, fn *ast.FuncDecl) []lineRange {
	if fset == nil || fn == nil || fn.Body == nil {
		return nil
	}
	ranges := []lineRange{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch stmt := node.(type) {
		case *ast.AssignStmt:
			for i, rhs := range stmt.Rhs {
				lit, ok := rhs.(*ast.CompositeLit)
				if !ok || i >= len(stmt.Lhs) || !isTableFixtureLiteral(stmt.Lhs[i], lit) {
					continue
				}
				ranges = append(ranges, compositeLiteralLineRange(fset, lit))
			}
		case *ast.ValueSpec:
			for i, value := range stmt.Values {
				lit, ok := value.(*ast.CompositeLit)
				if !ok || i >= len(stmt.Names) || !isTableFixtureLiteral(stmt.Names[i], lit) {
					continue
				}
				ranges = append(ranges, compositeLiteralLineRange(fset, lit))
			}
		}
		return true
	})
	return ranges
}

// isTableFixtureLiteral reports whether a composite literal looks like table-driven test data rather than executable control-flow logic.
// A nil lit is false; lit counts when it is an anonymous struct slice or array, or a slice or array assigned to an lhs with a table-like name.
func isTableFixtureLiteral(lhs ast.Expr, lit *ast.CompositeLit) bool {
	if lit == nil {
		return false
	}
	if isAnonymousStructSliceLiteral(lit) {
		return true
	}
	return isTableishName(lhs) && isSliceLikeCompositeLiteral(lit)
}

// isAnonymousStructSliceLiteral recognises the canonical case-table form of Go table-driven tests, a slice literal of an anonymous struct.
// It reports true when the type of lit is a slice or array of an inline struct type, and false for any other type or none.
func isAnonymousStructSliceLiteral(lit *ast.CompositeLit) bool {
	switch typ := lit.Type.(type) {
	case *ast.ArrayType:
		_, ok := typ.Elt.(*ast.StructType)
		return ok
	case *ast.Ellipsis:
		_, ok := typ.Elt.(*ast.StructType)
		return ok
	default:
		return false
	}
}

// isSliceLikeCompositeLiteral recognises slice and array literals whose assignment target can provide the table-fixture intent.
// It reports true when the type of lit is written as a slice or array type, and false for maps, structs, named types or an elided type.
func isSliceLikeCompositeLiteral(lit *ast.CompositeLit) bool {
	switch lit.Type.(type) {
	case *ast.ArrayType, *ast.Ellipsis:
		return true
	default:
		return false
	}
}

// isTableishName recognises the usual variable names for test case tables, so data literals under other names are not discounted by name.
// It reports true only when expr is a plain identifier named tests, cases, fixtures or rows in any letter case, and false otherwise.
func isTableishName(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	switch strings.ToLower(ident.Name) {
	case "tests", "cases", "fixtures", "rows":
		return true
	default:
		return false
	}
}

// compositeLiteralLineRange converts a literal's brace positions into the line span that function-length counting discounts.
// It returns the inclusive line range of the braces of lit as resolved by fset, with start equal to end for a one-line literal.
func compositeLiteralLineRange(fset *token.FileSet, lit *ast.CompositeLit) lineRange {
	start := fset.Position(lit.Lbrace).Line
	end := fset.Position(lit.Rbrace).Line
	return lineRange{start: start, end: end}
}

// keyedLiteralArgumentLineRanges returns the lines after the opening brace of every multi-line keyed literal passed straight to a call.
//
// Each such literal counts as at most one line of function length, as twelve calls passing keyed request structs are data, not logic.
// Without the discount, the keyed fields alone can make such a function read as long.
//
// fset resolves literal braces to lines, and fn is the function whose body is searched for call arguments, including literals passed by address.
// It returns nil when fset, fn or its body is nil; a literal whose braces share one line adds no range.
func keyedLiteralArgumentLineRanges(fset *token.FileSet, fn *ast.FuncDecl) []lineRange {
	if fset == nil || fn == nil || fn.Body == nil {
		return nil
	}
	ranges := []lineRange{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			lit := keyedCompositeLiteral(arg)
			if lit == nil {
				continue
			}
			literal := compositeLiteralLineRange(fset, lit)
			if literal.end > literal.start {
				ranges = append(ranges, lineRange{start: literal.start + 1, end: literal.end})
			}
		}
		return true
	})
	return ranges
}

// keyedCompositeLiteral returns an argument's composite literal, or the literal behind its address, when every element is key: value.
// arg is a call argument, possibly behind the address operator; it gives nil for a non-literal, an empty literal, or any unkeyed element.
func keyedCompositeLiteral(arg ast.Expr) *ast.CompositeLit {
	if unary, ok := arg.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		arg = unary.X
	}
	lit, ok := arg.(*ast.CompositeLit)
	if !ok || len(lit.Elts) == 0 {
		return nil
	}
	for _, element := range lit.Elts {
		if _, keyed := element.(*ast.KeyValueExpr); !keyed {
			return nil
		}
	}
	return lit
}

// countLinesInLineRangesExcept counts unique code-bearing lines in ranges that no excluded range covers.
//
// A literal inside a discounted test table is therefore not subtracted twice.
// codeLines is the set of code-bearing line numbers, ranges are the inclusive spans to count, and excluded lists spans whose lines never count.
// It returns the number of distinct lines counted, and zero when codeLines or ranges is empty.
func countLinesInLineRangesExcept(codeLines map[int]bool, ranges, excluded []lineRange) int {
	if len(codeLines) == 0 || len(ranges) == 0 {
		return 0
	}
	excludedLines := map[int]bool{}
	for _, r := range excluded {
		for line := r.start; line <= r.end; line++ {
			excludedLines[line] = true
		}
	}
	lines := map[int]bool{}
	for _, r := range ranges {
		for line := r.start; line <= r.end; line++ {
			if codeLines[line] && !excludedLines[line] {
				lines[line] = true
			}
		}
	}
	return len(lines)
}

// countLinesInLineRanges counts unique code-bearing lines inside ranges, so nested literals cannot subtract the same fixture row twice.
// It returns how many distinct lines in the inclusive ranges are set in codeLines, and zero when codeLines or ranges is empty.
func countLinesInLineRanges(codeLines map[int]bool, ranges []lineRange) int {
	if len(codeLines) == 0 || len(ranges) == 0 {
		return 0
	}
	lines := map[int]bool{}
	for _, r := range ranges {
		for line := r.start; line <= r.end; line++ {
			if codeLines[line] {
				lines[line] = true
			}
		}
	}
	return len(lines)
}

// codeBearingLines runs go/scanner over src and returns the set of 1-based line numbers holding at least one non-comment token.
//
// Blank lines, comment-only lines and lines inside block comments are left out; the result is nil only for empty source.
// src is the file text, scanned with errors ignored and illegal tokens skipped; whitespace-only or comment-only src gives an empty map.
func codeBearingLines(src string) map[int]bool {
	if src == "" {
		return nil
	}
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	// Scanner errors are ignored because this pass only needs the line of each token, not a valid parse.
	s.Init(file, []byte(src), func(token.Position, string) {}, 0)
	out := map[int]bool{}
	for {
		pos, tok, _ := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.ILLEGAL {
			continue
		}
		out[file.Position(pos).Line] = true
	}
	return out
}

// countLinesInRange counts how many lines from start to end, inclusive, are code-bearing in codeLines, the per-file set from codeBearingLines.
//
// It returns that count, and 0 for a nil codeLines, which codeBearingLines produces only for empty source.
// The function-length caller falls back to the raw span whenever the count is zero.
func countLinesInRange(codeLines map[int]bool, start, end int) int {
	if codeLines == nil {
		return 0
	}
	count := 0
	for line := start; line <= end; line++ {
		if codeLines[line] {
			count++
		}
	}
	return count
}
