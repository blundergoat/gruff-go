// Package rule defines gruff-go's rule registry and analysers.
package rule

import (
	"go/ast"
	"go/scanner"
	"go/token"
	"strings"
)

// funcDeclsBySymbol indexes top-level function declarations, and function literals assigned to package-level vars,
// using the same symbol spelling as parser.Function and funcDeclSymbol.
func funcDeclsBySymbol(file *ast.File) map[string]*ast.FuncDecl {
	out := map[string]*ast.FuncDecl{}
	for _, fn := range measuredFuncDecls(file) {
		out[functionName(fn)] = fn
	}
	return out
}

// lineRange stores an inclusive source-line interval for discounting fixture
// data from test function length calculations.
type lineRange struct {
	start int
	end   int
}

// tableFixtureLineRanges returns multiline test-table data ranges inside a
// function. Anonymous struct slices and common table variable names are treated
// as fixture data so case matrices do not dominate test function length.
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

// isTableFixtureLiteral reports whether a composite literal looks like
// table-driven test data rather than executable control-flow logic.
func isTableFixtureLiteral(lhs ast.Expr, lit *ast.CompositeLit) bool {
	if lit == nil {
		return false
	}
	if isAnonymousStructSliceLiteral(lit) {
		return true
	}
	return isTableishName(lhs) && isSliceLikeCompositeLiteral(lit)
}

// isAnonymousStructSliceLiteral recognises the canonical `[]struct{...}{...}`
// case-table form used by Go table-driven tests.
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

// isSliceLikeCompositeLiteral recognises slice and array literals whose
// assignment target can provide the table-fixture intent.
func isSliceLikeCompositeLiteral(lit *ast.CompositeLit) bool {
	switch lit.Type.(type) {
	case *ast.ArrayType, *ast.Ellipsis:
		return true
	default:
		return false
	}
}

// isTableishName recognises conventional variable names for test case matrices
// without applying the discount to arbitrary production-looking data literals.
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

// compositeLiteralLineRange converts a fixture literal's brace positions into
// the line interval that should be removed from executable length accounting.
func compositeLiteralLineRange(fset *token.FileSet, lit *ast.CompositeLit) lineRange {
	start := fset.Position(lit.Lbrace).Line
	end := fset.Position(lit.Rbrace).Line
	return lineRange{start: start, end: end}
}

// keyedLiteralArgumentLineRanges returns, for every multi-line composite literal
// written with keys and passed straight to a call, the lines after its opening
// brace, so the literal counts as one line of function length. Twelve calls that
// each pass a keyed request struct are data, not logic, and must not read as a
// long function (finding GO-09 of the 2026-10-04 blundergoat-platform field report).
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

// keyedCompositeLiteral returns an argument's composite literal, or the literal
// whose address it takes, when every element is written as key: value.
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

// countLinesInLineRangesExcept counts unique code-bearing lines inside ranges
// that no excluded range covers, so a literal inside a discounted test table is
// not subtracted twice.
func countLinesInLineRangesExcept(codeLines map[int]bool, ranges, excluded []lineRange) int {
	if len(codeLines) == 0 || len(ranges) == 0 {
		return 0
	}
	skip := map[int]bool{}
	for _, r := range excluded {
		for line := r.start; line <= r.end; line++ {
			skip[line] = true
		}
	}
	lines := map[int]bool{}
	for _, r := range ranges {
		for line := r.start; line <= r.end; line++ {
			if codeLines[line] && !skip[line] {
				lines[line] = true
			}
		}
	}
	return len(lines)
}

// countLinesInLineRanges counts unique code-bearing lines inside the supplied
// ranges so nested literals cannot subtract the same fixture row twice.
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

// codeBearingLines runs go/scanner over the source and returns the set of
// 1-based line numbers that hold at least one non-comment, non-whitespace
// token. Blank lines, doc-only lines, and lines inside `/* */` blocks are
// excluded. Returns nil for non-Go input or empty source.
func codeBearingLines(src string) map[int]bool {
	if src == "" {
		return nil
	}
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	// Suppress scanner errors: this rule should never fail because a partial
	// parse left junk behind; we only want token-line positions.
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

// countLinesInRange counts how many lines in [start, end] are code-bearing
// according to codeLines (built once per file by codeBearingLines). A nil
// codeLines means "the scanner failed for this file" - we return 0 so the
// caller can detect that case and fall back to the raw span; if we silently
// returned end-start+1 instead, a parse-broken file would still report
// realistic length numbers and mask the underlying failure.
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
