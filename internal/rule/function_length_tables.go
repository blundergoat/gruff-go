// Package rule defines gruff-go's rule registry and analysers.
package rule

import (
	"go/ast"
	"go/scanner"
	"go/token"
	"strings"
)

// funcDeclsBySymbol indexes top-level function declarations using the same
// symbol spelling as parser.Function and funcDeclSymbol.
func funcDeclsBySymbol(file *ast.File) map[string]*ast.FuncDecl {
	out := map[string]*ast.FuncDecl{}
	if file == nil {
		return out
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		out[funcDeclSymbol(fn)] = fn
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

// countLinesInRange returns how many lines in [start, end] are code-bearing.
// When codeLines is nil the caller substitutes the raw span, so we don't
// silently emit zero-length findings.
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

// funlenNolintNames walks the file's function declarations and returns the
// symbols carrying a directly attached `//nolint:funlen` or `//nolint:all`
// directive in their doc comment.
func funlenNolintNames(file *ast.File) map[string]bool {
	out := map[string]bool{}
	if file == nil {
		return out
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Doc == nil {
			continue
		}
		if !docMentionsFunlenNolint(fn.Doc) {
			continue
		}
		out[funcDeclSymbol(fn)] = true
	}
	return out
}

// docMentionsFunlenNolint reports whether a comment group contains a
// function-length suppression entry such as `//nolint:funlen`.
func docMentionsFunlenNolint(doc *ast.CommentGroup) bool {
	for _, c := range doc.List {
		text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		if !strings.HasPrefix(text, "nolint") {
			continue
		}
		rest := strings.TrimPrefix(text, "nolint")
		if rest == "" {
			return true
		}
		if rest[0] != ':' {
			continue
		}
		rest = rest[1:]
		if i := strings.IndexAny(rest, " \t/"); i >= 0 {
			rest = rest[:i]
		}
		for _, name := range strings.Split(rest, ",") {
			name = strings.TrimSpace(name)
			if name == "funlen" || name == "all" {
				return true
			}
		}
	}
	return false
}

// funcDeclSymbol mirrors parser.functions' Name construction so nolint
// lookups align with the symbols attached to parser.Function entries.
func funcDeclSymbol(fn *ast.FuncDecl) string {
	name := fn.Name.Name
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return name
	}
	switch expr := fn.Recv.List[0].Type.(type) {
	case *ast.Ident:
		return expr.Name + "." + name
	case *ast.StarExpr:
		if ident, ok := expr.X.(*ast.Ident); ok {
			return ident.Name + "." + name
		}
	}
	return "receiver." + name
}
