package rule

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/scanner"
	"go/token"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// DuplicateTestBodyRule finds same-file test groups that could share a case loop.
type DuplicateTestBodyRule struct{}

// Definition keeps the candidate rule opt-in until its precision is measured.
func (DuplicateTestBodyRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.duplicate-test-body",
		Title:          "Duplicate test body",
		Description:    "Groups three or more runnable tests in one file whose multi-statement bodies differ only in eligible literal values.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceLow,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Tags:           []string{"tests"},
		Remediation:    "Go table-driven case loop: put the varying inputs and expected values in a case table, then run the shared assertions for each named case with t.Run.",
		FalsePositiveShapes: []FalsePositiveShape{{
			Shape:      "Separate tests can describe distinct behaviours even when their bodies have the same structure.",
			Mitigation: "Keep separate tests when a shared case loop would obscure their intent; review every listed member before consolidating.",
		}},
	}
}

// AnalyzeUnit emits one finding per complete group, anchored at its first test.
func (DuplicateTestBodyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") {
		return nil
	}
	groups := map[string][]*ast.FuncDecl{}
	var order []string
	testingPackages := testingPackageNames(unit.AST)
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !duplicateTestCandidate(fn, testingPackages) {
			continue
		}
		key := duplicateTestBodyKey(unit, fn.Body)
		if len(groups[key]) == 0 {
			order = append(order, key)
		}
		groups[key] = append(groups[key], fn)
	}
	var findings []finding.Finding
	for _, key := range order {
		if len(groups[key]) >= 3 {
			findings = append(findings, duplicateTestGroupFinding(unit, groups[key]))
		}
	}
	return findings
}

// duplicateTestCandidate excludes runner variants, trivial bodies and existing case loops.
func duplicateTestCandidate(fn *ast.FuncDecl, testingPackages map[string]bool) bool {
	kind, _ := testFunctionReceiverKind(fn.Name.Name)
	if kind != "T" || !isRunnableTestFunction(fn, testingPackages) || fn.Body == nil {
		return false
	}
	statements := 0
	for _, stmt := range fn.Body.List {
		if _, empty := stmt.(*ast.EmptyStmt); !empty {
			statements++
		}
	}
	return statements >= 2 && !duplicateTestHasCaseLoop(fn)
}

// duplicateTestGroupFinding keeps every member location available for review.
func duplicateTestGroupFinding(unit parser.Unit, members []*ast.FuncDecl) finding.Finding {
	locations := make([]map[string]any, 0, len(members))
	labels := make([]string, 0, len(members))
	for _, member := range members {
		pos := unit.FileSet.Position(member.Name.Pos())
		locations = append(locations, map[string]any{"symbol": member.Name.Name, "line": pos.Line, "column": pos.Column})
		labels = append(labels, fmt.Sprintf("%s (line %d, column %d)", member.Name.Name, pos.Line, pos.Column))
	}
	first := unit.FileSet.Position(members[0].Name.Pos())
	return finding.Finding{
		Message:  fmt.Sprintf("%d tests share a body after literal normalization: %s. Consider a Go table-driven case loop with a descriptive label per case.", len(members), strings.Join(labels, ", ")),
		File:     unit.File.Path,
		Location: &finding.Location{Line: first.Line, Column: first.Column},
		Symbol:   members[0].Name.Name,
		Metadata: map[string]any{"groupSize": len(members), "members": locations},
	}
}

// duplicateTestBodyKey preserves names and operators without mutating the shared AST.
// AST positions protect literal descendants of keys, indices and slice bounds.
func duplicateTestBodyKey(unit parser.Unit, body *ast.BlockStmt) string {
	start := unit.FileSet.Position(body.Pos()).Offset
	end := unit.FileSet.Position(body.End()).Offset
	retained, builtins := duplicateTestLiteralPositions(body)
	file := token.NewFileSet().AddFile("", -1, end-start)
	var scan scanner.Scanner
	scan.Init(file, []byte(unit.Source[start:end]), nil, 0)
	hash := sha256.New()
	for {
		pos, kind, value := scan.Scan()
		if kind == token.EOF {
			break
		}
		original := body.Pos() + token.Pos(file.Offset(pos))
		if !retained[original] {
			value = duplicateTestLiteralValue(kind, value, builtins[original])
		} else if kind == token.STRING || kind == token.CHAR {
			value, _ = strconv.Unquote(value)
		}
		// Both inserted and explicit semicolons delimit the same statements.
		if kind == token.SEMICOLON {
			value = ";"
		}
		fmt.Fprintf(hash, "%d:%q;", kind, value)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// duplicateTestLiteralValue preserves whitespace strings and distinguishes literal kinds.
func duplicateTestLiteralValue(kind token.Token, value string, builtin bool) string {
	switch kind {
	case token.INT, token.FLOAT, token.IMAG, token.CHAR:
		return "literal"
	case token.STRING:
		decoded, _ := strconv.Unquote(value)
		if strings.ContainsAny(decoded, " \t\n\r\f\v") {
			return decoded
		}
		return "literal"
	case token.IDENT:
		if builtin && (value == "true" || value == "false") {
			return "\x00boolean"
		}
	}
	return value
}

// duplicateTestLiteralPositions marks value-sensitive contexts and unshadowed builtins.
func duplicateTestLiteralPositions(body *ast.BlockStmt) (map[token.Pos]bool, map[token.Pos]bool) {
	retained := map[token.Pos]bool{}
	builtins := map[token.Pos]bool{}
	ast.Inspect(body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.KeyValueExpr:
			duplicateTestRetainLiterals(value.Key, retained)
		case *ast.IndexExpr:
			duplicateTestRetainLiterals(value.Index, retained)
		case *ast.IndexListExpr:
			for _, index := range value.Indices {
				duplicateTestRetainLiterals(index, retained)
			}
		case *ast.SliceExpr:
			duplicateTestRetainLiterals(value.Low, retained)
			duplicateTestRetainLiterals(value.High, retained)
			duplicateTestRetainLiterals(value.Max, retained)
		case *ast.Ident:
			builtins[value.Pos()] = value.Obj == nil
		}
		return true
	})
	return retained, builtins
}

// duplicateTestRetainLiterals protects all literal descendants of a key or index expression.
func duplicateTestRetainLiterals(expr ast.Expr, retained map[token.Pos]bool) {
	if expr == nil {
		return
	}
	ast.Inspect(expr, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.BasicLit:
			retained[value.Pos()] = true
		case *ast.Ident:
			if value.Obj == nil {
				retained[value.Pos()] = true
			}
		}
		return true
	})
}

// duplicateTestHasCaseLoop ignores unused closures when looking for existing case loops.
func duplicateTestHasCaseLoop(fn *ast.FuncDecl) bool {
	receivers := map[*ast.Object]bool{}
	for _, param := range fn.Type.Params.List {
		for _, name := range param.Names {
			receivers[name.Obj] = true
		}
	}
	found := false
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		switch loop := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.RangeStmt:
			found = duplicateTestTableSource(loop.X, fn.Body, loop.Pos()) ||
				duplicateTestIndexedTable(loop.X, loop.Key, loop.Body, fn.Body, loop.Pos()) ||
				duplicateTestSubtestLoop(loop.Body, receivers)
		case *ast.ForStmt:
			found = duplicateTestCountedTable(loop, fn.Body) || duplicateTestSubtestLoop(loop.Body, receivers)
		}
		return !found
	})
	return found
}

// duplicateTestSubtestLoop binds Run calls to the test's declared testing.T parameter.
func duplicateTestSubtestLoop(body *ast.BlockStmt, receivers map[*ast.Object]bool) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Run" {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		found = found || ok && receiver.Obj != nil && receivers[receiver.Obj]
		return !found
	})
	return found
}

// duplicateTestTableSource accepts visible literal tables unless a later assignment obscures their value.
func duplicateTestTableSource(expr ast.Expr, body *ast.BlockStmt, before token.Pos) bool {
	expr = ast.Unparen(expr)
	if duplicateTestTableLiteral(expr) {
		return true
	}
	name, ok := expr.(*ast.Ident)
	if !ok || name.Obj == nil {
		return false
	}
	// Package declarations may follow the test. Local assignments below override this initial value.
	declaration, _ := name.Obj.Decl.(ast.Node)
	latest, _ := duplicateTestAssignedValue(declaration, name.Obj)
	straightLine := duplicateTestStraightLineNodes(body)
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil || node.Pos() >= before {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		if value, assigned := duplicateTestAssignedValue(node, name.Obj); assigned {
			latest = nil
			if straightLine[node] {
				latest = value
			}
		}
		return true
	})
	return duplicateTestTableLiteral(latest)
}

// duplicateTestStraightLineNodes distinguishes unconditional bindings from nested assignments.
func duplicateTestStraightLineNodes(body *ast.BlockStmt) map[ast.Node]bool {
	straightLine := map[ast.Node]bool{}
	for _, stmt := range body.List {
		straightLine[stmt] = true
		if decl, ok := stmt.(*ast.DeclStmt); ok {
			if general, ok := decl.Decl.(*ast.GenDecl); ok {
				for _, spec := range general.Specs {
					straightLine[spec] = true
				}
			}
		}
	}
	return straightLine
}

// duplicateTestAssignedValue finds writes to the exact variable, preserving shadowed names.
func duplicateTestAssignedValue(node ast.Node, object *ast.Object) (ast.Expr, bool) {
	switch value := node.(type) {
	case *ast.AssignStmt:
		for i, lhs := range value.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Obj == object {
				if len(value.Lhs) == len(value.Rhs) {
					return value.Rhs[i], true
				}
				return nil, true
			}
		}
	case *ast.ValueSpec:
		for i, id := range value.Names {
			if id.Obj == object {
				if len(value.Names) == len(value.Values) {
					return value.Values[i], true
				}
				return nil, true
			}
		}
	}
	return nil, false
}

// duplicateTestCountedTable recognizes an ascending index loop over a visible case table.
func duplicateTestCountedTable(loop *ast.ForStmt, body *ast.BlockStmt) bool {
	condition, ok := ast.Unparen(loop.Cond).(*ast.BinaryExpr)
	if !ok || condition.Op != token.LSS {
		return false
	}
	index, ok := ast.Unparen(condition.X).(*ast.Ident)
	if !ok || index.Obj == nil {
		return false
	}
	step, ok := loop.Post.(*ast.IncDecStmt)
	if !ok || step.Tok != token.INC {
		return false
	}
	stepped, ok := ast.Unparen(step.X).(*ast.Ident)
	return ok && stepped.Obj == index.Obj &&
		duplicateTestIndexedTable(condition.Y, index, loop.Body, body, loop.Pos())
}

// duplicateTestIndexedTable requires both the table's length and a lookup using the loop's index.
func duplicateTestIndexedTable(bound, counter ast.Expr, loopBody, testBody *ast.BlockStmt, before token.Pos) bool {
	index, ok := ast.Unparen(counter).(*ast.Ident)
	if !ok || index.Obj == nil {
		return false
	}
	length, ok := ast.Unparen(bound).(*ast.CallExpr)
	if !ok || len(length.Args) != 1 {
		return false
	}
	callee, ok := ast.Unparen(length.Fun).(*ast.Ident)
	if !ok || callee.Name != "len" || callee.Obj != nil {
		return false
	}
	table, ok := ast.Unparen(length.Args[0]).(*ast.Ident)
	if !ok || !duplicateTestTableSource(table, testBody, before) {
		return false
	}
	found := false
	ast.Inspect(loopBody, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		if lookup, ok := node.(*ast.IndexExpr); ok {
			value, valueOK := ast.Unparen(lookup.X).(*ast.Ident)
			key, keyOK := ast.Unparen(lookup.Index).(*ast.Ident)
			found = found || valueOK && keyOK && value.Obj == table.Obj && key.Obj == index.Obj
		}
		return !found
	})
	return found
}

// duplicateTestTableLiteral recognizes array, slice and map tables, including address forms.
func duplicateTestTableLiteral(expr ast.Expr) bool {
	switch value := expr.(type) {
	case *ast.ParenExpr:
		return duplicateTestTableLiteral(value.X)
	case *ast.UnaryExpr:
		return value.Op == token.AND && duplicateTestTableLiteral(value.X)
	case *ast.CompositeLit:
		switch value.Type.(type) {
		case *ast.ArrayType, *ast.MapType:
			return true
		}
	}
	return false
}
