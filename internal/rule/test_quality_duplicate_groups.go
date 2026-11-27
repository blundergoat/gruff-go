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
//
// It groups four or more runnable tests in one _test.go file when their bodies differ only in eligible literals.
// Each body must have at least four non-empty statements and no case loop the rule recognizes.
// The advisory finding sits on the first test and lists every member, so the user can fold them into one table-driven test.
type DuplicateTestBodyRule struct{}

// Definition enables calibrated duplicate groups unless a project opts out.
// It returns the fixed test-quality.duplicate-test-body definition: an advisory, low-confidence parser rule that is enabled by default.
func (DuplicateTestBodyRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.duplicate-test-body",
		Title:          "Duplicate test body",
		Description:    "Groups four or more runnable tests in one file whose multi-statement bodies differ only in eligible literal values.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceLow,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Tags:           []string{"tests"},
		Remediation:    "Go table-driven case loop: put the varying inputs and expected values in a case table, then run the shared assertions for each named case with t.Run.",
		FalsePositiveShapes: []FalsePositiveShape{{
			Shape:      "Separate tests can describe distinct behaviours even when their bodies have the same structure.",
			Mitigation: "Keep separate tests when a shared case loop would obscure their intent; review every listed member before consolidating.",
		}},
	}
}

// AnalyzeUnit emits one finding per complete group, anchored at its first test.
//
// unit is one parsed file; a file whose path lacks the _test.go suffix, or that has no AST or file set, is skipped.
// It returns one finding per group of at least four tests sharing a body key, in first-seen order, and nil when no group is that large.
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
		// Recording each key on first sight keeps findings in source order, since Go map iteration order changes between runs.
		if len(groups[key]) == 0 {
			order = append(order, key)
		}
		groups[key] = append(groups[key], fn)
	}
	var findings []finding.Finding
	for _, key := range order {
		if len(groups[key]) >= duplicateTestMinimumGroupSize {
			findings = append(findings, duplicateTestGroupFinding(unit, groups[key]))
		}
	}
	return findings
}

// duplicateTestMinimumGroupSize applies section 16's Go floor before suggesting a shared case loop.
//
// Three look-alike tests in one file get no finding; a fourth makes the group a finding.
const duplicateTestMinimumGroupSize = 4

// duplicateTestMinimumStatements is section 16's Go member minimum for a test body.
//
// A Go check is a two-statement call-and-compare, so a one- to three-statement test is one named case whose table form reads no better.
const duplicateTestMinimumStatements = 4

// duplicateTestCandidate excludes runner variants, bodies below the member minimum and existing case loops.
//
// fn is a top-level function declaration, and testingPackages holds the names the testing package is imported under, with "." for a dot import.
// It returns true when testFunctionReceiverKind maps the name to T, fn is runnable, and its body has at least four non-empty statements.
// Any other function, a nil body, or a body that already has a case loop gives false.
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
	return statements >= duplicateTestMinimumStatements && !duplicateTestHasCaseLoop(fn)
}

// duplicateTestGroupFinding keeps every member location available for review.
//
// unit supplies the file path and the file set that resolves each member's line and column.
// members is the group in source order and must not be empty, because its first test anchors the finding.
//
// It returns a finding with a message naming every member and metadata holding groupSize and each member's symbol, line and column.
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
//
// AST positions keep literals under keys, indices, slice bounds and local type declarations exact.
// unit supplies the file set and source text that body spans, and body is the test block whose tokens are rescanned in order.
//
// It returns the hex SHA-256 digest of each token's kind and normalized value, so bodies that differ only in normalized literals share a key.
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
		// Literals under a key, index, slice bound or local type declaration stay exact, so tests that differ there land in separate groups.
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
//
// kind is the scanned token kind and value its source text.
// builtin marks an identifier with no resolved object, so a locally declared true or false is kept as written.
//
// It returns "literal" for numeric and character tokens and for strings without ASCII whitespace, and the decoded text of any other string.
// A builtin true or false yields a NUL-prefixed boolean marker, and any other token yields value unchanged.
// The caller hashes kind beside this value, which is what keeps an integer literal apart from a string literal.
func duplicateTestLiteralValue(kind token.Token, value string, builtin bool) string {
	switch kind {
	case token.INT, token.FLOAT, token.IMAG, token.CHAR:
		return "literal"
	case token.STRING:
		decoded, _ := strconv.Unquote(value)
		// A string with ASCII whitespace, such as an expected error message, stays exact, so tests that differ in it are not grouped.
		if strings.ContainsAny(decoded, " \t\n\r\f\v") {
			return decoded
		}
		return "literal"
	case token.IDENT:
		// Eligible builtin true and false values share one marker, so boolean-only value changes can still join a duplicate group.
		if builtin && (value == "true" || value == "false") {
			return "\x00boolean"
		}
	}
	return value
}

// duplicateTestLiteralPositions marks value-sensitive contexts and unshadowed builtins.
//
// body is the test block, walked in full including nested function literals.
//
// It returns retained, holding the positions of literals and unresolved identifiers under a key, index, slice bound or local type declaration.
// It also returns builtins, which maps every identifier position to true when that identifier has no resolved object and to false otherwise.
// An empty retained map leaves every literal in body open to normalization.
func duplicateTestLiteralPositions(body *ast.BlockStmt) (map[token.Pos]bool, map[token.Pos]bool) {
	retained := map[token.Pos]bool{}
	builtins := map[token.Pos]bool{}
	ast.Inspect(body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.GenDecl:
			// Section 16 keeps a type declared in the body exact, since its struct tags and array lengths are structure a case table cannot carry.
			// Local constants and variables still normalize as values.
			if value.Tok == token.TYPE {
				duplicateTestRetainLiterals(value, retained)
			}
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

// duplicateTestRetainLiterals protects all literal descendants of a key, index, slice bound or local type declaration.
//
// root is the key, index, slice bound or type declaration to walk, and a nil root changes nothing.
// retained gains the position of every basic literal and every identifier with no resolved object under root.
func duplicateTestRetainLiterals(root ast.Node, retained map[token.Pos]bool) {
	// An omitted slice bound arrives here as nil and has no literal to keep exact, so it adds no constraint to grouping.
	if root == nil {
		return
	}
	ast.Inspect(root, func(node ast.Node) bool {
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

// duplicateTestHasCaseLoop finds a test that already runs a case loop, which keeps it out of every duplicate group.
//
// Every function literal is skipped, called or not, so a loop inside a closure never counts.
// fn is the candidate test, and the objects of all its declared parameters are the receivers whose Run calls mark a subtest loop.
// It returns true when a range or for loop walks a visible case table or calls Run on one of those parameters, and false otherwise.
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
//
// body is a loop body searched outside nested function literals, and receivers holds the objects of the test's declared parameters.
// It returns true when body calls Run directly on an identifier bound to one of receivers, and false for any other call or receiver.
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
//
// expr is the ranged or measured expression, body the enclosing test body, and before the loop position that bounds the writes examined.
//
// It returns true for a literal table, or for a variable whose declaration or latest tracked top-level write before that position holds one.
// Only assignment statements and value specs are tracked; nested ones hide the value until a later top-level write, and closures are skipped.
// Any other expression, or a variable whose value is unknown, gives false.
func duplicateTestTableSource(expr ast.Expr, body *ast.BlockStmt, before token.Pos) bool {
	expr = ast.Unparen(expr)
	if duplicateTestTableLiteral(expr) {
		return true
	}
	name, ok := expr.(*ast.Ident)
	// A table from a call, a field or another file is not visible here; a Run call on the test parameter can still mark the loop.
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
//
// body is the test block; only its direct statements and the specs of its direct declaration statements are marked.
// It returns a set holding each marked node as true, so a node missing from it, such as an assignment inside a branch, is nested.
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
//
// node is any AST node and object the resolved variable sought; a shadowing variable of the same name has a different object and never matches.
//
// It returns the assigned expression and true when node is an assignment or value spec that writes object.
// The expression is nil when values cannot be paired one to one, as in a multi-value call or a declaration without values.
// Any other node gives nil and false.
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
//
// loop is the for statement to inspect, and body is the enclosing test body used to confirm the table holds a visible literal.
// It returns true only when the condition is index < len(table) with unshadowed builtin len and the post step increments the same index.
// The loop body must also index the visible table with that index outside function literals; otherwise it returns false.
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
//
// bound must be a call to the unshadowed builtin len on one table variable, and counter must be the loop index identifier.
// loopBody is searched outside function literals for the table indexed by counter.
// testBody is the enclosing test block, and before is the loop position that bounds the search for writes to the table.
//
// It returns true only when the table is a visible literal table and all of these hold, and false otherwise.
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
//
// expr may be nil or any expression; parentheses and a leading address-of operator are looked through.
// It returns true for a composite literal whose written type is an array, slice or map, and false otherwise, including for a named table type.
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
