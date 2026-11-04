// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements an opt-in parser-only rule for tests that assert static code shape instead of runtime behaviour.
// It flags an if statement whose condition compares reflect.TypeOf(T{}) Kind, Name, NumField, or a FieldByName lookup with what T declares.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// StaticAnalysisRedundantTestRule flags unit-test assertions whose main evidence is a parser-visible static declaration fact.
//
// It ships disabled by default as test-quality.static-analysis-redundant-test, so default scans never show its findings.
// Each candidate carries the assertion, the static fact, and the declaration's file and line as proof.
type StaticAnalysisRedundantTestRule struct{}

// Definition declares the opt-in static-analysis-redundant test candidate rule.
// It returns the rule metadata for test-quality.static-analysis-redundant-test: advisory severity, high confidence, and disabled by default.
func (StaticAnalysisRedundantTestRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.static-analysis-redundant-test",
		Title:          "Static-analysis-redundant test candidate",
		Description:    "Flags Go unit-test assertions whose main evidence is a parser-visible static code-shape fact rather than runtime behaviour.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Tags:           []string{"candidate", "tests"},
		Remediation:    "Remove the redundant assertion if it is the only behaviour under test, or replace it with an assertion about runtime behaviour or meaningful values.",
	}
}

// AnalyzeProject emits findings for test assertions that restate parser-visible declaration facts from the same package.
//
// units holds the parsed files; each one with an AST feeds the declaration index, and only test files are inspected for findings.
// It returns one finding per assertion-shaped if statement that restates a declaration fact, and an empty, non-nil slice when none do.
func (StaticAnalysisRedundantTestRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	index := newStaticFactIndex(units)
	findings := []finding.Finding{}
	for _, unit := range units {
		if unit.AST == nil || unit.FileSet == nil || !isGoTestFile(unit.File.Path) {
			continue
		}
		group := index.groupForUnit(unit)
		if group == nil {
			continue
		}
		findings = append(findings, staticFactFindingsForUnit(unit, group)...)
	}
	return findings
}

// staticFactIndex stores parser-visible declarations by package boundary.
//
// Groups are keyed by directory and package clause name, so an external x_test package is a separate group from package x.
// Its tests are checked only against types declared in x_test files, never against package x.
type staticFactIndex struct {
	groups map[packageReferenceKey]*staticFactPackage
}

// staticFactPackage stores declarations the rule can prove without type loading.
type staticFactPackage struct {
	types map[string]staticFactTypeDecl
}

// staticFactTypeDecl records one named type declaration and its direct struct fields.
type staticFactTypeDecl struct {
	unit       parser.Unit
	name       string
	pos        token.Pos
	kind       string
	fieldCount int
	fields     map[string]staticFactFieldDecl
}

// staticFactFieldDecl records one direct struct field declaration.
type staticFactFieldDecl struct {
	unit parser.Unit
	name string
	pos  token.Pos
}

// staticFactCandidate carries a single assertion candidate and its source proof.
type staticFactCandidate struct {
	assertion      string
	staticFact     string
	staticFactFile string
	staticFactLine int
	confidence     finding.Confidence
	confidenceWhy  string
	location       finding.Location
	testFunction   string
}

// staticFactExpression represents a declaration-backed expression used in an assertion.
type staticFactExpression struct {
	kind      string
	typeDecl  staticFactTypeDecl
	wantText  string
	wantInt   int
	factText  string
	proofLine int
}

// staticFactAssertionContext carries package proof state while inspecting one test function.
type staticFactAssertionContext struct {
	unit            parser.Unit
	group           *staticFactPackage
	testFunction    string
	reflectPackages map[string]bool
}

// newStaticFactIndex builds the package declaration index for static test facts, from test and non-test files alike.
//
// units holds the parsed files; each one with an AST and package name joins the group for its directory and package name.
// It returns an index with one group per directory and package pair, holding its declared named types, and no groups when no unit qualifies.
func newStaticFactIndex(units []parser.Unit) staticFactIndex {
	index := staticFactIndex{groups: map[packageReferenceKey]*staticFactPackage{}}
	for _, unit := range units {
		if unit.AST == nil || unit.AST.Name == nil {
			continue
		}
		key := packageReferenceKey{dir: filepath.Dir(unit.File.Path), packageName: unit.AST.Name.Name}
		group := index.group(key)
		group.collectTypes(unit)
	}
	return index
}

// group returns the package group for key, creating and storing an empty one on first use, so the result is never nil.
func (i *staticFactIndex) group(key packageReferenceKey) *staticFactPackage {
	group, ok := i.groups[key]
	if ok {
		return group
	}
	group = &staticFactPackage{types: map[string]staticFactTypeDecl{}}
	i.groups[key] = group
	return group
}

// groupForUnit returns the package declaration group for unit, looked up by its directory and package clause name.
// It returns nil when unit has no AST or package name, or its package was never indexed, and AnalyzeProject then skips the file.
func (i staticFactIndex) groupForUnit(unit parser.Unit) *staticFactPackage {
	if unit.AST == nil || unit.AST.Name == nil {
		return nil
	}
	key := packageReferenceKey{dir: filepath.Dir(unit.File.Path), packageName: unit.AST.Name.Name}
	return i.groups[key]
}

// collectTypes records parser-visible named type declarations from unit.
// A type name declared in two files of one group keeps the last one seen, so its proof points at that file.
func (p *staticFactPackage) collectTypes(unit parser.Unit) {
	for _, decl := range unit.AST.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name == nil {
				continue
			}
			typeDecl := staticFactTypeDecl{
				unit:   unit,
				name:   typeSpec.Name.Name,
				pos:    typeSpec.Name.NamePos,
				kind:   staticFactKind(typeSpec.Type),
				fields: map[string]staticFactFieldDecl{},
			}
			if structType, ok := typeSpec.Type.(*ast.StructType); ok {
				typeDecl.collectStructFields(unit, structType)
			}
			p.types[typeDecl.name] = typeDecl
		}
	}
}

// collectStructFields records direct struct fields and counts embedded fields.
//
// structType is the declaration's struct type, and unit is the file it sits in, kept with each field for proof locations.
// Embedded fields named by an identifier, a selector, or a pointer to one are also recorded by name; a nil field list leaves d unchanged.
func (d *staticFactTypeDecl) collectStructFields(unit parser.Unit, structType *ast.StructType) {
	if structType.Fields == nil {
		return
	}
	for _, field := range structType.Fields.List {
		// An embedded field counts once toward NumField; only the type forms embeddedFieldName names get a FieldByName entry.
		if len(field.Names) == 0 {
			d.fieldCount++
			if name := embeddedFieldName(field.Type); name != "" {
				d.fields[name] = staticFactFieldDecl{unit: unit, name: name, pos: field.Pos()}
			}
			continue
		}
		for _, name := range field.Names {
			if name == nil {
				continue
			}
			d.fieldCount++
			d.fields[name.Name] = staticFactFieldDecl{unit: unit, name: name.Name, pos: name.NamePos}
		}
	}
}

// staticFactKind returns the reflect.Kind selector name for supported type shapes.
// expr is a type declaration's type; a struct gives Struct, an interface gives Interface, and any other shape gives an empty string.
func staticFactKind(expr ast.Expr) string {
	switch expr.(type) {
	case *ast.StructType:
		return "Struct"
	case *ast.InterfaceType:
		return "Interface"
	default:
		return ""
	}
}

// embeddedFieldName returns the declared field name for simple embedded fields.
//
// expr is the embedded field's type: a name gives itself, a pointer is unwrapped, and a selector gives its final name.
// Any other shape, such as a generic instantiation, gives an empty string.
func embeddedFieldName(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return embeddedFieldName(value.X)
	case *ast.SelectorExpr:
		return value.Sel.Name
	default:
		return ""
	}
}

// staticFactFindingsForUnit inspects runnable tests in one unit.
//
// group holds the declarations of the unit's package; only runnable tests with a body and at least one testing receiver name are inspected.
// It returns the findings of those tests in declaration order, and an empty, non-nil slice when none match.
func staticFactFindingsForUnit(unit parser.Unit, group *staticFactPackage) []finding.Finding {
	findings := []finding.Finding{}
	testingPackages := testingPackageNames(unit.AST)
	assertionPackages := assertionPackageNames(unit.AST)
	reflectPackages := reflectPackageNames(unit.AST)
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !isRunnableTestFunction(fn, testingPackages) || fn.Body == nil {
			continue
		}
		receivers := testingReceiverNames(fn, testingPackages)
		if len(receivers) == 0 {
			continue
		}
		ctx := staticFactAssertionContext{
			unit:            unit,
			group:           group,
			testFunction:    fn.Name.Name,
			reflectPackages: reflectPackages,
		}
		findings = append(findings, staticFactFindingsForFunction(ctx, fn, receivers, assertionPackages, testingPackages)...)
	}
	return findings
}

// staticFactFindingsForFunction inspects assertion-shaped if statements in one test.
//
// ctx carries the unit, package group, test name, and reflect qualifiers; fn is the test, and nested function literals are not entered.
// receivers, assertionPackages, and testingPackages let blockHasFailureCall recognise failure, assertion, or delegation calls in an if body.
// It returns one finding per such if statement that restates a static fact, and an empty, non-nil slice when none do.
func staticFactFindingsForFunction(ctx staticFactAssertionContext, fn *ast.FuncDecl, receivers, assertionPackages, testingPackages map[string]bool) []finding.Finding {
	findings := []finding.Finding{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if node == nil {
			return true
		}
		// If statements inside a t.Run closure or other function literal are skipped, so a subtest's static-fact check is never reported.
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		stmt, ok := node.(*ast.IfStmt)
		// Only an if whose body shows failure evidence counts as an assertion, and that evidence may be an unread delegated or helper call.
		if !ok || !blockHasFailureCall(stmt.Body, testingPackages, assertionPackages, receivers) {
			return true
		}
		candidate, ok := staticFactCandidateFromIf(ctx, stmt)
		if !ok {
			return true
		}
		findings = append(findings, candidate.finding(ctx.unit.File.Path))
		return true
	})
	return findings
}

// staticFactCandidateFromIf extracts a candidate from one assertion-shaped if statement.
//
// ctx carries the unit, package group, and test name; stmt is the if statement, tried first as a missing-field check, then as a fact comparison.
// It returns the candidate and true on a match, and a zero candidate and false otherwise.
func staticFactCandidateFromIf(ctx staticFactAssertionContext, stmt *ast.IfStmt) (staticFactCandidate, bool) {
	facts, okFacts := staticFactInitFacts(ctx, stmt.Init)
	if candidate, ok := candidateFromMissingFieldCheck(ctx, stmt, okFacts); ok {
		return candidate, true
	}
	candidate, ok := candidateFromStaticFactComparison(ctx, stmt, facts)
	return candidate, ok
}

// staticFactInitFacts extracts facts bound by an if statement's init clause.
//
// ctx supplies the package group and reflect qualifiers; init counts only when it is an assignment with one right-hand side.
// It returns two maps: identifiers bound to a fact expression, and the second identifier of a FieldByName lookup mapped to its candidate.
// Both maps are empty but non-nil when init is not such an assignment or binds nothing.
func staticFactInitFacts(ctx staticFactAssertionContext, init ast.Stmt) (map[string]staticFactExpression, map[string]staticFactCandidate) {
	facts := map[string]staticFactExpression{}
	okFacts := map[string]staticFactCandidate{}
	assign, ok := init.(*ast.AssignStmt)
	if !ok {
		return facts, okFacts
	}
	if len(assign.Rhs) == 1 {
		if fact, ok := staticFactExpressionFromExpr(ctx, assign.Rhs[0]); ok {
			for _, lhs := range assign.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
					facts[ident.Name] = fact
				}
			}
		}
		if candidate, ok := fieldByNameCandidateFromExpr(ctx, assign.Rhs[0]); ok && len(assign.Lhs) >= 2 {
			if ident, ok := assign.Lhs[1].(*ast.Ident); ok && ident.Name != "_" {
				okFacts[ident.Name] = candidate
			}
		}
	}
	return facts, okFacts
}

// candidateFromMissingFieldCheck recognises if _, ok := reflect.TypeOf(T{}).FieldByName("X"); !ok when T declares field X.
//
// The condition of stmt must negate an identifier found in okFacts, the ok variables staticFactInitFacts bound to FieldByName candidates.
// ctx supplies the unit and test name the candidate is stamped with; any other condition gives a zero candidate and false.
// It returns the candidate and true on a match, with its assertion and location set to the negated condition.
func candidateFromMissingFieldCheck(ctx staticFactAssertionContext, stmt *ast.IfStmt, okFacts map[string]staticFactCandidate) (staticFactCandidate, bool) {
	unary, ok := stmt.Cond.(*ast.UnaryExpr)
	if !ok || unary.Op != token.NOT {
		return staticFactCandidate{}, false
	}
	ident, ok := unary.X.(*ast.Ident)
	if !ok {
		return staticFactCandidate{}, false
	}
	candidate, ok := okFacts[ident.Name]
	if !ok {
		return staticFactCandidate{}, false
	}
	candidate.assertion = renderNode(ctx.unit.FileSet, stmt.Cond)
	candidate.location = locationForNode(ctx.unit, stmt.Cond)
	candidate.testFunction = ctx.testFunction
	return candidate, true
}

// candidateFromStaticFactComparison recognises if staticFact != declaredValue, with the fact on either side of the comparison.
//
// The condition of stmt must compare with != a fact expression, or an identifier in facts, against the value that fact declares.
// ctx supplies the package group, reflect qualifiers, unit, and test name; any other condition gives a zero candidate and false.
// It returns the matched candidate and true; an == comparison is never matched.
func candidateFromStaticFactComparison(ctx staticFactAssertionContext, stmt *ast.IfStmt, facts map[string]staticFactExpression) (staticFactCandidate, bool) {
	binary, ok := stmt.Cond.(*ast.BinaryExpr)
	if !ok || binary.Op != token.NEQ {
		return staticFactCandidate{}, false
	}
	if fact, ok := staticFactFromSide(ctx, binary.X, facts); ok && fact.matches(binary.Y, ctx.reflectPackages) {
		return fact.candidate(ctx.unit, ctx.testFunction, stmt.Cond), true
	}
	if fact, ok := staticFactFromSide(ctx, binary.Y, facts); ok && fact.matches(binary.X, ctx.reflectPackages) {
		return fact.candidate(ctx.unit, ctx.testFunction, stmt.Cond), true
	}
	return staticFactCandidate{}, false
}

// staticFactFromSide resolves either a direct fact expression or an init-bound identifier.
//
// An identifier expr is looked up in facts only, and any other expr is resolved against ctx as a reflect fact expression.
// It returns the fact and true when one resolves, and a zero fact and false otherwise.
func staticFactFromSide(ctx staticFactAssertionContext, expr ast.Expr, facts map[string]staticFactExpression) (staticFactExpression, bool) {
	if ident, ok := expr.(*ast.Ident); ok {
		fact, ok := facts[ident.Name]
		return fact, ok
	}
	return staticFactExpressionFromExpr(ctx, expr)
}

// staticFactExpressionFromExpr recognises reflect.TypeOf(T{}).Kind/Name/NumField.
//
// expr must be a Kind, Name, or NumField call with no arguments on a reflected type that the package group in ctx declares.
// Kind needs a struct or interface type and NumField a struct type; it returns the fact and true on a match, and a zero fact and false otherwise.
func staticFactExpressionFromExpr(ctx staticFactAssertionContext, expr ast.Expr) (staticFactExpression, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return staticFactExpression{}, false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) != 0 {
		return staticFactExpression{}, false
	}
	typeName, ok := reflectedCompositeTypeName(selector.X, ctx.reflectPackages)
	if !ok {
		return staticFactExpression{}, false
	}
	typeDecl, ok := ctx.group.types[typeName]
	if !ok {
		return staticFactExpression{}, false
	}
	switch selector.Sel.Name {
	case "Kind":
		if typeDecl.kind == "" {
			return staticFactExpression{}, false
		}
		return typeDecl.staticFactExpression("kind", "reflect."+typeDecl.kind, 0), true
	case "Name":
		return typeDecl.staticFactExpression("name", typeDecl.name, 0), true
	case "NumField":
		if typeDecl.kind != "Struct" {
			return staticFactExpression{}, false
		}
		return typeDecl.staticFactExpression("numField", strconv.Itoa(typeDecl.fieldCount), typeDecl.fieldCount), true
	default:
		return staticFactExpression{}, false
	}
}

// staticFactExpression builds a proof-bearing fact expression for a type declaration.
//
// kind names the fact, one of kind, name, or numField; wantText is the expected value as text and wantInt the expected count for numField.
// It returns the expression carrying factText for kind and the line of the declaration as proof.
func (d staticFactTypeDecl) staticFactExpression(kind, wantText string, wantInt int) staticFactExpression {
	position := d.unit.FileSet.Position(d.pos)
	return staticFactExpression{
		kind:      kind,
		typeDecl:  d,
		wantText:  wantText,
		wantInt:   wantInt,
		factText:  d.factText(kind),
		proofLine: position.Line,
	}
}

// factText describes one static fact in finding metadata.
// It returns a sentence about d for kind, which is kind, name, or numField; any other kind gives a generic parser-visible declaration sentence.
func (d staticFactTypeDecl) factText(kind string) string {
	switch kind {
	case "kind":
		return fmt.Sprintf("%s is declared as a %s type", d.name, strings.ToLower(d.kind))
	case "name":
		return fmt.Sprintf("%s is declared with name %q", d.name, d.name)
	case "numField":
		return fmt.Sprintf("%s declares %d direct struct fields", d.name, d.fieldCount)
	default:
		return fmt.Sprintf("%s has a parser-visible declaration", d.name)
	}
}

// matches reports whether expr equals the parser-visible static value.
//
// reflectPackages holds the qualifiers for package reflect, which a kind fact needs to match a reflect Kind selector.
// A name fact needs an equal string literal, a numField fact an integer literal whose base-10 text equals the count, and other kinds never match.
func (e staticFactExpression) matches(expr ast.Expr, reflectPackages map[string]bool) bool {
	switch e.kind {
	case "kind":
		return isReflectKindSelector(expr, reflectPackages, strings.TrimPrefix(e.wantText, "reflect."))
	case "name":
		value, ok := stringLiteralValue(expr)
		return ok && value == e.wantText
	case "numField":
		value, ok := intLiteralValue(expr)
		return ok && value == e.wantInt
	default:
		return false
	}
}

// candidate converts a matched comparison fact into a finding candidate.
//
// expr is the matched condition, rendered and located in unit, and testFunction names the test that holds it.
// It returns a high-confidence candidate carrying the fact text and the declaration's file and line as proof.
func (e staticFactExpression) candidate(unit parser.Unit, testFunction string, expr ast.Expr) staticFactCandidate {
	return staticFactCandidate{
		assertion:      renderNode(unit.FileSet, expr),
		staticFact:     e.factText,
		staticFactFile: e.typeDecl.unit.File.Path,
		staticFactLine: e.proofLine,
		confidence:     finding.ConfidenceHigh,
		confidenceWhy:  "direct parser-visible declaration fact",
		location:       locationForNode(unit, expr),
		testFunction:   testFunction,
	}
}

// fieldByNameCandidateFromExpr recognises reflect.TypeOf(T{}).FieldByName("X").
//
// expr must call FieldByName with one string literal on a reflected struct type that the package group in ctx declares with that field.
// It returns the candidate and true, with the field's file and line as proof but no assertion or location, or a zero candidate and false.
func fieldByNameCandidateFromExpr(ctx staticFactAssertionContext, expr ast.Expr) (staticFactCandidate, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return staticFactCandidate{}, false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "FieldByName" {
		return staticFactCandidate{}, false
	}
	fieldName, ok := stringLiteralValue(call.Args[0])
	if !ok {
		return staticFactCandidate{}, false
	}
	typeName, ok := reflectedCompositeTypeName(selector.X, ctx.reflectPackages)
	if !ok {
		return staticFactCandidate{}, false
	}
	typeDecl, ok := ctx.group.types[typeName]
	if !ok || typeDecl.kind != "Struct" {
		return staticFactCandidate{}, false
	}
	field, ok := typeDecl.fields[fieldName]
	if !ok {
		return staticFactCandidate{}, false
	}
	position := field.unit.FileSet.Position(field.pos)
	return staticFactCandidate{
		staticFact:     fmt.Sprintf("%s declares field %q", typeDecl.name, field.name),
		staticFactFile: field.unit.File.Path,
		staticFactLine: position.Line,
		confidence:     finding.ConfidenceHigh,
		confidenceWhy:  "direct parser-visible struct field declaration",
	}, true
}
