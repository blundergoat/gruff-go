// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds parser-only maintainability checks for ignored errors, context.TODO and panics in production code.
// They read syntax only, so a finding marks a likely shape rather than a type-checked fact.
package rule

import (
	"go/ast"
	"path"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// IgnoredErrorRule flags direct assignments of error-looking values to the blank identifier, as rule maintainability.ignored-error.
//
// A value counts by its name, such as err or parseError, or as an errors.New or fmt.Errorf call; types are never resolved.
type IgnoredErrorRule struct{}

// Definition declares the maintainability.ignored-error rule for explicit ignored error values.
// It returns the same populated Definition on every call: maintainability pillar, advisory severity, medium confidence, enabled by default.
func (IgnoredErrorRule) Definition() Definition {
	return Definition{
		ID:             "maintainability.ignored-error",
		Title:          "Ignored error",
		Description:    "Flags error-looking values that are assigned directly to the blank identifier.",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"errors"},
		Remediation:    "Handle the error, return it to the caller, or document why ignoring it is safe.",
	}
}

// AnalyzeUnit emits findings for direct _ = err style assignments in one parsed file.
//
// It stays conservative because parser-only analysis cannot prove arbitrary call return types without type information.
// unit is that file; assignments with unequal left and right counts are skipped, so a blank from a multi-value call is never reported.
//
// It returns one finding per error-looking blank, recording the expression and evidence kind, and nil when unit has no AST or FileSet.
func (IgnoredErrorRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	errorsPackages := packageImportNames(unit.AST, "errors", "errors")
	fmtPackages := packageImportNames(unit.AST, "fmt", "fmt")
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for index, lhs := range assign.Lhs {
			if !isBlankIdent(lhs) {
				continue
			}
			expr, evidence, ok := ignoredErrorEvidence(assign.Rhs[index], errorsPackages, fmtPackages)
			if !ok {
				continue
			}
			position := unit.FileSet.Position(lhs.Pos())
			findings = append(findings, finding.Finding{
				Message:  "error value is assigned to the blank identifier",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Metadata: map[string]any{
					"expression": formatExpr(expr),
					"evidence":   evidence,
				},
			})
		}
		return true
	})
	return findings
}

// ContextTODOProductionRule flags context.TODO calls in production code, as rule maintainability.context-todo-production.
//
// Test files and testdata or example paths are exempt; elsewhere cancellation ownership should be explicit.
type ContextTODOProductionRule struct{}

// Definition declares the maintainability.context-todo-production rule for TODO contexts outside tests and examples.
// It returns the same populated Definition on every call: maintainability pillar, advisory severity, high confidence, enabled by default.
func (ContextTODOProductionRule) Definition() Definition {
	return Definition{
		ID:             "maintainability.context-todo-production",
		Title:          "Context TODO in production",
		Description:    "Flags context.TODO calls in production files where cancellation ownership should be explicit.",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"context"},
		Remediation:    "Accept a caller-provided context or use a documented bootstrap context where cancellation is intentionally unavailable.",
	}
}

// AnalyzeUnit emits findings for context.TODO() calls outside test and example paths.
//
// unit is one parsed file; only calls through its own context import names count, and each finding records the rendered callee.
// It returns one finding per such call, nil for a non-production path, a missing AST or FileSet, or no usable context import.
func (ContextTODOProductionRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	contextPackages := packageImportNames(unit.AST, "context", "context")
	if len(contextPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !selectorCallMatches(call, contextPackages, "TODO") {
			return true
		}
		position := unit.FileSet.Position(call.Pos())
		findings = append(findings, finding.Finding{
			Message:  "context.TODO used in production code",
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Metadata: map[string]any{"call": formatExpr(call.Fun)},
		})
		return true
	})
	return findings
}

// ProductionPanicRule flags qualifying literal and constructed panic messages outside tests and bootstrap code.
//
// A package with any function body that calls recover and assigns through a pointer is skipped whole, as a likely panic-to-error boundary.
type ProductionPanicRule struct{}

// Definition declares the maintainability.production-panic rule for concrete production panic sites.
// It returns the same populated Definition on every call: maintainability pillar, advisory severity, medium confidence, enabled by default.
func (ProductionPanicRule) Definition() Definition {
	return Definition{
		ID:             "maintainability.production-panic",
		Title:          "Production panic",
		Description:    "Flags direct literal panic calls in non-test, non-main production code.",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"errors"},
		Remediation:    "Return an error or fail during command/bootstrap setup instead of panicking from reusable production code.",
	}
}

// AnalyzeProject emits findings for production panics with literal or constructed messages, outside packages with a recovery boundary.
//
// A recovery boundary is any function body in the package that calls recover and assigns through a pointer, a syntactic signal only.
// Judging the whole package sees an entry-point handler beside panics in sibling files, as in promql query evaluation.
//
// units holds the scan's parsed files, grouped per directory and package name; test, testdata, example, main-package and cmd files are left out.
// A constructed message is a Sprintf, Errorf or New call passed straight to panic, as panicHasLiteralEvidence accepts it.
// Functions named init, main or Defaults, Must-prefixed functions and panics inside function literals are skipped.
//
// It returns findings by first-seen package group, preserving file order within each group, and an empty non-nil slice when none qualify.
func (ProductionPanicRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	findings := []finding.Finding{}
	for _, group := range groupProductionUnitsByPackage(units) {
		// One recover-and-pointer-store body anywhere in the package silences every panic finding in it, even panics that handler never covers.
		if group.declaresRecoveryBoundary() {
			continue
		}
		for _, unit := range group.units {
			findings = append(findings, productionPanicFindingsForUnit(unit)...)
		}
	}
	return findings
}

// productionPanicFindingsForUnit reports one file's panic calls whose literal or constructed message panicHasLiteralEvidence accepts.
//
// unit must carry an AST and FileSet; functions named init, main, Defaults or Must-prefixed are skipped, as are panics in function literals.
// Each finding carries the enclosing function as its symbol, and the result is an empty non-nil slice when nothing qualifies.
func productionPanicFindingsForUnit(unit parser.Unit) []finding.Finding {
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || productionPanicFunctionExempt(fn.Name.Name) {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			// A panic inside a closure, such as a goroutine or deferred func body, is never reported by this rule.
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok || !isDirectPanicCall(call) || !panicHasLiteralEvidence(call) {
				return true
			}
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				// Sprintf, Errorf and New arguments get constructed-message wording, so the finding describes the matched expression.
				Message:  panicFindingMessage(call),
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   functionName(fn),
			})
			return true
		})
	}
	return findings
}

// productionPackageGroup is the production files of one Go package, keyed by directory and package name.
//
// It is the scope a recovery boundary is judged in: one qualifying recover body anywhere in the group exempts every panic in its files.
type productionPackageGroup struct {
	units []parser.Unit
}

// groupProductionUnitsByPackage buckets production files by the package they compile into, keyed by directory plus package name.
//
// units is the scan's parsed files; files lacking an AST, FileSet or package name are dropped.
// Test, testdata, example, main-package and cmd files are dropped, so a bootstrap file cannot lend its recovery boundary to a judged package.
//
// It returns one group per package in first-seen order with files in input order, and an empty non-nil slice when nothing survives.
func groupProductionUnitsByPackage(units []parser.Unit) []productionPackageGroup {
	order := []string{}
	unitsByPackageKey := map[string][]parser.Unit{}
	for _, unit := range units {
		if unit.AST == nil || unit.FileSet == nil || unit.AST.Name == nil {
			continue
		}
		if !isProductionCodePath(unit.File.Path) || unit.AST.Name.Name == "main" || isBootstrapPath(unit.File.Path) {
			continue
		}
		key := path.Dir(unit.File.Path) + "\x00" + unit.AST.Name.Name
		if _, seen := unitsByPackageKey[key]; !seen {
			order = append(order, key)
		}
		unitsByPackageKey[key] = append(unitsByPackageKey[key], unit)
	}
	groups := make([]productionPackageGroup, 0, len(order))
	for _, key := range order {
		groups = append(groups, productionPackageGroup{units: unitsByPackageKey[key]})
	}
	return groups
}

// declaresRecoveryBoundary reports whether a function body in g's files contains both a recover() call and an assignment through a pointer.
//
// It does not check that the assignment carries the recovered value, that its target is an error, or that the function is deferred.
// So an unrelated recover call and pointer assignment can exempt the whole package; a match does not prove a panic becomes a returned error.
//
// It returns true for a match in g's function declarations or literals; without a call graph, panic-site reachability is not checked.
func (g productionPackageGroup) declaresRecoveryBoundary() bool {
	for _, unit := range g.units {
		found := false
		ast.Inspect(unit.AST, func(node ast.Node) bool {
			if found {
				return false
			}
			switch current := node.(type) {
			case *ast.FuncDecl:
				found = bodyRecoversIntoPointer(current.Body)
			case *ast.FuncLit:
				found = bodyRecoversIntoPointer(current.Body)
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

// bodyRecoversIntoPointer reports whether body contains both a recover() call and an assignment through a pointer, the *errp = ... shape.
//
// It does not verify that the assignment publishes the recovered value, so an unrelated pointer store beside a recover call also qualifies.
// A handler with no pointer assignment cannot exempt the package, even when it calls recover to log the panic.
//
// A nil body, from a function declared without one, gives false.
func bodyRecoversIntoPointer(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	recovers, assignsThroughPointer := false, false
	ast.Inspect(body, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.CallExpr:
			if ident, ok := current.Fun.(*ast.Ident); ok && ident.Name == "recover" {
				recovers = true
			}
		case *ast.AssignStmt:
			for _, target := range current.Lhs {
				if _, ok := target.(*ast.StarExpr); ok {
					assignsThroughPointer = true
				}
			}
		}
		return !(recovers && assignsThroughPointer)
	})
	return recovers && assignsThroughPointer
}

// ignoredErrorEvidence classifies an ignored value as error-like by its name or constructor call, without resolving types.
//
// expr is the value assigned to a blank; errorsPackages and fmtPackages hold the import names under which errors.New and fmt.Errorf count.
// It returns expr, an evidence kind of identifier, selector or error-constructor, and true; any other shape gives nil, an empty string and false.
func ignoredErrorEvidence(expr ast.Expr, errorsPackages, fmtPackages map[string]bool) (ast.Expr, string, bool) {
	switch value := expr.(type) {
	case *ast.Ident:
		if isErrorLikeName(value.Name) {
			return expr, "identifier", true
		}
	case *ast.SelectorExpr:
		if isErrorLikeName(value.Sel.Name) {
			return expr, "selector", true
		}
	case *ast.CallExpr:
		if isErrorConstructorCall(value, errorsPackages, fmtPackages) {
			return expr, "error-constructor", true
		}
	}
	return nil, "", false
}

// isBlankIdent reports whether expr is the blank identifier.
func isBlankIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "_"
}

// isErrorLikeName recognises conventional error variable and field names.
// It reports true when the lower-cased name is err or error or ends in err or error, such as myErr or parseError, and false otherwise.
func isErrorLikeName(name string) bool {
	lower := strings.ToLower(name)
	return lower == "err" || lower == "error" || strings.HasSuffix(lower, "err") || strings.HasSuffix(lower, "error")
}

// isErrorConstructorCall recognises an errors.New or fmt.Errorf call by the import names the file uses for errors and fmt.
//
// call must be pkg.New with pkg in errorsPackages or pkg.Errorf with pkg in fmtPackages; any other callee, dot imports included, gives false.
// It reports true only for that call shape; the discard comes from the caller, which reads the right side of a blank assignment.
func isErrorConstructorCall(call *ast.CallExpr, errorsPackages, fmtPackages map[string]bool) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	return selector.Sel.Name == "New" && errorsPackages[receiver.Name] || selector.Sel.Name == "Errorf" && fmtPackages[receiver.Name]
}

// isProductionCodePath reports whether path is neither a Go test file nor under a testdata, examples or example directory.
// A false result keeps rules such as context-todo-production, production-panic and log-fatal-library silent on that file.
func isProductionCodePath(path string) bool {
	if isGoTestFile(path) {
		return false
	}
	clean := strings.ReplaceAll(path, "\\", "/")
	for _, marker := range []string{"/testdata/", "/examples/", "/example/"} {
		if strings.Contains(clean, marker) {
			return false
		}
	}
	return !strings.HasPrefix(clean, "testdata/") && !strings.HasPrefix(clean, "examples/") && !strings.HasPrefix(clean, "example/")
}

// isBootstrapPath exempts command entry files under cmd from rules such as production-panic and log-fatal-library.
//
// Code there often uses panic for impossible setup invariants rather than request-time production flow.
// It reports true when path, after backslashes become slashes, starts with cmd/ or contains /cmd/, and false otherwise.
func isBootstrapPath(path string) bool {
	clean := strings.ReplaceAll(path, "\\", "/")
	return strings.HasPrefix(clean, "cmd/") || strings.Contains(clean, "/cmd/")
}

// productionPanicFunctionExempt recognises functions whose names conventionally document panic-on-impossible-invariant behavior.
// It reports true when name is init, main or Defaults, or starts with the prefix Must, and false for any other function name.
func productionPanicFunctionExempt(name string) bool {
	return name == "init" || name == "main" || name == "Defaults" || strings.HasPrefix(name, "Must")
}

// isDirectPanicCall reports whether call has the unqualified callee name panic, without resolving shadowing.
// A local function named panic is therefore treated as the builtin, and its calls can be reported.
func isDirectPanicCall(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "panic"
}

// panicFindingMessage describes what the rule actually saw at the panic site.
//
// A bare string literal is a literal message; a Sprintf, Errorf or New argument is constructed, and calling it literal misleads the reader.
//
// It returns one of two fixed, non-empty messages: literal when the first argument of call unquotes as a string or rune literal, else constructed.
// call is a panic call that panicHasLiteralEvidence accepted, so the constructed wording means a Sprintf, Errorf or New argument.
func panicFindingMessage(call *ast.CallExpr) string {
	if len(call.Args) > 0 {
		if _, isLiteral := stringLiteral(call.Args[0]); isLiteral {
			return "production code calls panic with a literal message"
		}
	}
	return "production code calls panic with a constructed message"
}

// panicHasLiteralEvidence limits the rule to panics whose first argument is a quoted literal or a call named Sprintf, Errorf or New.
//
// Only the name from callFunctionName is compared, never the package or arguments, so crash messages and impossible-state notes look alike.
// It reports true when the first argument of call matches either shape, as stringLiteral and callFunctionName read it.
//
// A panic with no arguments, or with any other first argument, gives false, so panic(err) is never reported.
func panicHasLiteralEvidence(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	if _, ok := stringLiteral(call.Args[0]); ok {
		return true
	}
	nested, ok := call.Args[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	name := callFunctionName(nested)
	return name == "Sprintf" || name == "Errorf" || name == "New"
}
