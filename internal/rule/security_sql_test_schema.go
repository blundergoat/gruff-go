// Package rule defines gruff-go's rule registry and analysers.
// This file contains focused SQL-string-query allowances for test schema setup.
package rule

import (
	"go/ast"
	"regexp"
	"strings"
)

// testSchemaNamePattern recognises fixed-prefix integration-test schema names
// such as `test_%d`, `test_db_%d`, or `test_migrate_%d`.
var testSchemaNamePattern = regexp.MustCompile(`^test(?:_[A-Za-z0-9]+)*_%d$`)

// collectTestSchemaVars records locals initialized from fixed-prefix test schema names.
func collectTestSchemaVars(body *ast.BlockStmt, fmtPackages map[string]bool, timePackages map[string]bool) map[string]bool {
	vars := map[string]bool{}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch stmt := node.(type) {
		case *ast.ValueSpec:
			for i, name := range stmt.Names {
				if name.Name == "_" || i >= len(stmt.Values) || !isTestSchemaNameExpr(stmt.Values[i], fmtPackages, timePackages) {
					continue
				}
				vars[name.Name] = true
			}
		case *ast.AssignStmt:
			for i, lhs := range stmt.Lhs {
				name, ok := lhs.(*ast.Ident)
				if !ok || name.Name == "_" || i >= len(stmt.Rhs) || !isTestSchemaNameExpr(stmt.Rhs[i], fmtPackages, timePackages) {
					continue
				}
				vars[name.Name] = true
			}
		}
		return true
	})
	return vars
}

// isTestSupportPath reports whether filePath is test-only code or test support code.
func isTestSupportPath(filePath string) bool {
	if isGoTestFile(filePath) {
		return true
	}
	normalized := "/" + strings.ReplaceAll(filePath, "\\", "/") + "/"
	return strings.Contains(normalized, "/testutil/")
}

// isTestSchemaCreation recognises CREATE SCHEMA statements for generated test schemas.
func isTestSchemaCreation(expr ast.Expr, testSchemaVars map[string]bool) bool {
	binary, ok := expr.(*ast.BinaryExpr)
	if !ok || binary.Op.String() != "+" {
		return false
	}
	literal, ok := stringLiteral(binary.X)
	if !ok || !strings.EqualFold(strings.TrimSpace(literal), "CREATE SCHEMA") {
		return false
	}
	return identInSet(binary.Y, testSchemaVars)
}

// isTestSchemaNameExpr recognises fmt.Sprintf calls that produce fixed-prefix test schema names.
func isTestSchemaNameExpr(expr ast.Expr, fmtPackages map[string]bool, timePackages map[string]bool) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || !isFmtSprintfCall(call, fmtPackages) || len(call.Args) != 2 {
		return false
	}
	format, ok := stringLiteral(call.Args[0])
	if !ok || !testSchemaNamePattern.MatchString(format) {
		return false
	}
	return isTimeUnixNanoCall(call.Args[1], timePackages)
}

// identInSet reports whether expr is an identifier present in values.
func identInSet(expr ast.Expr, values map[string]bool) bool {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			break
		}
		expr = paren.X
	}
	ident, ok := expr.(*ast.Ident)
	return ok && values[ident.Name]
}

// isTimeUnixNanoCall reports whether expr is time.Now().UnixNano() through an imported time package.
func isTimeUnixNanoCall(expr ast.Expr, timePackages map[string]bool) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	unixNano, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || unixNano.Sel.Name != "UnixNano" {
		return false
	}
	nowCall, ok := unixNano.X.(*ast.CallExpr)
	if !ok || len(nowCall.Args) != 0 {
		return false
	}
	now, ok := nowCall.Fun.(*ast.SelectorExpr)
	if !ok || now.Sel.Name != "Now" {
		return false
	}
	receiver, ok := now.X.(*ast.Ident)
	return ok && timePackages[receiver.Name]
}
