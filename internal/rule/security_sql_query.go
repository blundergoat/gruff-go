// Package rule defines gruff-go's rule registry and analysers.
// This file contains SQL string-query construction classification helpers.
package rule

import (
	"go/ast"
	"go/token"
	"regexp"
)

// sqlPlaceholderPattern recognises common bind parameter placeholders.
var sqlPlaceholderPattern = regexp.MustCompile(`(\?|\$\d+|[:@][A-Za-z_][A-Za-z0-9_]*)`)

// sqlConstruction describes parser-visible SQL string assembly evidence.
type sqlConstruction struct {
	kind          string
	static        bool
	parameterized bool
}

// sqlConstructionAssignment stores one parser-visible assignment to a SQL
// construction variable.
type sqlConstructionAssignment struct {
	pos          token.Pos
	construction sqlConstruction
}

// isAcceptedStaticSQLConstruction accepts literal-only query assembly when it
// is either fully static SQL or parameterized SQL with bind arguments supplied.
func isAcceptedStaticSQLConstruction(call *ast.CallExpr, queryArgIndex int, construction sqlConstruction) bool {
	if !construction.static {
		return false
	}
	if !construction.parameterized {
		return true
	}
	return len(call.Args) > queryArgIndex+1
}

// staticStringExpr returns the concatenated string when expr is made only from
// string literals and + operators.
func staticStringExpr(expr ast.Expr) (string, bool) {
	switch value := expr.(type) {
	case *ast.BasicLit:
		return stringLiteral(value)
	case *ast.ParenExpr:
		return staticStringExpr(value.X)
	case *ast.BinaryExpr:
		if value.Op != token.ADD {
			return "", false
		}
		left, ok := staticStringExpr(value.X)
		if !ok {
			return "", false
		}
		right, ok := staticStringExpr(value.Y)
		if !ok {
			return "", false
		}
		return left + right, true
	default:
		return "", false
	}
}
