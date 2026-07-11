// Package rule classifies net/http calls that can send a user-controlled URL.
// It gives the URL rule stable sink labels for terminal, JSON, and dashboard
// findings without changing how destination safety itself is decided.
package rule

import (
	"go/ast"
	"go/token"
)

// httpClientURLArg reports the URL argument index and a sink label for net/http
// client calls, including package helpers and known http.Client values.
func httpClientURLArg(candidateCall *ast.CallExpr, httpPackageAliases, httpClientVariables map[string]bool) (int, string, bool) {
	methodSelector, isSelector := candidateCall.Fun.(*ast.SelectorExpr)
	// A plain function call is not one of the net/http sinks shown to users.
	if !isSelector {
		return 0, "", false
	}
	packageIdentifier, hasPackageIdentifier := methodSelector.X.(*ast.Ident)
	// Package helpers expose their URL at a stable position in the UI metadata.
	if hasPackageIdentifier && httpPackageAliases[packageIdentifier.Name] {
		switch methodSelector.Sel.Name {
		case "Get", "Head", "Post", "PostForm":
			return 0, packageIdentifier.Name + "." + methodSelector.Sel.Name, true
		case "NewRequest":
			return 1, packageIdentifier.Name + ".NewRequest", true
		case "NewRequestWithContext":
			return 2, packageIdentifier.Name + ".NewRequestWithContext", true
		}
		return 0, "", false
	}
	// Known client values use the first argument as their destination URL.
	if isHTTPClientReceiver(methodSelector.X, httpPackageAliases, httpClientVariables) {
		switch methodSelector.Sel.Name {
		case "Get", "Head", "Post", "PostForm":
			return 0, "client." + methodSelector.Sel.Name, true
		}
	}
	return 0, "", false
}

// isHTTPClientReceiver recognises a collected http.Client or DefaultClient.
// Use it so method-based fetches appear beside package-helper findings in the UI.
func isHTTPClientReceiver(receiverExpression ast.Expr, httpPackageAliases, httpClientVariables map[string]bool) bool {
	switch receiverValue := receiverExpression.(type) {
	case *ast.Ident:
		return httpClientVariables[receiverValue.Name]
	case *ast.SelectorExpr:
		packageIdentifier, isIdentifier := receiverValue.X.(*ast.Ident)
		return isIdentifier && httpPackageAliases[packageIdentifier.Name] && receiverValue.Sel.Name == "DefaultClient"
	}
	return false
}

// collectHTTPClientVars records locals bound to an http.Client value.
// The URL scan uses them to show method-based outbound requests to the user.
func collectHTTPClientVars(functionBody *ast.BlockStmt, httpPackageAliases map[string]bool) map[string]bool {
	httpClientVariables := map[string]bool{}
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// A nested callback gets its own scan context and client-variable list.
		if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
			return false
		}
		switch statement := syntaxNode.(type) {
		case *ast.AssignStmt:
			// Track each assignment so a user's custom client method is still reported.
			for valueIndex, leftHandValue := range statement.Lhs {
				clientName, isIdentifier := leftHandValue.(*ast.Ident)
				// Blank, missing, or non-client values cannot send a classified request.
				if !isIdentifier || clientName.Name == "_" || valueIndex >= len(statement.Rhs) || !isHTTPClientExpr(statement.Rhs[valueIndex], httpPackageAliases) {
					continue
				}
				httpClientVariables[clientName.Name] = true
			}
		case *ast.ValueSpec:
			// Track declared client values for the same user-visible method sinks.
			for valueIndex, clientName := range statement.Names {
				// Empty or non-client declarations never become outbound URL sinks.
				if clientName.Name == "_" || valueIndex >= len(statement.Values) || !isHTTPClientExpr(statement.Values[valueIndex], httpPackageAliases) {
					continue
				}
				httpClientVariables[clientName.Name] = true
			}
		}
		return true
	})
	return httpClientVariables
}

// isHTTPClientExpr recognises an http.Client construction or reference.
// Use it while collecting client variables that can create a URL finding.
func isHTTPClientExpr(clientExpression ast.Expr, httpPackageAliases map[string]bool) bool {
	switch clientValue := clientExpression.(type) {
	case *ast.UnaryExpr:
		// Users often construct a pointer client with &http.Client{}.
		if clientValue.Op == token.AND {
			return isHTTPClientExpr(clientValue.X, httpPackageAliases)
		}
	case *ast.CompositeLit:
		return isHTTPClientLiteral(clientValue, httpPackageAliases)
	case *ast.SelectorExpr:
		packageIdentifier, isIdentifier := clientValue.X.(*ast.Ident)
		return isIdentifier && httpPackageAliases[packageIdentifier.Name] && clientValue.Sel.Name == "DefaultClient"
	}
	return false
}
