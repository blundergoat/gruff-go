// Package rule defines gruff-go's rule registry and analysers.
// This file implements parser-only crypto and random security checks.
package rule

import (
	"go/ast"
	"go/token"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// randomSecretContextWords names contexts where math/rand is not appropriate.
var randomSecretContextWords = []string{
	"token",
	"nonce",
	"session",
	"password",
	"passwd",
	"secret",
	"key",
	"csrf",
	"salt",
	"otp",
}

// randomStateContextWords keeps OAuth-style state in scope without making it a strong signal.
var randomStateContextWords = []string{"state"}

// randomSafeContextWords describe ordinary pseudo-random use that should not fire on state alone.
var randomSafeContextWords = []string{
	"bench",
	"benchmark",
	"dice",
	"fixture",
	"fuzz",
	"game",
	"jitter",
	"mock",
	"order",
	"sample",
	"shuffle",
	"simulation",
	"test",
}

// mathRandAPIs are package-level math/rand calls that produce pseudo-random values.
var mathRandAPIs = map[string]bool{
	"Float32":   true,
	"Float64":   true,
	"Int":       true,
	"Int31":     true,
	"Int31n":    true,
	"Int63":     true,
	"Int63n":    true,
	"Intn":      true,
	"New":       true,
	"NewSource": true,
	"Read":      true,
}

// InsecureRandomSecretRule flags math/rand use in secret-bearing contexts.
type InsecureRandomSecretRule struct{}

// Definition declares the security.insecure-random-secret rule for pseudo-random secret generation evidence.
func (InsecureRandomSecretRule) Definition() Definition {
	return Definition{
		ID:             "security.insecure-random-secret",
		Title:          "Insecure random secret",
		Description:    "Flags math/rand use when the result is assigned to or returned from token, nonce, session, password, key, or other secret-looking contexts.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"random", "security"},
		Remediation:    "Use crypto/rand for security-sensitive random values and keep math/rand for sampling, tests, and simulations.",
	}
}

// AnalyzeUnit emits findings for math/rand calls that feed security-named values.
func (InsecureRandomSecretRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	randPackages := packageImportNames(unit.AST, "math/rand", "rand")
	if len(randPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		parents := astParentMap(fn.Body)
		seen := map[tokenKey]bool{}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			api, ok := mathRandCallName(call, randPackages)
			if !ok {
				return true
			}
			contextWord, ok := randomCallSecurityContext(call, fn, parents)
			if !ok {
				return true
			}
			key := tokenKey{pos: call.Pos(), label: api}
			if seen[key] {
				return true
			}
			seen[key] = true
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "math/rand used for security-sensitive random value",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Metadata: map[string]any{
					"api":     api,
					"context": contextWord,
				},
			})
			return true
		})
	}
	return findings
}

// tokenKey deduplicates findings by position plus call label.
type tokenKey struct {
	pos   token.Pos
	label string
}

// astParentMap records parent links for AST nodes under root.
func astParentMap(root ast.Node) map[ast.Node]ast.Node {
	parents := map[ast.Node]ast.Node{}
	stack := []ast.Node{}
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return true
		}
		if len(stack) > 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	return parents
}

// mathRandCallName returns the package-qualified math/rand API name for supported calls.
func mathRandCallName(call *ast.CallExpr, randPackages map[string]bool) (string, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !mathRandAPIs[selector.Sel.Name] {
		return "", false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !randPackages[receiver.Name] {
		return "", false
	}
	return receiver.Name + "." + selector.Sel.Name, true
}

// randomCallSecurityContext finds the security word that makes a math/rand call actionable.
func randomCallSecurityContext(call *ast.CallExpr, fn *ast.FuncDecl, parents map[ast.Node]ast.Node) (string, bool) {
	if word, ok := randomSecurityContextWord(fn.Name.Name); ok {
		return word, true
	}
	if word, ok := enclosingAssignmentContext(call, parents, randomSecurityContextWord); ok {
		return word, true
	}
	return callArgumentContext(call, randomSecurityContextWord)
}

// enclosingAssignmentContext returns the target-name context for a call nested in an assignment, value, or return statement.
func enclosingAssignmentContext(call *ast.CallExpr, parents map[ast.Node]ast.Node, classify func(string) (string, bool)) (string, bool) {
	for parent := parents[call]; parent != nil; parent = parents[parent] {
		switch stmt := parent.(type) {
		case *ast.AssignStmt:
			return assignStmtContext(stmt, call, classify)
		case *ast.ValueSpec:
			return valueSpecContext(stmt, call, classify)
		case *ast.ReturnStmt:
			return "", false
		case *ast.FuncLit:
			return "", false
		}
	}
	return "", false
}

// assignStmtContext finds a security word on the assignment target receiving call's expression.
func assignStmtContext(stmt *ast.AssignStmt, call *ast.CallExpr, classify func(string) (string, bool)) (string, bool) {
	for index, expr := range stmt.Rhs {
		if !exprContainsNode(expr, call) || index >= len(stmt.Lhs) {
			continue
		}
		if word, ok := exprTextContext(stmt.Lhs[index], classify); ok {
			return word, true
		}
	}
	return "", false
}

// valueSpecContext finds a security word on the value-spec name receiving call's expression.
func valueSpecContext(spec *ast.ValueSpec, call *ast.CallExpr, classify func(string) (string, bool)) (string, bool) {
	for index, expr := range spec.Values {
		if !exprContainsNode(expr, call) || index >= len(spec.Names) {
			continue
		}
		if word, ok := classify(spec.Names[index].Name); ok {
			return word, true
		}
	}
	return "", false
}

// callArgumentContext finds a security word in any call argument expression.
func callArgumentContext(call *ast.CallExpr, classify func(string) (string, bool)) (string, bool) {
	for _, arg := range call.Args {
		if word, ok := exprTextContext(arg, classify); ok {
			return word, true
		}
	}
	return "", false
}

// exprTextContext scans identifiers, selectors, and string literals inside expr for a context word.
func exprTextContext(expr ast.Expr, classify func(string) (string, bool)) (string, bool) {
	var matched string
	ast.Inspect(expr, func(node ast.Node) bool {
		if matched != "" {
			return false
		}
		switch value := node.(type) {
		case *ast.Ident:
			if word, ok := classify(value.Name); ok {
				matched = word
				return false
			}
		case *ast.SelectorExpr:
			if word, ok := classify(value.Sel.Name); ok {
				matched = word
				return false
			}
		case *ast.BasicLit:
			if literal, ok := stringLiteral(value); ok {
				if word, matchedOK := classify(literal); matchedOK {
					matched = word
					return false
				}
			}
		}
		return true
	})
	return matched, matched != ""
}

// exprContainsNode reports whether target appears under expr.
func exprContainsNode(expr ast.Expr, target ast.Node) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		if found {
			return false
		}
		if node == target {
			found = true
			return false
		}
		return true
	})
	return found
}

// randomSecurityContextWord classifies token, nonce, key, and similar random-secret names.
func randomSecurityContextWord(text string) (string, bool) {
	if word, ok := firstContextWord(text, randomSecretContextWords); ok {
		return word, true
	}
	if _, safe := firstContextWord(text, randomSafeContextWords); safe {
		return "", false
	}
	return firstContextWord(text, randomStateContextWords)
}

// firstContextWord returns the first configured word present as a token in text.
func firstContextWord(text string, words []string) (string, bool) {
	tokens := tokenizeForMisspelling(text)
	for _, token := range tokens {
		for _, word := range words {
			if token == word {
				return word, true
			}
		}
	}
	return "", false
}
