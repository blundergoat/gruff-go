// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds `security.insecure-random-secret`, which answers one question
// about the code a user pointed gruff-go at: is this random value protecting
// something. It reports `math/rand` only where the value looks like a secret -
// a token, nonce, session key, password, salt, or OTP. Digest, cipher, and RSA
// key strength are a separate rule in `security_weak_crypto.go`.
//
// The hard part is telling secret *generation* from ordinary *selection*: both
// spell `pool[rand.Intn(len(pool))]`. Building a token one character per pass is
// a finding; picking one item out of a list the user already has is not. Getting
// that wrong either floods the report with noise or hides a guessable token.
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

// AnalyzeUnit reports every math/rand call in one scanned file that produces a
// value the surrounding code treats as a secret. This is the entry point the
// scan pipeline calls once per file; everything else here supports its verdict.
// It returns an empty slice when the file is safe, which is the common case.
func (InsecureRandomSecretRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	// A file the parser could not read has no tree to walk, so it cannot be
	// judged either way and is reported as clean rather than guessed at.
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	randPackages := packageImportNames(unit.AST, "math/rand", "rand")
	// No math/rand import means nothing in this file can be the weak generator,
	// including a file that imports crypto/rand under the same `rand` name.
	if len(randPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		// Only a function body can contain the call. Interface methods, type
		// declarations, and imports are skipped without comment.
		if !ok || fn.Body == nil {
			continue
		}
		parents := astParentMap(fn.Body)
		seen := map[tokenKey]bool{}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			// A closure has no name of its own, so the enclosing function's name
			// would be the only evidence and would describe the wrong code. The
			// loop above visits declared functions only, so a `math/rand` call
			// inside a closure is skipped entirely rather than judged elsewhere -
			// a known blind spot, and the quiet direction.
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			// Most nodes are not calls at all; keep descending past them.
			if !ok {
				return true
			}
			api, ok := mathRandCallName(call, randPackages)
			// A call to something other than a supported math/rand API - the
			// user's own helper, or a strings call - is not this rule's concern.
			if !ok {
				return true
			}
			// The security context decides both questions below, so resolve it
			// once: whether a buffer-filling selection builds a secret, and
			// whether the call is worth reporting at all.
			contextWord, securityContext := randomCallSecurityContext(call, fn, parents)
			// The user is picking one item out of a collection they already
			// have - `values[rand.Intn(len(values))]` - and not assembling a
			// secret from it. Ordinary sampling stays out of the report.
			if randomCallSelectsExistingValue(call, parents) &&
				!randomSelectionBuildsSecretBuffer(call, parents, securityContext) {
				return true
			}
			// Nothing around the call suggests the value guards anything, so
			// this is a shuffle, a jitter, or a test fixture. Weak randomness
			// is the correct choice there and reporting it would be noise.
			if !securityContext {
				return true
			}
			key := tokenKey{pos: call.Pos(), label: api}
			// Defensive: the walk reaches each node once, so this does not fire
			// today. It guarantees one finding per call site if the traversal
			// ever revisits a node, because a duplicate line in the report reads
			// as two separate problems to fix.
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

// randomCallSelectsExistingValue reports the narrow sampling role where Intn
// directly indexes the same identifier or selector chain used by len.
func randomCallSelectsExistingValue(call *ast.CallExpr, parents map[ast.Node]ast.Node) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Intn" || len(call.Args) != 1 {
		return false
	}
	parent := parents[call]
	for {
		paren, ok := parent.(*ast.ParenExpr)
		if !ok {
			break
		}
		parent = parents[paren]
	}
	index, ok := parent.(*ast.IndexExpr)
	if !ok || unwrapRandomSelectionParens(index.Index) != call {
		return false
	}
	lengthCall, ok := unwrapRandomSelectionParens(call.Args[0]).(*ast.CallExpr)
	if !ok || len(lengthCall.Args) != 1 {
		return false
	}
	lengthName, ok := unwrapRandomSelectionParens(lengthCall.Fun).(*ast.Ident)
	if !ok || lengthName.Name != "len" {
		return false
	}
	return sameRandomSelectionCollection(index.X, lengthCall.Args[0])
}

// randomSelectionBuildsSecretBuffer distinguishes token generation such as
// `token[i] = alphabet[rand.Intn(len(alphabet))]`,
// `token = append(token, alphabet[rand.Intn(len(alphabet))])`, and
// `token += string(alphabet[rand.Intn(len(alphabet))])` from choosing one
// existing key or sample. Only the shape is decided here; securityContext
// carries the caller's already-resolved answer to whether the value matters.
// Returning false sends the call back to the sampling exemption and no finding
// is shown, so this is the last thing standing between a real token builder and
// a silent report.
func randomSelectionBuildsSecretBuffer(call *ast.CallExpr, parents map[ast.Node]ast.Node, securityContext bool) bool {
	parent := parents[call]
	// A user may have written `(pool)[(rand.Intn(len(pool)))]` while debugging.
	// Step past those parentheses so spelling does not change the verdict.
	for {
		paren, ok := parent.(*ast.ParenExpr)
		if !ok {
			break
		}
		parent = parents[paren]
	}
	selection, ok := parent.(*ast.IndexExpr)
	// The random number is not indexing anything, so no character is being
	// drawn from a pool and this shape cannot be assembling a secret.
	if !ok {
		return false
	}
	for ancestor := parents[selection]; ancestor != nil; ancestor = parents[ancestor] {
		switch statement := ancestor.(type) {
		case *ast.CallExpr:
			// `token = append(token, pool[...])` inside a loop: each pass adds
			// one more character, which is generation however it is named.
			if appendCallAddsSelection(statement, selection) {
				return securityContext
			}
		case *ast.AssignStmt:
			return assignmentBuildsSecretBuffer(statement, call, securityContext)
		case *ast.ReturnStmt, *ast.ValueSpec, *ast.FuncLit:
			// Returned or bound straight to a new name, the drawn element is
			// the whole result - one pick, not a buffer being filled.
			return false
		}
	}
	return false
}

// assignmentBuildsSecretBuffer decides whether the assignment carrying the
// random selection grows a secret. A plain binding such as
// `chosen := keys[rand.Intn(len(keys))]` picks one existing value instead.
// It reports true for the two shapes that add one element per pass: an
// accumulating `token += ...` and an indexed write `token[i] = ...`.
func assignmentBuildsSecretBuffer(assignment *ast.AssignStmt, call *ast.CallExpr, securityContext bool) bool {
	for valueIndex, assignedValue := range assignment.Rhs {
		// Skip any value that does not contain this call - a multi-assignment
		// such as `a, b := pick(), pool[rand.Intn(len(pool))]` has both - and
		// skip a right-hand side with no matching target to describe it.
		if !exprContainsNode(assignedValue, call) || valueIndex >= len(assignment.Lhs) {
			continue
		}
		target := unwrapRandomSelectionParens(assignment.Lhs[valueIndex])
		// An accumulating assignment extends a value it already holds, so it
		// generates one element per pass whatever the destination is called.
		// randomCallSecurityContext still decides whether that value matters.
		if randomSelectionAccumulates(assignment, target) {
			return true
		}
		// The destination is a plain name, so this replaces it rather than
		// filling it: `chosen := keys[rand.Intn(len(keys))]` is one pick.
		if _, indexedTarget := target.(*ast.IndexExpr); !indexedTarget {
			return false
		}
		// An indexed write fills a buffer one element per pass. Reading only the
		// target's own name lost `buf[i] = pool[rand.Intn(len(pool))]` inside
		// generateToken, which builds the same secret as `token[i] = ...`; the
		// enclosing-function evidence the caller already resolved answers this.
		return securityContext
	}
	return false
}

// randomSelectionAccumulates reports whether an assignment extends its own
// target rather than binding a fresh sample: `token += pool[i]` or the
// equivalent `token = token + pool[i]`. Both grow a secret one element per
// pass, so treating either as plain selection hid the common string-concat
// token generator behind the existing-value exemption.
func randomSelectionAccumulates(assignment *ast.AssignStmt, target ast.Expr) bool {
	if assignment.Tok == token.ADD_ASSIGN {
		return true
	}
	// A `:=` or a `=` that does not read its target binds a new value instead.
	if assignment.Tok != token.ASSIGN {
		return false
	}
	targetName, isIdentifier := target.(*ast.Ident)
	if !isIdentifier {
		return false
	}
	for _, value := range assignment.Rhs {
		if concatExtendsIdent(value, targetName.Name) {
			return true
		}
	}
	return false
}

// concatExtendsIdent reports whether a `+` expression reads the name it is
// assigned back to, which separates extending a buffer from replacing it.
func concatExtendsIdent(value ast.Expr, targetName string) bool {
	concatenation, isConcatenation := unwrapRandomSelectionParens(value).(*ast.BinaryExpr)
	if !isConcatenation || concatenation.Op != token.ADD {
		return false
	}
	extendsTarget := false
	ast.Inspect(concatenation, func(node ast.Node) bool {
		if extendsTarget {
			return false
		}
		identifier, isIdentifier := node.(*ast.Ident)
		if isIdentifier && identifier.Name == targetName {
			extendsTarget = true
		}
		return !extendsTarget
	})
	return extendsTarget
}

// appendCallAddsSelection reports when the selected alphabet element is one of
// append's added values rather than its destination slice. Appending a freshly
// selected element grows a buffer, which is generation rather than sampling.
func appendCallAddsSelection(call *ast.CallExpr, selection *ast.IndexExpr) bool {
	functionName, isIdentifier := unwrapRandomSelectionParens(call.Fun).(*ast.Ident)
	if !isIdentifier || functionName.Name != "append" || len(call.Args) < 2 {
		return false
	}
	for _, appendedValue := range call.Args[1:] {
		if exprContainsNode(appendedValue, selection) {
			return true
		}
	}
	return false
}

// unwrapRandomSelectionParens removes syntax-only parentheses before the
// selection predicate compares a call, collection, or length expression.
func unwrapRandomSelectionParens(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// sameRandomSelectionCollection compares supported collection paths without
// admitting calls, computed indexes, or other expressions that need type flow.
func sameRandomSelectionCollection(left, right ast.Expr) bool {
	left = unwrapRandomSelectionParens(left)
	right = unwrapRandomSelectionParens(right)
	switch leftValue := left.(type) {
	case *ast.Ident:
		rightValue, ok := right.(*ast.Ident)
		return ok && leftValue.Name == rightValue.Name
	case *ast.SelectorExpr:
		rightValue, ok := right.(*ast.SelectorExpr)
		return ok && leftValue.Sel.Name == rightValue.Sel.Name &&
			sameRandomSelectionCollection(leftValue.X, rightValue.X)
	default:
		return false
	}
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
