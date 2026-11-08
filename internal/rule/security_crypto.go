// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds security.insecure-random-secret, which reports math/rand only where the value looks like a secret.
// A secret here is a token, nonce, session key, password, salt, or OTP; digest, cipher, and RSA key strength live in security_weak_crypto.go.
//
// The hard part is telling secret generation from selection, because both index a pool with rand.Intn(len(pool)).
// Building a token one character per pass is a finding; picking one item from a list the user already has is not.
// Getting that wrong either floods the report with noise or hides a guessable token.
package rule

import (
	"go/ast"
	"go/token"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// randomSecretContextWords names contexts where math/rand is not appropriate.
//
// A word of the enclosing function name, receiving target, or call argument text that equals one of these marks the value as a secret.
// A secret word wins even when a safe word such as test also appears, so the user still sees the finding.
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
//
// A state word marks a secret only when the same name or text carries no word from randomSafeContextWords.
var randomStateContextWords = []string{"state"}

// randomSafeContextWords describe ordinary pseudo-random use that should not fire on state alone.
//
// They silence only the weaker state word; a secret word such as token in the same name still reports.
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
//
// A call outside this list, such as rand.Shuffle or rand.Perm, is never reported.
// A method on a generator value such as r.Intn is not matched, because the receiver's spelling must equal a math/rand import name.
// Shadowing is not resolved, so a local generator spelled like the import name can still match.
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
//
// It ships disabled by default at advisory severity, so a user sees its findings only after turning security.insecure-random-secret on.
type InsecureRandomSecretRule struct{}

// Definition declares the security.insecure-random-secret rule for pseudo-random secret generation evidence.
// It returns an advisory, medium-confidence security definition that is disabled by default and points remediation at crypto/rand.
func (InsecureRandomSecretRule) Definition() Definition {
	return Definition{
		ID:             "security.insecure-random-secret",
		Title:          "Insecure random secret",
		Description:    "Flags math/rand use when the result is assigned to or returned from token, nonce, session, password, key, or other secret-looking contexts.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: false,
		Tags:           []string{"random", "security"},
		Remediation:    "Use crypto/rand for security-sensitive random values and keep math/rand for sampling, tests, and simulations.",
	}
}

// AnalyzeUnit reports supported math/rand calls in the declared function bodies of one scanned file when the value looks like a secret.
//
// The enclosing function name, receiving target, or call arguments must mark the value as a secret.
// The scan pipeline calls it once per file; everything else here supports its verdict.
//
// It returns nil when unit has no parsed AST or file set or does not import math/rand; package-level initializers and closures are not examined.
// It returns an empty slice when no supported call in the examined function bodies qualifies for a finding.
// An Intn index into the same identifier or selector chain its len argument measures is skipped when randomSelectionBuildsSecretBuffer is false.
//
// Each finding sits at the call position in unit and records the api name and the context word that marked the value as a secret.
func (InsecureRandomSecretRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	// A file the parser could not read has no tree to walk, so this rule adds no finding for it rather than guessing.
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	randPackages := packageImportNames(unit.AST, "math/rand", "rand")
	// A file without a named math/rand import is skipped, including one that imports crypto/rand under the rand name.
	// Calls through a dot import of math/rand are not examined either.
	if len(randPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		// Only declared function bodies are examined; package-level initializers and functions without bodies are skipped.
		// A math/rand call in a package-level var, such as var sessionKey = rand.Int63(), is never reported.
		if !ok || fn.Body == nil {
			continue
		}
		parents := astParentMap(fn.Body)
		seen := map[tokenKey]bool{}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			// A closure has no name of its own, so the enclosing function's name would describe the wrong code.
			//
			// AnalyzeUnit visits declared functions only, so a math/rand call inside a closure is never judged anywhere.
			// That is a known blind spot in the quiet direction: a token built inside a func literal yields no finding.
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			// Most nodes are not calls at all; keep descending past them.
			if !ok {
				return true
			}
			api, ok := mathRandCallName(call, randPackages)
			// A call that is not a listed math/rand API, such as the user's own helper or rand.Shuffle, is not this rule's concern.
			if !ok {
				return true
			}
			// The security context decides both the sampling exemption and whether the call is reported, so it is resolved once.
			contextWord, securityContext := randomCallSecurityContext(call, fn, parents)
			// Direct Intn indexing of an identifier or selector chain bounded by its len is skipped when randomSelectionBuildsSecretBuffer returns false.
			// Picking one existing item into a plain variable is ordinary sampling and stays out of the report.
			if randomCallSelectsExistingValue(call, parents) &&
				!randomSelectionBuildsSecretBuffer(call, parents, securityContext) {
				return true
			}
			// No checked name or argument yields a security context, so the rule leaves this call unreported.
			// A guessable ID from id := rand.Int63() inside func newID is missed this way.
			if !securityContext {
				return true
			}
			key := tokenKey{pos: call.Pos(), label: api}
			// Defensive: the walk reaches each node once, so this does not fire today.
			//
			// It keeps one finding per call site if the traversal ever revisits a node, because a duplicate line reads as two problems to fix.
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
// It returns a map from each node under root to its direct parent, with no entry for root itself, so a childless root gives an empty map.
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
//
// The call must select a listed math/rand API through an identifier in randPackages, the names under which the file imports math/rand.
// It returns that name, such as rand.Intn, with true; any other call shape gives an empty name and false.
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

// randomCallSelectsExistingValue reports the narrow sampling role where Intn directly indexes the same identifier or selector chain used by len.
//
// It walks parents up from call past parentheses and reports false unless call is the whole index of a collection matching its len argument.
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

// randomSelectionBuildsSecretBuffer tells token generation apart from choosing one existing key or sample.
//
// Generation adds one drawn element per pass: an indexed write into a buffer, an append of the element, or a += that grows a string.
// Only the shape is decided here; securityContext carries the caller's resolved answer to whether the value matters.
//
// From call it climbs parents past parentheses to the indexing expression, then up its ancestors until one settles the verdict.
// An append that adds the selection yields securityContext and an assignment defers to assignmentBuildsSecretBuffer.
// A return, value spec, closure, or reaching the top without either gives false, as does a call not directly inside an index expression.
//
// A false result sends the call back to the sampling exemption and no finding is shown, so a wrong false hides a real token builder.
func randomSelectionBuildsSecretBuffer(call *ast.CallExpr, parents map[ast.Node]ast.Node, securityContext bool) bool {
	parent := parents[call]
	// Parentheses around the call must not change whether the pool selection is treated as generation, so step past them.
	for {
		paren, ok := parent.(*ast.ParenExpr)
		if !ok {
			break
		}
		parent = parents[paren]
	}
	selection, ok := parent.(*ast.IndexExpr)
	// The random number is not indexing anything, so no character is drawn from a pool and this shape cannot be assembling a secret.
	if !ok {
		return false
	}
	for ancestor := parents[selection]; ancestor != nil; ancestor = parents[ancestor] {
		switch statement := ancestor.(type) {
		case *ast.CallExpr:
			// Appending the drawn element adds one more element per pass, which is generation; securityContext still decides whether it matters.
			if appendCallAddsSelection(statement, selection) {
				return securityContext
			}
		case *ast.AssignStmt:
			return assignmentBuildsSecretBuffer(statement, call, securityContext)
		case *ast.ReturnStmt, *ast.ValueSpec, *ast.FuncLit:
			// A return, value spec, or closure reached before a recognized builder keeps this call in the sampling exemption.
			return false
		}
	}
	return false
}

// assignmentBuildsSecretBuffer decides whether the assignment carrying the random selection grows a secret.
//
// A plain binding of one drawn element to a variable picks one existing value instead.
// The first right-hand value of assignment that contains call and has a target at the same position selects that target.
//
// It reports true when the target accumulates: +=, or = with an identifier target and a right-hand + expression, parentheses aside, reading it.
// An indexed target reports securityContext, and a plain target or no matching value reports false.
func assignmentBuildsSecretBuffer(assignment *ast.AssignStmt, call *ast.CallExpr, securityContext bool) bool {
	for valueIndex, assignedValue := range assignment.Rhs {
		// A multi-assignment can mix this call with unrelated values, so only the value holding the call is judged, and only when it has a target.
		if !exprContainsNode(assignedValue, call) || valueIndex >= len(assignment.Lhs) {
			continue
		}
		target := unwrapRandomSelectionParens(assignment.Lhs[valueIndex])
		// An accumulating assignment extends a value it already holds, so it generates one element per pass whatever the destination is called.
		// randomCallSecurityContext still decides whether that value matters.
		if randomSelectionAccumulates(assignment, target) {
			return true
		}
		// A non-indexed target that did not accumulate, such as a plain name or a field, replaces one value, so this call stays exempt.
		if _, indexedTarget := target.(*ast.IndexExpr); !indexedTarget {
			return false
		}
		// An indexed write fills a buffer one element per pass.
		//
		// Judging only the target name would hide an indexed write into buf inside generateToken, which builds the same secret as a write into token.
		// The enclosing-function evidence the caller already resolved answers this instead.
		return securityContext
	}
	return false
}

// randomSelectionAccumulates reports whether an assignment extends its own target rather than binding a fresh sample.
//
// Both token += piece and token = token + piece grow a secret one element per pass.
// Treating either spelling as sampling would hide string-concatenated token generators from the report.
//
// It reports true for any += and for a plain = whose identifier target appears inside a + expression on the right-hand side.
// Anything else, including a := binding, reports false.
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

// concatExtendsIdent reports whether a + expression reads the name it is assigned back to, which separates extending a buffer from replacing it.
//
// It reports true only when value, once unwrapped from parentheses, is a + expression with an identifier named targetName anywhere inside it.
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

// appendCallAddsSelection reports when the selected alphabet element is one of append's added values rather than its destination slice.
//
// Appending a freshly selected element grows a buffer, which is generation rather than sampling.
// It reports true only when call invokes append with at least one added value and selection sits inside one of those added values.
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

// unwrapRandomSelectionParens removes syntax-only parentheses before the selection predicate compares a call, collection, or length expression.
//
// It returns expr with every enclosing ParenExpr layer stripped, or expr itself when it is not parenthesized.
func unwrapRandomSelectionParens(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// sameRandomSelectionCollection compares supported collection paths, refusing calls, computed indexes, and anything that needs type flow.
//
// A pool reached through a call or an index never counts as the same, so a pick from it stays eligible for a finding.
// It reports true when left and right, ignoring parentheses, name the same identifier or the same selector chain on one identifier, else false.
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
//
// It checks the name of fn first, then the assignment or declaration target that parents show receiving call, and finally the arguments of call.
// It returns the first matched word and true, or an empty word and false when none of the three carries a security word.
func randomCallSecurityContext(call *ast.CallExpr, fn *ast.FuncDecl, parents map[ast.Node]ast.Node) (string, bool) {
	if word, ok := randomSecurityContextWord(fn.Name.Name); ok {
		return word, true
	}
	if word, ok := enclosingAssignmentContext(call, parents, randomSecurityContextWord); ok {
		return word, true
	}
	return callArgumentContext(call, randomSecurityContextWord)
}

// enclosingAssignmentContext returns the target-name context for a call nested in an assignment or value spec.
//
// It walks parents up from call and lets classify judge the target receiving it in the first enclosing assignment or value spec.
// A return statement or closure reached first, or no such ancestor at all, ends the walk with an empty word and false.
func enclosingAssignmentContext(call *ast.CallExpr, parents map[ast.Node]ast.Node, classify func(string) (string, bool)) (string, bool) {
	for parent := parents[call]; parent != nil; parent = parents[parent] {
		switch stmt := parent.(type) {
		case *ast.AssignStmt:
			return assignStmtContext(stmt, call, classify)
		case *ast.ValueSpec:
			return valueSpecContext(stmt, call, classify)
		// A value returned straight out has no receiving name, so only the function name or the call arguments can still mark it.
		case *ast.ReturnStmt:
			return "", false
		case *ast.FuncLit:
			return "", false
		}
	}
	return "", false
}

// assignStmtContext finds a security word on the assignment target receiving call's expression.
//
// Each value in stmt that contains call is paired with its same-position target, which exprTextContext searches using classify.
// It returns the first word classify accepts and true, or an empty word and false when no such target matches.
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
//
// Each value in spec that contains call is paired with its same-position name, and classify judges that name alone.
// It returns the first word classify accepts and true, or an empty word and false when no such name matches.
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
//
// Each argument of call is searched in order by exprTextContext, with classify judging its identifiers, selectors, and string literals.
// It returns the first word found and true, or an empty word and false when no argument carries one.
func callArgumentContext(call *ast.CallExpr, classify func(string) (string, bool)) (string, bool) {
	for _, arg := range call.Args {
		if word, ok := exprTextContext(arg, classify); ok {
			return word, true
		}
	}
	return "", false
}

// exprTextContext scans identifiers, selectors, and string literals inside expr for a context word.
// It returns the first word classify accepts, in walk order, with true, or an empty word and false when nothing inside expr matches.
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

// exprContainsNode reports whether target is expr itself or appears anywhere under it.
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
//
// A secret word anywhere in text wins outright; otherwise a safe word such as test or shuffle suppresses the weaker state word.
// It returns the matched word and true, or an empty word and false when text holds no secret word and no unsuppressed state word.
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
//
// The earliest token of text equal to any entry in words decides, so token order rather than list order picks the word.
// It returns an empty word and false when no token of text matches.
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
