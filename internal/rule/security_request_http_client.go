// Package rule classifies net/http calls that can send a user-controlled URL.
//
// It gives the URL rule stable sink labels for terminal, JSON, and dashboard findings.
// It does not change how destination safety itself is decided.
package rule

import (
	"go/ast"
	"go/token"
)

// httpClientBindingChange records whether one lexical variable holds a usable
// net/http client after a declaration or assignment in the handler.
type httpClientBindingChange struct {
	changeSite      ast.Node
	holdsHTTPClient bool
}

// httpClientBindings tracks client state by lexical object and source position.
// Request calls use it to avoid inheriting state from shadows or later writes.
type httpClientBindings struct {
	functionBody        *ast.BlockStmt
	changesByBinding    map[*ast.Object][]httpClientBindingChange
	typedClientBindings map[*ast.Object]bool
}

// httpClientURLArg reports the URL argument index and a sink label for net/http client calls.
//
// It covers package helpers such as http.Get and http.NewRequest, and the Get, Head, Post and PostForm methods of known http.Client values.
// candidateCall is the call to classify, httpPackageAliases names the net/http imports, and clientBindings resolves client receivers.
//
// It returns the URL index, sink label and true for a recognised call, or zero, an empty label and false for any other call.
func httpClientURLArg(candidateCall *ast.CallExpr, httpPackageAliases map[string]bool, clientBindings httpClientBindings) (int, string, bool) {
	methodSelector, isSelector := candidateCall.Fun.(*ast.SelectorExpr)
	// A plain function call is not one of the net/http sinks shown to users.
	if !isSelector {
		return 0, "", false
	}
	packageIdentifier, hasPackageIdentifier := methodSelector.X.(*ast.Ident)
	// Package helpers such as http.Get take their URL at a fixed argument position, and the sink label keeps the user's import alias.
	if hasPackageIdentifier && isImportedPackageIdentifier(packageIdentifier, httpPackageAliases) {
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
	if isHTTPClientReceiver(methodSelector.X, httpPackageAliases, clientBindings, candidateCall) {
		switch methodSelector.Sel.Name {
		case "Get", "Head", "Post", "PostForm":
			return 0, "client." + methodSelector.Sel.Name, true
		}
	}
	return 0, "", false
}

// isHTTPClientReceiver recognises a collected http.Client or DefaultClient.
//
// It lets client.Get, Head, Post and PostForm calls produce the same URL findings as the package helpers.
// receiverExpression is the method receiver; an identifier is checked in clientBindings at requestCall.
// It returns true for an identifier that can hold a client there or for DefaultClient on a package in httpPackageAliases, and false otherwise.
func isHTTPClientReceiver(receiverExpression ast.Expr, httpPackageAliases map[string]bool, clientBindings httpClientBindings, requestCall *ast.CallExpr) bool {
	switch receiverValue := receiverExpression.(type) {
	case *ast.Ident:
		return clientBindings.canHoldHTTPClientAt(receiverValue, requestCall)
	case *ast.SelectorExpr:
		packageIdentifier, isIdentifier := receiverValue.X.(*ast.Ident)
		return isIdentifier && isImportedPackageIdentifier(packageIdentifier, httpPackageAliases) && receiverValue.Sel.Name == "DefaultClient"
	}
	return false
}

// canHoldHTTPClientAt reports whether a lexical receiver can hold a net/http client when the request executes.
//
// A later non-client write clears a candidate by syntax checks on source order and enclosing branches, not a full runtime path analysis.
// receiver is the method receiver identifier and requestCall the request; a nil or unresolved receiver or a nil requestCall gives false.
// False means the call is not classified as an http.Client request.
func (clientBindings httpClientBindings) canHoldHTTPClientAt(receiver *ast.Ident, requestCall *ast.CallExpr) bool {
	// An unresolved receiver cannot be tied to a declaration without guessing by name.
	if receiver == nil || receiver.Obj == nil || requestCall == nil {
		return false
	}
	bindingChanges := clientBindings.changesByBinding[receiver.Obj]
	// Any reachable client-producing change can classify the request unless a later non-client write passes the replacement checks first.
	for changeIndex, bindingChange := range bindingChanges {
		if !bindingChange.holdsHTTPClient || bindingChange.changeSite.Pos() >= requestCall.Pos() {
			continue
		}
		// If the control-path check treats the change and the request as exclusive, that change cannot make this call produce a URL finding.
		if !nodesCanShareControlPath(clientBindings.functionBody, bindingChange.changeSite, requestCall) {
			continue
		}
		if !clientBindings.hasDominatingNonClientWrite(bindingChanges[changeIndex+1:], bindingChange.changeSite, requestCall) {
			return true
		}
	}
	return false
}

// hasDominatingNonClientWrite reports whether one later non-client write replaces the client candidate before the request, by syntax checks alone.
//
// laterWrites follow the candidate written at clientValueWrite; only non-client writes positioned before requestCall can count.
// False keeps the client classification, including when separate if and else writes together replace the candidate.
func (clientBindings httpClientBindings) hasDominatingNonClientWrite(laterWrites []httpClientBindingChange, clientValueWrite ast.Node, requestCall *ast.CallExpr) bool {
	for _, laterWrite := range laterWrites {
		// A write after the request in the source is ignored, even when a loop runs it before a later pass of the same call.
		if laterWrite.changeSite.Pos() >= requestCall.Pos() {
			continue
		}
		// Another client value preserves the candidate instead of invalidating it.
		if laterWrite.holdsHTTPClient {
			continue
		}
		// A write treated as exclusive from the client assignment or the request cannot prevent a URL finding based on that candidate.
		if !nodesCanShareControlPath(clientBindings.functionBody, clientValueWrite, laterWrite.changeSite) ||
			!nodesCanShareControlPath(clientBindings.functionBody, laterWrite.changeSite, requestCall) {
			continue
		}
		// Every optional region around the write must also contain the request;
		// otherwise the request can run on a path that skipped the replacement.
		if enclosingControlRegionsContainPosition(clientBindings.functionBody, laterWrite.changeSite, requestCall.Pos()) {
			return true
		}
	}
	return false
}

// recordBindingChange adds one declaration or assignment to the receiver's timeline.
//
// Blank and unresolved names, and a nil changeSite, are skipped because they cannot affect a later classified call.
// identifier names the receiver, changeSite is the node that binds it, and holdsHTTPClient says whether the bound value holds a client.
func (clientBindings *httpClientBindings) recordBindingChange(identifier *ast.Ident, changeSite ast.Node, holdsHTTPClient bool) {
	// Only a resolved local lets the scanner distinguish shadows with the same name.
	if identifier == nil || identifier.Name == "_" || identifier.Obj == nil || changeSite == nil {
		return
	}
	clientBindings.changesByBinding[identifier.Obj] = append(clientBindings.changesByBinding[identifier.Obj], httpClientBindingChange{
		changeSite:      changeSite,
		holdsHTTPClient: holdsHTTPClient,
	})
}

// recordClientType remembers a declaration whose static type is http.Client or *http.Client.
//
// Later factory assignments still hold that type even when their expression shape does not reveal it to this parser-only scan.
// identifier is the declared name, clientType its declared type, and httpPackageAliases names the net/http imports.
// It returns true once identifier is marked client-typed, and false for a nil or unresolved identifier or a non-client type.
func (clientBindings *httpClientBindings) recordClientType(identifier *ast.Ident, clientType ast.Expr, httpPackageAliases map[string]bool) bool {
	// Only exact net/http types with resolved bindings can constrain later writes.
	if identifier == nil || identifier.Obj == nil || !isHTTPClientParameterType(clientType, httpPackageAliases) {
		return false
	}
	clientBindings.typedClientBindings[identifier.Obj] = true
	return true
}

// recordInferredClientType preserves the concrete type introduced by := or an untyped var initializer.
//
// A pre-existing name in a mixed short declaration is only assigned, so its earlier interface type must remain dynamic.
// identifier becomes client-typed only when declarationSite declared it and assignedValue is a client expression per httpPackageAliases.
func (clientBindings *httpClientBindings) recordInferredClientType(identifier *ast.Ident, declarationSite ast.Node, assignedValue ast.Expr, httpPackageAliases map[string]bool) {
	// Only a new resolved declaration with recognizable client syntax infers this type.
	if identifier == nil || identifier.Obj == nil || identifier.Obj.Decl != declarationSite ||
		!isHTTPClientExpr(assignedValue, httpPackageAliases) {
		return
	}
	clientBindings.typedClientBindings[identifier.Obj] = true
}

// assignmentHoldsHTTPClient classifies a value written to one receiver.
//
// A recognizable client literal or DefaultClient is enough for inferred and interface-typed locals.
// Statically typed client bindings also keep their client type across factory calls.
//
// identifier is the receiver written, assignedValue its value, hasAssignedValue whether one exists, and httpPackageAliases the net/http names.
// It returns false when hasAssignedValue is false or assignedValue is the bare identifier nil, and true for a client expression.
// Any other value yields true only when identifier is resolved and recorded as client-typed.
func (clientBindings httpClientBindings) assignmentHoldsHTTPClient(identifier *ast.Ident, assignedValue ast.Expr, hasAssignedValue bool, httpPackageAliases map[string]bool) bool {
	// An absent initializer is handled by the declaration scan, which distinguishes usable value clients from nil pointers.
	if !hasAssignedValue {
		return false
	}
	if isHTTPClientExpr(assignedValue, httpPackageAliases) {
		return true
	}
	// An explicit nil keeps a typed pointer unusable at the next request.
	if nilIdentifier, isIdentifier := assignedValue.(*ast.Ident); isIdentifier && nilIdentifier.Name == "nil" {
		return false
	}
	return identifier != nil && identifier.Obj != nil && clientBindings.typedClientBindings[identifier.Obj]
}

// collectHTTPClientBindings records parameter and local client state for one handler.
//
// The URL scan consults this timeline at each method-based request such as client.Get.
// functionType, when non-nil, supplies the parameters; functionBody supplies AssignStmt and ValueSpec nodes outside nested function literals.
// httpPackageAliases names the net/http imports used to recognise client types and values.
//
// It returns the bindings with a timeline entry for each resolved non-blank name those nodes bind.
// Range clauses add no initial entry, but assignments to their resolved non-blank variables are still recorded.
func collectHTTPClientBindings(functionType *ast.FuncType, functionBody *ast.BlockStmt, httpPackageAliases map[string]bool) httpClientBindings {
	clientBindings := httpClientBindings{
		functionBody:        functionBody,
		changesByBinding:    map[*ast.Object][]httpClientBindingChange{},
		typedClientBindings: map[*ast.Object]bool{},
	}
	// Injected value or pointer clients are usable sinks when the handler begins.
	if functionType != nil && functionType.Params != nil {
		for _, parameterField := range functionType.Params.List {
			// Each named parameter has its own lexical binding in the handler.
			for _, parameterName := range parameterField.Names {
				isHTTPClientParameter := clientBindings.recordClientType(parameterName, parameterField.Type, httpPackageAliases)
				clientBindings.recordBindingChange(parameterName, parameterField, isHTTPClientParameter)
			}
		}
	}
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// Nested callbacks get a separate scan only when they declare their own request parameter; captured request state is not inherited.
		if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
			return false
		}
		switch statement := syntaxNode.(type) {
		case *ast.AssignStmt:
			// Each assignment adds a possible state; an optional non-client assignment can leave an earlier client eligible at a later request.
			for valueIndex, leftHandValue := range statement.Lhs {
				clientName, isIdentifier := leftHandValue.(*ast.Ident)
				// Non-identifiers cannot name the method receiver used by this rule.
				if !isIdentifier {
					continue
				}
				var assignedValue ast.Expr
				// Multi-result assignments have one RHS for several typed receivers.
				if valueIndex < len(statement.Rhs) {
					assignedValue = statement.Rhs[valueIndex]
				}
				// A short declaration infers the concrete net/http type from its value.
				if statement.Tok == token.DEFINE {
					clientBindings.recordInferredClientType(clientName, statement, assignedValue, httpPackageAliases)
				}
				isHTTPClientValue := clientBindings.assignmentHoldsHTTPClient(clientName, assignedValue, len(statement.Rhs) > 0, httpPackageAliases)
				clientBindings.recordBindingChange(clientName, statement, isHTTPClientValue)
			}
		case *ast.ValueSpec:
			// A declaration establishes the initial receiver state before later writes.
			for valueIndex, clientName := range statement.Names {
				isDeclaredClient := clientBindings.recordClientType(clientName, statement.Type, httpPackageAliases)
				var initialValue ast.Expr
				// A missing initializer leaves a value client usable and a pointer nil.
				if valueIndex < len(statement.Values) {
					initialValue = statement.Values[valueIndex]
				}
				// Without an explicit type, the initializer determines the binding type.
				if statement.Type == nil {
					clientBindings.recordInferredClientType(clientName, statement, initialValue, httpPackageAliases)
				}
				isInitializedClient := clientBindings.assignmentHoldsHTTPClient(clientName, initialValue, valueIndex < len(statement.Values), httpPackageAliases)
				isUsableZeroValue := isDeclaredClient && isHTTPClientValueType(statement.Type, httpPackageAliases) && len(statement.Values) == 0
				clientBindings.recordBindingChange(clientName, statement, isInitializedClient || isUsableZeroValue)
			}
		}
		return true
	})
	return clientBindings
}

// isHTTPClientParameterType recognises injected http.Client values and pointers.
//
// A pointer parameter may be non-nil even though an uninitialized local is not.
// It returns true when parameterType, stripped of parentheses and one pointer, is Client on a package in httpPackageAliases, else false.
func isHTTPClientParameterType(parameterType ast.Expr, httpPackageAliases map[string]bool) bool {
	parameterType = unwrapRequestExprParens(parameterType)
	// Dependency injection commonly passes a pointer to a shared configured client.
	if pointerType, isPointer := parameterType.(*ast.StarExpr); isPointer {
		parameterType = unwrapRequestExprParens(pointerType.X)
	}
	return isHTTPClientValueType(parameterType, httpPackageAliases)
}

// isHTTPClientValueType recognises the usable zero-value http.Client type.
//
// An uninitialized *http.Client remains nil and cannot send a request, so it is intentionally not classified without a concrete initializer.
// It returns true only when clientType is a Client selector on a package in httpPackageAliases, and false for pointers and any other type.
func isHTTPClientValueType(clientType ast.Expr, httpPackageAliases map[string]bool) bool {
	selector, ok := clientType.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Client" {
		return false
	}
	packageIdentifier, ok := selector.X.(*ast.Ident)
	return ok && isImportedPackageIdentifier(packageIdentifier, httpPackageAliases)
}

// isHTTPClientExpr recognises an http.Client construction or reference.
//
// Use it while collecting client variables that can create a URL finding.
// clientExpression is the value to classify and httpPackageAliases names the net/http imports.
// It returns true for a client composite literal, the address of a recognised value, or DefaultClient on such a package, and false otherwise.
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
		return isIdentifier && isImportedPackageIdentifier(packageIdentifier, httpPackageAliases) && clientValue.Sel.Name == "DefaultClient"
	}
	return false
}
