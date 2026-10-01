// Package rule defines gruff-go's rule registry and analysers.
//
// This file proves one logged Vault storage prefix comes from fixed package constants.
// A user sees no credential warning for that storage-list label when every closure call is safe.
// Missing sibling source, mutation or aliasing keeps the warning for review.
package rule

import (
	"go/ast"
	"go/token"
	"path"

	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// isProvenFixedStorageListPrefix accepts the logged label only with fixed constants and a storage-list use.
// A missing source, unsafe caller or unproved request credential leaves the user's warning visible.
func isProvenFixedStorageListPrefix(context loggingArgContext, args []ast.Expr, index int) bool {
	// The observed log names the value as a prefix for a role-HMAC storage listing.
	if index < 2 || context.body == nil || context.unit.AST == nil {
		return false
	}
	message, messageOK := stringLiteral(args[0])
	key, keyOK := stringLiteral(args[index-1])
	loggedPrefix, nameOK := args[index].(*ast.Ident)
	// An expression or a different log role may contain real credential material.
	if !messageOK || message != "listing role HMACs" || !keyOK || key != "prefix" || !nameOK || loggedPrefix.Obj == nil {
		return false
	}
	// A value captured outside the closure may hide a credential; keep the prefix warning when that value is not classified.
	if logHasUnprovedAdditionalLogValue(args[index+1:], context.requestScope, context.osPackages) {
		return false
	}
	outerBody, closureName := fixedStoragePrefixClosure(context.unit.AST, context.body, loggedPrefix.Obj)
	// A nonlocal function or another parameter has no bounded call-site proof.
	if outerBody == nil || closureName == nil {
		return false
	}
	// The prefix must remain the original argument and be used to list storage keys after the log.
	if prefixParameterCanChange(context.body, loggedPrefix.Obj) || !closureListsStorageWithPrefix(context.body, loggedPrefix.Obj, args[index].Pos()) {
		return false
	}
	// Every caller must pass one of the two exact constants declared in a parsed sibling file.
	if !hasFixedStoragePrefixConstants(context.unit, context.projectUnits) {
		return false
	}
	return allStoragePrefixCallsUseConstants(outerBody, closureName)
}

// logHasUnprovedAdditionalLogValue keeps the prefix warning when a later value could hide a captured credential.
// A recognized secret still reports at its own argument as the user reads the log call.
func logHasUnprovedAdditionalLogValue(args []ast.Expr, scope *requestTaintScope, osPackages map[string]bool) bool {
	// A structured key or masked value cannot add raw credential bytes to the log.
	for _, arg := range args {
		// Literal keys and a fully redacted value do not need another source proof.
		if isStringLiteral(arg) || isRedactionCall(arg) {
			continue
		}
		// A request recognized inside this closure reports at its own value after the prefix is skipped.
		if scope != nil {
			// The user's request warning will point to this value when its source is known here.
			if _, proved := scope.requestSensitiveRead(arg); proved {
				continue
			}
		}
		// Recognized environment or secret values retain their own warning location.
		if isSecretEnvRead(arg, osPackages) || hasSecretIdentifier(arg) {
			continue
		}
		// An unclassified value could be an outer request alias, so the prefix cannot be cleared.
		return true
	}
	return false
}

// fixedStoragePrefixClosure finds the directly bound closure that contains the user's log call.
// Only its first string parameter can borrow the fixed-prefix proof from local call sites.
func fixedStoragePrefixClosure(file *ast.File, body *ast.BlockStmt, loggedPrefix *ast.Object) (*ast.BlockStmt, *ast.Ident) {
	// A direct assignment inside one outer function makes the closure's callers inspectable.
	for _, declaration := range file.Decls {
		outerFunction, isFunction := declaration.(*ast.FuncDecl)
		// Other declarations cannot own the observed tidy closure.
		if !isFunction || outerFunction.Body == nil {
			continue
		}
		// A direct local binding avoids guessing how a returned or nested callback is invoked.
		for _, statement := range outerFunction.Body.List {
			assignment, isAssignment := statement.(*ast.AssignStmt)
			// The observed closure has exactly one new local name and one function literal.
			if !isAssignment || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				continue
			}
			closureName, hasName := assignment.Lhs[0].(*ast.Ident)
			closure, isClosure := assignment.Rhs[0].(*ast.FuncLit)
			// A different closure or unresolved name cannot identify every caller.
			if !hasName || closureName.Obj == nil || !isClosure || closure.Body != body {
				continue
			}
			// The logged value must be the first parameter passed by each call.
			if closure.Type.Params == nil || len(closure.Type.Params.List) == 0 || len(closure.Type.Params.List[0].Names) == 0 ||
				closure.Type.Params.List[0].Names[0].Obj != loggedPrefix {
				return nil, nil
			}
			return outerFunction.Body, closureName
		}
	}
	return nil, nil
}

// closureListsStorageWithPrefix checks that the logged parameter selects a storage list after the log.
// A list using a different value does not explain what the user chose to log.
func closureListsStorageWithPrefix(body *ast.BlockStmt, prefix *ast.Object, logPosition token.Pos) bool {
	// Only a direct statement after the log can establish the observed storage role.
	for _, statement := range body.List {
		assignment, isAssignment := statement.(*ast.AssignStmt)
		// Earlier or nested calls do not prove this log's following storage-list operation.
		if !isAssignment || statement.Pos() <= logPosition || len(assignment.Rhs) != 1 {
			continue
		}
		call, isCall := assignment.Rhs[0].(*ast.CallExpr)
		// A value other than the direct call could hide a different operation.
		if !isCall || len(call.Args) != 2 || !isObjectIdentifier(call.Args[1], prefix) {
			continue
		}
		method, isMethod := call.Fun.(*ast.SelectorExpr)
		// The call must use a local storage receiver's List method.
		if !isMethod || method.Sel.Name != "List" {
			continue
		}
		receiver, isReceiver := method.X.(*ast.Ident)
		// An unresolved package selector is not evidence of the user's storage object.
		if isReceiver && receiver.Obj != nil {
			return true
		}
	}
	return false
}

// prefixParameterCanChange rejects writes or address escapes that could replace the fixed call argument.
// For example, assigning a request value before Trace keeps the warning.
func prefixParameterCanChange(body *ast.BlockStmt, prefix *ast.Object) bool {
	changed := false
	ast.Inspect(body, func(node ast.Node) bool {
		// Once the parameter can change, further source inspection cannot restore the proof.
		if changed {
			return false
		}
		switch statement := node.(type) {
		case *ast.AssignStmt:
			// Any direct assignment, including +=, may replace the value shown to the user.
			for _, target := range statement.Lhs {
				if isObjectIdentifier(target, prefix) {
					changed = true
				}
			}
		case *ast.IncDecStmt:
			changed = isObjectIdentifier(statement.X, prefix)
		case *ast.RangeStmt:
			changed = isObjectIdentifier(statement.Key, prefix) || isObjectIdentifier(statement.Value, prefix)
		case *ast.UnaryExpr:
			// Passing the address to another function could change the logged value indirectly.
			if statement.Op == token.AND && isObjectIdentifier(statement.X, prefix) {
				changed = true
			}
		}
		return true
	})
	return changed
}

// hasFixedStoragePrefixConstants verifies the two package constants behind the observed calls.
// A missing, duplicate, mutable or changed sibling declaration cannot clear a warning.
func hasFixedStoragePrefixConstants(unit parser.Unit, projectUnits []parser.Unit) bool {
	found := map[string]bool{}
	// Only parsed Go files in the same directory and package can define the caller's constants.
	for _, sibling := range projectUnits {
		// Other file types and directories cannot supply a Go package constant.
		if sibling.File.Type != source.FileTypeGo || !isProductionCodePath(sibling.File.Path) ||
			path.Dir(sibling.File.Path) != path.Dir(unit.File.Path) {
			continue
		}
		// A parse failure in this package leaves sibling declarations unresolved.
		if sibling.AST == nil {
			return false
		}
		// A different package name has no bearing on the observed handler.
		if sibling.AST.Name.Name != unit.AST.Name.Name {
			continue
		}
		// A declaration failure means the user's package value has no fixed source proof.
		if !collectSiblingStorageConstants(sibling, unit.File.Path, found) {
			return false
		}
	}
	return found["secretIDPrefix"] && found["secretIDLocalPrefix"]
}

// collectSiblingStorageConstants reads package declarations without treating local variables as fixed.
// A function or unrelated declaration leaves the two required names for another sibling.
func collectSiblingStorageConstants(sibling parser.Unit, handlerPath string, found map[string]bool) bool {
	// Only top-level declarations can establish package-wide fixed values.
	for _, declaration := range sibling.AST.Decls {
		group, isGroup := declaration.(*ast.GenDecl)
		// A function or method is not a constant declaration.
		if !isGroup {
			continue
		}
		// Each declared value must satisfy the exact sibling constant check.
		for _, specification := range group.Specs {
			values, hasValues := specification.(*ast.ValueSpec)
			// Type declarations do not define either fixed prefix.
			if !hasValues {
				continue
			}
			// A variable or duplicate under a required name invalidates the package proof.
			if !recordFixedStorageValues(values, group.Tok, sibling.File.Path != handlerPath, found) {
				return false
			}
		}
	}
	return true
}

// recordFixedStorageValues accepts only exact literal constants in a different file.
// A changed prefix, duplicate name or variable keeps the user's warning visible.
func recordFixedStorageValues(values *ast.ValueSpec, declarationKind token.Token, isSibling bool, found map[string]bool) bool {
	// Each required name needs its own literal value; unrelated names have no bearing on this warning.
	for index, name := range values.Names {
		expected, isPrefix := fixedStoragePrefixLiteral(name.Name)
		if !isPrefix {
			continue
		}
		// The handler's own declaration or a mutable source cannot establish a sibling constant.
		if !isSibling || declarationKind != token.CONST || found[name.Name] || len(values.Values) != len(values.Names) {
			return false
		}
		literal, isLiteral := stringLiteral(values.Values[index])
		// A derived value or a different literal may carry something other than this fixed storage label.
		if !isLiteral || literal != expected {
			return false
		}
		found[name.Name] = true
	}
	return true
}

// fixedStoragePrefixLiteral names the two exact public storage labels observed in Vault.
// Other names, including secret-bearing variables, receive no exception.
func fixedStoragePrefixLiteral(name string) (string, bool) {
	switch name {
	case "secretIDPrefix":
		return "secret_id/", true
	case "secretIDLocalPrefix":
		return "secret_id_local/", true
	}
	return "", false
}

// allStoragePrefixCallsUseConstants proves every use of the local closure is a direct safe call.
// An alias, escaped callback or secret-derived argument leaves the user's warning visible.
func allStoragePrefixCallsUseConstants(outerBody *ast.BlockStmt, closureName *ast.Ident) bool {
	allowedUses := map[*ast.Ident]bool{closureName: true}
	callCount := 0
	valid := true
	ast.Inspect(outerBody, func(node ast.Node) bool {
		// A nested closure's invocation cannot be tied to the direct calls in this function.
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, isCall := node.(*ast.CallExpr)
		// Only calls to the observed local closure need call-argument checks.
		if !isCall || !valid {
			return valid
		}
		callee, hasName := call.Fun.(*ast.Ident)
		// A different function cannot affect the observed prefix.
		if !hasName || callee.Obj != closureName.Obj {
			return true
		}
		// A direct call must pass one of the known package constants as its first argument.
		if len(call.Args) == 0 {
			valid = false
			return false
		}
		prefix, isName := call.Args[0].(*ast.Ident)
		// A local shadow or expression might contain a real credential despite the same name.
		if !isName || prefix.Obj != nil {
			valid = false
			return false
		}
		_, isFixedName := fixedStoragePrefixLiteral(prefix.Name)
		// A different package value cannot inherit the sibling constants' proof.
		if !isFixedName {
			valid = false
			return false
		}
		allowedUses[callee] = true
		callCount++
		return true
	})
	// No direct call means the user could invoke the closure through an unresolved path.
	if !valid || callCount == 0 {
		return false
	}
	ast.Inspect(outerBody, func(node ast.Node) bool {
		name, isName := node.(*ast.Ident)
		// A reference other than the binding or certified calls may alias, escape or rewrite the closure.
		if isName && name.Obj == closureName.Obj && !allowedUses[name] {
			valid = false
			return false
		}
		return true
	})
	return valid
}
