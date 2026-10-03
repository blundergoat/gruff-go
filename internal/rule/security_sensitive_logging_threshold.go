// Package rule defines gruff-go's rule registry and analysers.
//
// This file recognizes a seal's required share count in a structured log.
//
// A user sees no credential warning when the same function proves the value is a count.
// Source, progress and result checks keep other secret-looking integers visible.
package rule

import (
	"go/ast"
	"go/token"
)

// isProvenSealShareThreshold accepts only the logged share count with its local source and progress role.
// A missing source, comparison or returned required count leaves the user's warning in place.
func isProvenSealShareThreshold(body *ast.BlockStmt, args []ast.Expr, index int) bool {
	// A structured threshold needs a preceding key and a progress value in the same log record.
	if index < 3 || body == nil {
		return false
	}
	key, keyOK := stringLiteral(args[index-1])
	progressKey, progressKeyOK := stringLiteral(args[index-3])
	config := sealThresholdReceiver(args[index])
	// Only the observed threshold and keys fields can claim this share-count role.
	if !keyOK || key != "threshold" || !progressKeyOK || progressKey != "keys" || config == nil {
		return false
	}
	core := sealConfigSourceCore(body, config, args[index].Pos())
	// A configuration object with another source might hold a secret despite its field name.
	if core == nil {
		return false
	}
	progress := shareProgressObject(body, core, args[index].Pos())
	// The logged progress must be the same count used in the comparison and result.
	if progress == nil || !isObjectIdentifier(args[index-2], progress) {
		return false
	}
	return branchReturnsRequiredShareCount(body, args[index], config, core, progress)
}

// sealThresholdReceiver returns the local configuration object behind a logged SecretThreshold field.
func sealThresholdReceiver(value ast.Expr) *ast.Object {
	field, ok := value.(*ast.SelectorExpr)
	// An expression other than the direct field could contain a secret calculation.
	if !ok || field.Sel.Name != "SecretThreshold" {
		return nil
	}
	config, ok := field.X.(*ast.Ident)
	// A package name or unresolved value has no local configuration source to inspect.
	if !ok {
		return nil
	}
	return config.Obj
}

// sealConfigSourceCore proves the local SealConfig came only from the two seal configuration reads.
// The core receiver is returned so progress can be tied to that same seal update.
func sealConfigSourceCore(body *ast.BlockStmt, config *ast.Object, logPosition token.Pos) *ast.Object {
	declared := false
	var sourceCore *ast.Object
	// A direct local declaration and one complete branch precede the user's log call.
	for _, statement := range body.List {
		// Later statements cannot establish the value already sent to the log.
		if statement.Pos() >= logPosition {
			break
		}
		// The named SealConfig type supplies context beyond a SecretThreshold suffix.
		if isLocalSealConfigDeclaration(statement, config) {
			declared = true
		}
		branch, ok := statement.(*ast.IfStmt)
		// The source must be the observed recovery-or-barrier choice in this function.
		if !ok {
			continue
		}
		candidate := sealConfigBranchCore(branch, config)
		// More than one matching source branch would leave the chosen value ambiguous.
		if candidate != nil {
			// Two matching branches cannot prove which configuration reached the log.
			if sourceCore != nil {
				return nil
			}
			sourceCore = candidate
		}
	}
	// An alternate write or direct field overwrite can turn a share count into a secret integer.
	if !declared || sourceCore == nil || localObjectWriteCount(body, config) != 2 ||
		sealConfigDataIsWritten(body, config) || sealConfigAliasOrAddressEscapes(body, config) {
		return nil
	}
	return sourceCore
}

// isLocalSealConfigDeclaration recognizes an unseeded local pointer, as in a user starting a seal update.
func isLocalSealConfigDeclaration(statement ast.Stmt, config *ast.Object) bool {
	declaration, ok := statement.(*ast.DeclStmt)
	// A function parameter or seeded alias does not establish the observed configuration source.
	if !ok {
		return false
	}
	group, ok := declaration.Decl.(*ast.GenDecl)
	// Only one local var declaration is needed for this source proof.
	if !ok || group.Tok != token.VAR || len(group.Specs) != 1 {
		return false
	}
	value, ok := group.Specs[0].(*ast.ValueSpec)
	// A supplied initial value could bypass the seal configuration reads.
	if !ok || len(value.Names) != 1 || value.Names[0].Obj != config || len(value.Values) != 0 {
		return false
	}
	pointer, ok := value.Type.(*ast.StarExpr)
	// A different type gives the field name no share-count meaning here.
	if !ok {
		return false
	}
	kind, ok := pointer.X.(*ast.Ident)
	return ok && kind.Name == "SealConfig"
}

// sealConfigBranchCore checks both alternatives of a recovery-or-barrier configuration choice.
func sealConfigBranchCore(branch *ast.IfStmt, config *ast.Object) *ast.Object {
	// An else-if chain does not give the user the same two bounded source choices.
	if branch.Init != nil {
		return nil
	}
	elseBody, ok := branch.Else.(*ast.BlockStmt)
	// Both seal modes must assign the local config before the log can use it.
	if !ok {
		return nil
	}
	recoveryCore := sealConfigMethodCore(branch.Cond, "RecoveryKeySupported")
	// The mode check and both configuration calls must address the same core object.
	if recoveryCore == nil ||
		!branchAssignsSealConfig(branch.Body, config, recoveryCore, "RecoveryConfig") ||
		!branchAssignsSealConfig(elseBody, config, recoveryCore, "BarrierConfig") {
		return nil
	}
	return recoveryCore
}

// branchAssignsSealConfig requires one direct config assignment in a source branch.
// An error check may follow, but nested closures cannot provide the user's config.
func branchAssignsSealConfig(branch *ast.BlockStmt, config, core *ast.Object, method string) bool {
	matches := 0
	// A branch can check an error after obtaining its seal configuration.
	for _, statement := range branch.List {
		assignment, ok := statement.(*ast.AssignStmt)
		// Only direct assignments in this branch establish the logged source.
		if !ok || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 || assignment.Tok != token.ASSIGN ||
			!isObjectIdentifier(assignment.Lhs[0], config) {
			continue
		}
		// A method on another core object cannot prove this update's count.
		if sealConfigMethodCore(assignment.Rhs[0], method) == core {
			matches++
		}
	}
	return matches == 1
}

// sealConfigMethodCore returns the core behind c.seal.Method when the call has the expected role.
func sealConfigMethodCore(value ast.Expr, method string) *ast.Object {
	call, ok := value.(*ast.CallExpr)
	// An alias or composite expression could read a different configuration.
	if !ok {
		return nil
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	// The call name distinguishes recovery, barrier and mode checks.
	if !ok || selector.Sel.Name != method {
		return nil
	}
	seal, ok := selector.X.(*ast.SelectorExpr)
	// The seal must belong to the same core used for progress.
	if !ok || seal.Sel.Name != "seal" {
		return nil
	}
	core, ok := seal.X.(*ast.Ident)
	// A local object identity keeps lookalike receivers separate.
	if !ok {
		return nil
	}
	return core.Obj
}

// localObjectWriteCount counts every assignment to one local value, including unsafe extra writes.
func localObjectWriteCount(body *ast.BlockStmt, object *ast.Object) int {
	writes := 0
	ast.Inspect(body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		// Other syntax does not replace the local configuration pointer.
		if !ok {
			return true
		}
		// Any later replacement invalidates the source proof for the user.
		for _, target := range assignment.Lhs {
			// Only writes to this specific local object matter.
			if isObjectIdentifier(target, object) {
				writes++
			}
		}
		return true
	})
	return writes
}

// sealConfigDataIsWritten catches direct or dereferenced writes to a local seal configuration.
func sealConfigDataIsWritten(body *ast.BlockStmt, config *ast.Object) bool {
	written := false
	ast.Inspect(body, func(node ast.Node) bool {
		// An increment changes the count even without an assignment statement.
		if increment, ok := node.(*ast.IncDecStmt); ok && writeTargetsLocalConfigData(increment.X, config) {
			written = true
			return false
		}
		assignment, ok := node.(*ast.AssignStmt)
		// An unrelated statement cannot overwrite the share threshold.
		if !ok {
			return true
		}
		// A field or pointer write removes the original seal count's source proof.
		for _, target := range assignment.Lhs {
			// A different receiver's write does not change the logged config.
			if writeTargetsLocalConfigData(target, config) {
				written = true
			}
		}
		return true
	})
	return written
}

// writeTargetsLocalConfigData recognizes a write through this pointer without treating its source assignments as data writes.
func writeTargetsLocalConfigData(target ast.Expr, config *ast.Object) bool {
	// The two direct assignments to config are counted separately as source choices.
	if isObjectIdentifier(target, config) {
		return false
	}
	found := false
	ast.Inspect(target, func(node ast.Node) bool {
		name, ok := node.(*ast.Ident)
		// A nested pointer or field target can still update the logged config.
		if ok && name.Obj == config {
			found = true
			return false
		}
		return true
	})
	return found
}

// sealConfigAliasOrAddressEscapes rejects a config pointer that another name or call could mutate.
// The user keeps a warning when the original seal count can change unseen.
func sealConfigAliasOrAddressEscapes(body *ast.BlockStmt, config *ast.Object) bool {
	escaped := false
	ast.Inspect(body, func(node ast.Node) bool {
		// Once an escape is seen, later syntax cannot restore the source proof.
		if escaped {
			return false
		}
		switch value := node.(type) {
		case *ast.ValueSpec:
			// A var declaration can create an alias without using an assignment statement.
			for _, source := range value.Values {
				// The alias could change the share count before it is logged.
				if expressionExposesConfigPointer(source, config) {
					escaped = true
				}
			}
		case *ast.AssignStmt:
			// A second pointer name could write SecretThreshold before the log.
			for _, source := range value.Rhs {
				// Direct aliasing of this local pointer removes the unique-write guarantee.
				if expressionExposesConfigPointer(source, config) {
					escaped = true
				}
			}
		case *ast.CallExpr:
			selector, ok := value.Fun.(*ast.SelectorExpr)
			// A method on the config pointer may change the count internally.
			if ok && isObjectIdentifier(selector.X, config) {
				escaped = true
			}
			// Passing the config pointer to a helper could let that helper change the count.
			for _, argument := range value.Args {
				// Field values are copied; the whole pointer is the unsafe argument.
				if expressionExposesConfigPointer(argument, config) {
					escaped = true
				}
			}
		case *ast.UnaryExpr:
			// Taking the address of the count or config could expose it to a later write.
			if value.Op == token.AND && (isObjectIdentifier(value.X, config) || isSealThresholdField(value.X, config)) {
				escaped = true
			}
		}
		return !escaped
	})
	return escaped
}

// expressionExposesConfigPointer finds a raw config pointer inside a stored or passed expression.
// Reading a field copies its value; embedding the pointer lets another owner change the count.
func expressionExposesConfigPointer(value ast.Expr, config *ast.Object) bool {
	exposed := false
	ast.Inspect(value, func(node ast.Node) bool {
		field, ok := node.(*ast.SelectorExpr)
		// A direct field read is a value, so its receiver is not a pointer escape.
		if ok && isObjectIdentifier(field.X, config) {
			return false
		}
		name, ok := node.(*ast.Ident)
		// A raw config identifier in a collection or call can be aliased later.
		if ok && name.Obj == config {
			exposed = true
			return false
		}
		return true
	})
	return exposed
}

// objectAddressEscapes rejects a progress count passed by address to a mutating helper.
func objectAddressEscapes(body *ast.BlockStmt, object *ast.Object) bool {
	escaped := false
	ast.Inspect(body, func(node ast.Node) bool {
		address, ok := node.(*ast.UnaryExpr)
		// A plain log argument copies the count; an address can change it before logging.
		if ok && address.Op == token.AND && isObjectIdentifier(address.X, object) {
			escaped = true
			return false
		}
		return true
	})
	return escaped
}

// shareProgressObject finds the one local count of this core's collected shares before logging.
func shareProgressObject(body *ast.BlockStmt, core *ast.Object, logPosition token.Pos) *ast.Object {
	var progress *ast.Object
	// The progress shown in the log must already have been counted.
	for _, statement := range body.List {
		// Later statements cannot explain the progress already logged.
		if statement.Pos() >= logPosition {
			break
		}
		assignment, ok := statement.(*ast.AssignStmt)
		// Only a direct local count is accepted.
		if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			continue
		}
		name, ok := assignment.Lhs[0].(*ast.Ident)
		// A count from another core's progress is not this update's count.
		if !ok || name.Obj == nil || !isShareProgressLength(assignment.Rhs[0], core) {
			continue
		}
		// Multiple candidate counters make the logged value's role ambiguous.
		if progress != nil {
			return nil
		}
		progress = name.Obj
	}
	// An overwritten progress variable could carry a secret integer under the keys label.
	if progress == nil || localObjectWriteCount(body, progress) != 1 || objectAddressEscapes(body, progress) {
		return nil
	}
	return progress
}

// isShareProgressLength recognizes len(c.generateRootProgress) for the same core object.
func isShareProgressLength(value ast.Expr, core *ast.Object) bool {
	call, ok := value.(*ast.CallExpr)
	// Arithmetic or another collection does not establish a share count.
	if !ok || len(call.Args) != 1 {
		return false
	}
	builtin, ok := call.Fun.(*ast.Ident)
	// A shadowed len function may return something other than a collection count.
	if !ok || builtin.Name != "len" || builtin.Obj != nil {
		return false
	}
	progress, ok := call.Args[0].(*ast.SelectorExpr)
	// The count must come from this core's collected root shares.
	if !ok || progress.Sel.Name != "generateRootProgress" {
		return false
	}
	return isObjectIdentifier(progress.X, core)
}

// branchReturnsRequiredShareCount ties the logged threshold to the progress comparison and user-facing result.
func branchReturnsRequiredShareCount(body *ast.BlockStmt, loggedValue ast.Expr, config, core, progress *ast.Object) bool {
	// The log must sit inside the insufficient-shares branch, before its result.
	for _, statement := range body.List {
		branch, ok := statement.(*ast.IfStmt)
		// Another branch cannot establish the logged value's progress role.
		if !ok || branch.Body == nil || loggedValue.Pos() < branch.Body.Pos() || loggedValue.End() > branch.Body.End() {
			continue
		}
		comparison, ok := branch.Cond.(*ast.BinaryExpr)
		// A share threshold is the minimum count compared with collected shares.
		if !ok || comparison.Op != token.LSS || !isShareProgressLength(comparison.X, core) ||
			!isSealThresholdField(comparison.Y, config) {
			continue
		}
		// The returned Required count tells the user how many shares are still needed.
		for _, result := range branch.Body.List {
			// An earlier or unrelated result cannot explain this log record.
			if result.Pos() > loggedValue.Pos() && returnsRequiredShareCount(result, config, progress) {
				return true
			}
		}
	}
	return false
}

// returnsRequiredShareCount matches the progress and required fields of a root-generation result.
func returnsRequiredShareCount(statement ast.Stmt, config, progress *ast.Object) bool {
	result, ok := statement.(*ast.ReturnStmt)
	// A later assignment does not prove what the user receives from this branch.
	if !ok || len(result.Results) == 0 {
		return false
	}
	address, ok := result.Results[0].(*ast.UnaryExpr)
	// The observed result is a newly constructed GenerateRootResult.
	if !ok || address.Op != token.AND {
		return false
	}
	literal, ok := address.X.(*ast.CompositeLit)
	// Another result type may assign a very different meaning to Required.
	if !ok {
		return false
	}
	kind, ok := literal.Type.(*ast.Ident)
	// Only the root-generation result reports required share counts.
	if !ok || kind.Name != "GenerateRootResult" {
		return false
	}
	progressSeen, requiredSeen := false, false
	// Both fields must describe the same progress and threshold as the log.
	for _, element := range literal.Elts {
		field, ok := element.(*ast.KeyValueExpr)
		// Positional fields cannot establish which count reaches the user.
		if !ok {
			continue
		}
		name, ok := field.Key.(*ast.Ident)
		// An unknown field gives no count role.
		if !ok {
			continue
		}
		// Each result field supplies one part of the share-count proof.
		if name.Name == "Progress" && isObjectIdentifier(field.Value, progress) {
			progressSeen = true
		}
		// The required count must be the exact field that was logged.
		if name.Name == "Required" && isSealThresholdField(field.Value, config) {
			requiredSeen = true
		}
	}
	return progressSeen && requiredSeen
}

// isSealThresholdField checks that a value reads this exact local config's threshold.
func isSealThresholdField(value ast.Expr, config *ast.Object) bool {
	field, ok := value.(*ast.SelectorExpr)
	return ok && field.Sel.Name == "SecretThreshold" && isObjectIdentifier(field.X, config)
}

// isObjectIdentifier checks a local binding so similarly named values cannot borrow its count proof.
func isObjectIdentifier(value ast.Expr, object *ast.Object) bool {
	name, ok := value.(*ast.Ident)
	return ok && object != nil && name.Obj == object
}
