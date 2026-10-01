// Package rule defines gruff-go's rule registry and analysers.
// A developer scanning Go code sees weak-digest warnings when local names or use suggest security-sensitive values.
// A digest used only to choose a numbered storage bucket stays quiet when the full local flow proves that role.
package rule

import (
	"go/ast"
	"go/token"
	"strconv"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// weakDigestContextWords names security contexts where MD5/SHA1 should not be used.
var weakDigestContextWords = []string{
	"auth",
	"credential",
	"csrf",
	"key",
	"nonce",
	"otp",
	"password",
	"passwd",
	"salt",
	"secret",
	"session",
	"signature",
	"signing",
	"token",
}

// weakDigestAPIs are crypto/md5 and crypto/sha1 constructors or digest helpers.
var weakDigestAPIs = map[string]bool{
	"New": true,
	"Sum": true,
}

// weakCryptoCallContext carries evidence for one weak crypto finding.
type weakCryptoCallContext struct {
	primitive string
	reason    string
}

// WeakCryptoRule flags weak cryptographic primitives in concrete parser-only shapes.
type WeakCryptoRule struct{}

// Definition declares the security.weak-crypto rule for weak primitive usage.
func (WeakCryptoRule) Definition() Definition {
	return Definition{
		ID:             "security.weak-crypto",
		Title:          "Weak crypto primitive",
		Description:    "Flags MD5/SHA1 in security-looking contexts, direct DES/RC4 construction, and RSA key generation below 2048 bits.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"crypto", "security"},
		Remediation:    "Use modern primitives such as SHA-256 or HMAC-SHA-256 for security hashes, AES-GCM or ChaCha20-Poly1305 for encryption, and RSA keys of at least 2048 bits.",
	}
}

// AnalyzeUnit emits findings for weak crypto primitives with concrete local evidence.
func (WeakCryptoRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	packages := weakCryptoPackages{
		md5:     packageImportNames(unit.AST, "crypto/md5", "md5"),
		sha1:    packageImportNames(unit.AST, "crypto/sha1", "sha1"),
		des:     packageImportNames(unit.AST, "crypto/des", "des"),
		rc4:     packageImportNames(unit.AST, "crypto/rc4", "rc4"),
		rsa:     packageImportNames(unit.AST, "crypto/rsa", "rsa"),
		strconv: packageImportNames(unit.AST, "strconv", "strconv"),
	}
	if !packages.any() {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		parents := astParentMap(fn.Body)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			context, ok := weakCryptoCall(call, fn, parents, packages)
			if !ok {
				return true
			}
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "weak cryptographic primitive used",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Metadata: map[string]any{
					"primitive": context.primitive,
					"reason":    context.reason,
				},
			})
			return true
		})
	}
	return findings
}

// weakCryptoPackages groups weak-crypto imports and the standard decimal conversion used to prove a storage index.
type weakCryptoPackages struct {
	md5     map[string]bool
	sha1    map[string]bool
	des     map[string]bool
	rc4     map[string]bool
	rsa     map[string]bool
	strconv map[string]bool
}

// any reports whether at least one weak-crypto package was imported.
func (p weakCryptoPackages) any() bool {
	return len(p.md5) > 0 || len(p.sha1) > 0 || len(p.des) > 0 || len(p.rc4) > 0 || len(p.rsa) > 0
}

// weakCryptoCall classifies a weak-crypto call when the parser-only evidence is strong enough.
func weakCryptoCall(call *ast.CallExpr, fn *ast.FuncDecl, parents map[ast.Node]ast.Node, packages weakCryptoPackages) (weakCryptoCallContext, bool) {
	if primitive, ok := weakDigestCall(call, packages.md5, "md5"); ok {
		// A storage bucket keyed by one digest byte is a location choice, so the user should not see a weak-key warning.
		if digestChoosesStorageBucket(call, fn, parents, packages.strconv) {
			return weakCryptoCallContext{}, false
		}
		if word, contextOK := weakDigestSecurityContext(call, fn, parents); contextOK {
			return weakCryptoCallContext{primitive: primitive, reason: word}, true
		}
		return weakCryptoCallContext{}, false
	}
	if primitive, ok := weakDigestCall(call, packages.sha1, "sha1"); ok {
		// The same numbered-bucket proof applies to SHA-1; a full digest or a secret input still reports.
		if digestChoosesStorageBucket(call, fn, parents, packages.strconv) {
			return weakCryptoCallContext{}, false
		}
		if word, contextOK := weakDigestSecurityContext(call, fn, parents); contextOK {
			return weakCryptoCallContext{primitive: primitive, reason: word}, true
		}
		return weakCryptoCallContext{}, false
	}
	if selectorCallMatches(call, packages.des, "NewCipher") {
		return weakCryptoCallContext{primitive: "DES", reason: "obsolete-block-cipher"}, true
	}
	if selectorCallMatches(call, packages.des, "NewTripleDESCipher") {
		return weakCryptoCallContext{primitive: "3DES", reason: "obsolete-block-cipher"}, true
	}
	if selectorCallMatches(call, packages.rc4, "NewCipher") {
		return weakCryptoCallContext{primitive: "RC4", reason: "obsolete-stream-cipher"}, true
	}
	if bits, ok := rsaGenerateKeyBits(call, packages.rsa); ok && bits < 2048 {
		return weakCryptoCallContext{primitive: "RSA", reason: "key-size-" + strconv.Itoa(bits)}, true
	}
	return weakCryptoCallContext{}, false
}

// digestChoosesStorageBucket accepts a local MD5/SHA-1 constructor only when its sole digest use selects a decimal bucket number.
// A developer still sees a warning when the function hashes a secret, returns key material, or lacks the complete bucket flow.
func digestChoosesStorageBucket(
	digestCall *ast.CallExpr,
	function *ast.FuncDecl,
	parents map[ast.Node]ast.Node,
	strconvPackages map[string]bool,
) bool {
	// The method and documented return must describe a storage location before value-flow proof can quiet the warning.
	if !digestHasStorageBucketPurpose(digestCall, function) {
		return false
	}
	assignment, assigned := parents[digestCall].(*ast.AssignStmt)
	// An unnamed or reassigned hasher cannot prove where its digest goes.
	if !assigned || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return false
	}
	hasher, named := assignment.Lhs[0].(*ast.Ident)
	// Parser object identity keeps a same-spelled variable in another scope from borrowing this exception.
	if !named || hasher.Obj == nil {
		return false
	}
	// A security-named hasher is stronger evidence than the enclosing bucket-shaped method name.
	if _, securityHasher := weakDigestContextWord(hasher.Name); securityHasher {
		return false
	}
	bucketIndex := bucketDigestIndex(function.Body, hasher, parents)
	// A complete local flow needs one input, one first-byte digest and a decimal bucket return.
	return bucketIndex != nil && returnsDecimalBucket(function, bucketIndex, strconvPackages)
}

// digestHasStorageBucketPurpose checks that a developer-facing name, description and string result describe a numbered storage location.
// Any authentication or secret word preserves the security warning.
func digestHasStorageBucketPurpose(digestCall *ast.CallExpr, function *ast.FuncDecl) bool {
	selector, selectorOK := digestCall.Fun.(*ast.SelectorExpr)
	nameContext, hasNameContext := weakDigestContextWord(function.Name.Name)
	_, hasBucketName := firstContextWord(function.Name.Name, []string{"bucket"})
	// A bucket-shaped name cannot excuse a password or authentication function.
	if !selectorOK || selector.Sel.Name != "New" || len(digestCall.Args) != 0 || !hasBucketName || !hasNameContext || nameContext != "key" {
		return false
	}
	// A security word anywhere in the function name keeps an authentication or token use visible.
	if hasNonKeyDigestContext(function.Name.Name) {
		return false
	}
	// A storage bucket key is a string path; a numeric or opaque result has another role.
	if function.Type.Results == nil || len(function.Type.Results.List) != 1 {
		return false
	}
	resultType, isString := function.Type.Results.List[0].Type.(*ast.Ident)
	if !isString || resultType.Name != "string" {
		return false
	}
	// A documented security purpose overrides the storage-bucket shape.
	if function.Doc != nil && hasNonKeyDigestContext(function.Doc.Text()) {
		return false
	}
	return true
}

// bucketDigestIndex proves that one local hasher reads nonsecret input and exposes only one byte as a named bucket index.
// Copying the hasher or using its full digest keeps the warning visible to the developer.
func bucketDigestIndex(body *ast.BlockStmt, hasher *ast.Ident, parents map[ast.Node]ast.Node) *ast.Object {
	var bucketIndex *ast.Object
	writes, sums := 0, 0
	safe := true
	ast.Inspect(body, func(node ast.Node) bool {
		use, isName := node.(*ast.Ident)
		// Only uses of this hasher can establish or break the bucket-only flow.
		if !isName || use == hasher || use.Obj != hasher.Obj {
			return true
		}
		method, isMethod := parents[use].(*ast.SelectorExpr)
		// A copied, returned, or reassigned hasher could be used as key material elsewhere.
		if !isMethod || method.X != use {
			safe = false
			return false
		}
		methodCall, isCall := parents[method].(*ast.CallExpr)
		// Only an actual Write or Sum invocation supplies evidence of how the hasher is used.
		if !isCall || methodCall.Fun != method {
			safe = false
			return false
		}
		switch method.Sel.Name {
		case "Write":
			writes++
			// A secret-bearing input makes even a one-byte digest a security-relevant use.
			if len(methodCall.Args) != 1 {
				safe = false
				return false
			}
			if !bucketInputHasNonsecretOrigin(body, methodCall.Args[0], 0) {
				safe = false
				return false
			}
		case "Sum":
			sums++
			index, indexed := parents[methodCall].(*ast.IndexExpr)
			// The complete digest must stay out of the result; only its first byte may select a bucket.
			if !indexed || index.X != methodCall || len(methodCall.Args) != 1 || !isNilIdentifier(methodCall.Args[0]) || !isZeroIndex(index.Index) {
				safe = false
				return false
			}
			bucketIndex = assignedBucketIndex(index, parents)
			// A digest byte without a named bucket index does not prove storage use.
			if bucketIndex == nil {
				safe = false
				return false
			}
		default:
			safe = false
			return false
		}
		return true
	})
	// Without exactly one Write and one Sum, the caller cannot claim a storage-only digest.
	if !safe || writes != 1 || sums != 1 {
		return nil
	}
	return bucketIndex
}

// bucketInputHasNonsecretOrigin follows single-use local aliases to a neutral parameter or literal.
// Rebinding, borrowing, unknown transformations and security-named origins keep the digest warning.
func bucketInputHasNonsecretOrigin(body *ast.BlockStmt, input ast.Expr, depth int) bool {
	if _, securityInput := exprTextContext(input, weakDigestContextWord); securityInput || depth > 8 {
		return false
	}
	switch value := input.(type) {
	case *ast.ParenExpr:
		return bucketInputHasNonsecretOrigin(body, value.X, depth+1)
	case *ast.BasicLit:
		return value.Kind == token.STRING
	case *ast.CallExpr:
		kind, isBytes := value.Fun.(*ast.ArrayType)
		if !isBytes || kind.Len != nil || len(value.Args) != 1 {
			return false
		}
		element, isByte := kind.Elt.(*ast.Ident)
		return isByte && element.Name == "byte" && element.Obj == nil && bucketInputHasNonsecretOrigin(body, value.Args[0], depth+1)
	case *ast.Ident:
		return bucketInputNameHasNonsecretOrigin(body, value, depth)
	}
	return false
}

// bucketInputNameHasNonsecretOrigin rejects locals with extra uses that could modify or escape their bytes.
func bucketInputNameHasNonsecretOrigin(body *ast.BlockStmt, name *ast.Ident, depth int) bool {
	if name.Obj == nil {
		return false
	}
	uses := 0
	ast.Inspect(body, func(node ast.Node) bool {
		if use, named := node.(*ast.Ident); named && use.Obj == name.Obj {
			uses++
		}
		return true
	})
	if _, parameter := name.Obj.Decl.(*ast.Field); parameter {
		return uses == 1
	}
	assignment, assigned := name.Obj.Decl.(*ast.AssignStmt)
	if !assigned || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return false
	}
	return uses == 2 && bucketInputHasNonsecretOrigin(body, assignment.Rhs[0], depth+1)
}

// hasNonKeyDigestContext keeps explicit security descriptions from being hidden by a storage-bucket name.
func hasNonKeyDigestContext(description string) bool {
	for _, word := range weakDigestContextWords {
		// A storage key names a location; other security words describe material that needs a warning.
		if word == "key" {
			continue
		}
		if _, present := firstContextWord(description, []string{word}); present {
			return true
		}
	}
	return false
}

// isNilIdentifier accepts Sum(nil), which reads the digest without appending it to another value.
func isNilIdentifier(expression ast.Expr) bool {
	name, ok := expression.(*ast.Ident)
	return ok && name.Name == "nil" && name.Obj == nil
}

// isZeroIndex accepts only the first digest byte, the bounded value used for a numbered storage bucket.
func isZeroIndex(expression ast.Expr) bool {
	literal, ok := expression.(*ast.BasicLit)
	return ok && literal.Kind == token.INT && literal.Value == "0"
}

// assignedBucketIndex returns the local index receiving one digest byte; other destinations keep the weak-crypto warning.
func assignedBucketIndex(digestByte *ast.IndexExpr, parents map[ast.Node]ast.Node) *ast.Object {
	for parent := parents[digestByte]; parent != nil; parent = parents[parent] {
		assignment, ok := parent.(*ast.AssignStmt)
		// Only a direct, named bucket index can be followed to the returned storage path.
		if !ok {
			switch expression := parent.(type) {
			case *ast.ParenExpr:
				continue
			case *ast.CallExpr:
				cast, builtin := expression.Fun.(*ast.Ident)
				if builtin && cast.Obj == nil && (cast.Name == "uint8" || cast.Name == "int") && len(expression.Args) == 1 {
					continue
				}
			}
			return nil
		}
		if assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return nil
		}
		name, named := assignment.Lhs[0].(*ast.Ident)
		// The variable's index role must be visible in source, beyond the function's Key suffix.
		if !named || name.Obj == nil {
			return nil
		}
		if _, isIndex := firstContextWord(name.Name, []string{"index"}); !isIndex {
			return nil
		}
		return name.Obj
	}
	return nil
}

// returnsDecimalBucket proves the first digest byte becomes a decimal suffix on a nonsecurity storage prefix.
func returnsDecimalBucket(function *ast.FuncDecl, bucketIndex *ast.Object, strconvPackages map[string]bool) bool {
	uses := 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		name, isName := node.(*ast.Ident)
		// A bucket index used anywhere beyond its declaration and returned suffix may carry a security value.
		if isName && name.Obj == bucketIndex {
			uses++
		}
		return true
	})
	// The source needs exactly one declaration and one return use of the selected digest byte.
	if uses != 2 {
		return false
	}
	for _, statement := range function.Body.List {
		result, isReturn := statement.(*ast.ReturnStmt)
		// An early empty return has no bucket key to classify.
		if !isReturn || len(result.Results) != 1 {
			continue
		}
		joined, isJoin := result.Results[0].(*ast.BinaryExpr)
		// The user-facing storage key must be a prefix plus a decimal bucket number.
		if !isJoin || joined.Op != token.ADD {
			continue
		}
		decimalCall, isCall := joined.Y.(*ast.CallExpr)
		// A different conversion could expose the digest as security key material.
		if !isCall || !selectorCallMatches(decimalCall, strconvPackages, "Itoa") || len(decimalCall.Args) != 1 {
			continue
		}
		decimalSelector := decimalCall.Fun.(*ast.SelectorExpr)
		decimalPackage := decimalSelector.X.(*ast.Ident)
		// A local object named strconv cannot certify the standard decimal conversion.
		if decimalPackage.Obj != nil {
			continue
		}
		// A security-named prefix means the returned value may be a credential or signature.
		if _, securityPrefix := exprTextContext(joined.X, weakDigestContextWord); securityPrefix {
			continue
		}
		if isBucketIndexArgument(decimalCall.Args[0], bucketIndex) {
			return true
		}
	}
	return false
}

// isBucketIndexArgument accepts an index byte directly or through Go's int conversion for strconv.Itoa.
func isBucketIndexArgument(argument ast.Expr, bucketIndex *ast.Object) bool {
	name, isName := argument.(*ast.Ident)
	// A different integer could make a decoy bucket return hide another digest use.
	if isName {
		return name.Obj == bucketIndex
	}
	conversion, isCall := argument.(*ast.CallExpr)
	// The observed Go source converts its byte index to int before writing the decimal suffix.
	if !isCall || len(conversion.Args) != 1 {
		return false
	}
	cast, isInt := conversion.Fun.(*ast.Ident)
	return isInt && cast.Name == "int" && cast.Obj == nil && isBucketIndexArgument(conversion.Args[0], bucketIndex)
}

// weakDigestCall reports MD5/SHA1 New or Sum calls through imported package names.
func weakDigestCall(call *ast.CallExpr, packages map[string]bool, primitive string) (string, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !weakDigestAPIs[selector.Sel.Name] {
		return "", false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !packages[receiver.Name] {
		return "", false
	}
	return primitive + "." + selector.Sel.Name, true
}

// weakDigestSecurityContext finds the security context for MD5/SHA1 findings.
func weakDigestSecurityContext(call *ast.CallExpr, fn *ast.FuncDecl, parents map[ast.Node]ast.Node) (string, bool) {
	if word, ok := weakDigestContextWord(fn.Name.Name); ok {
		return word, true
	}
	if fn.Doc != nil {
		if word, ok := weakDigestContextWord(fn.Doc.Text()); ok {
			return word, true
		}
	}
	if word, ok := enclosingAssignmentContext(call, parents, weakDigestContextWord); ok {
		return word, true
	}
	return callArgumentContext(call, weakDigestContextWord)
}

// selectorCallMatches reports whether call invokes selectorName on one of packages.
func selectorCallMatches(call *ast.CallExpr, packages map[string]bool, selectorName string) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != selectorName {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && packages[receiver.Name]
}

// rsaGenerateKeyBits returns a literal RSA key size when call is rsa.GenerateKey.
func rsaGenerateKeyBits(call *ast.CallExpr, rsaPackages map[string]bool) (int, bool) {
	if !selectorCallMatches(call, rsaPackages, "GenerateKey") || len(call.Args) < 2 {
		return 0, false
	}
	literal, ok := call.Args[1].(*ast.BasicLit)
	if !ok {
		return 0, false
	}
	bits, err := strconv.Atoi(literal.Value)
	if err != nil {
		return 0, false
	}
	return bits, true
}

// weakDigestContextWord classifies password, token, signature, and similar digest contexts.
func weakDigestContextWord(text string) (string, bool) {
	return firstContextWord(text, weakDigestContextWords)
}
