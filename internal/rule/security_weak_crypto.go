// Package rule defines gruff-go's rule registry and analysers.
// This file implements parser-only weak-crypto security checks.
package rule

import (
	"go/ast"
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
		Severity:       finding.SeverityLow,
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
		md5:  packageImportNames(unit.AST, "crypto/md5", "md5"),
		sha1: packageImportNames(unit.AST, "crypto/sha1", "sha1"),
		des:  packageImportNames(unit.AST, "crypto/des", "des"),
		rc4:  packageImportNames(unit.AST, "crypto/rc4", "rc4"),
		rsa:  packageImportNames(unit.AST, "crypto/rsa", "rsa"),
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

// weakCryptoPackages groups imported weak-crypto package aliases.
type weakCryptoPackages struct {
	md5  map[string]bool
	sha1 map[string]bool
	des  map[string]bool
	rc4  map[string]bool
	rsa  map[string]bool
}

// any reports whether at least one weak-crypto package was imported.
func (p weakCryptoPackages) any() bool {
	return len(p.md5) > 0 || len(p.sha1) > 0 || len(p.des) > 0 || len(p.rc4) > 0 || len(p.rsa) > 0
}

// weakCryptoCall classifies a weak-crypto call when the parser-only evidence is strong enough.
func weakCryptoCall(call *ast.CallExpr, fn *ast.FuncDecl, parents map[ast.Node]ast.Node, packages weakCryptoPackages) (weakCryptoCallContext, bool) {
	if primitive, ok := weakDigestCall(call, packages.md5, "md5"); ok {
		if word, contextOK := weakDigestSecurityContext(call, fn, parents); contextOK {
			return weakCryptoCallContext{primitive: primitive, reason: word}, true
		}
		return weakCryptoCallContext{}, false
	}
	if primitive, ok := weakDigestCall(call, packages.sha1, "sha1"); ok {
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
