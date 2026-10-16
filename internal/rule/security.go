// Package rule defines gruff-go's rule registry and analysers.
// This file implements focused parser-only security checks beyond secret literals.
package rule

import (
	"bytes"
	"go/ast"
	"go/printer"
	"go/token"
	"regexp"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// sqlKeywordPattern recognises SQL statement keywords inside constructed query strings.
var sqlKeywordPattern = regexp.MustCompile(`(?i)\b(select|insert|update|delete|create|drop|alter)\b`)

// TLSInsecureConfigRule flags tls.Config literals with concrete insecure settings.
type TLSInsecureConfigRule struct{}

// Definition declares the security.tls-insecure-config rule for direct TLS misconfiguration evidence.
func (TLSInsecureConfigRule) Definition() Definition {
	return Definition{
		ID:             "security.tls-insecure-config",
		Title:          "TLS insecure config",
		Description:    "Flags tls.Config literals that disable certificate verification or allow obsolete TLS protocol versions.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"security", "tls"},
		Remediation:    "Keep certificate verification enabled and require TLS 1.2 or newer for minimum protocol versions.",
	}
}

// AnalyzeUnit emits findings for tls.Config literals with explicit insecure field values.
func (TLSInsecureConfigRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	tlsPackages := packageImportNames(unit.AST, "crypto/tls", "tls")
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok || !isTLSConfigLiteral(literal, tlsPackages) {
			return true
		}
		for _, element := range literal.Elts {
			keyValue, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			field, ok := keyValue.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch field.Name {
			case "InsecureSkipVerify":
				if isTrueLiteral(keyValue.Value) {
					findings = append(findings, tlsConfigFinding(unit, keyValue, "TLS config disables certificate verification", field.Name, "true"))
				}
			case "MinVersion":
				value, unsafe := unsafeTLSMinVersion(keyValue.Value, tlsPackages)
				if unsafe {
					findings = append(findings, tlsConfigFinding(unit, keyValue, "TLS config permits obsolete minimum version", field.Name, value))
				}
			}
		}
		return true
	})
	return findings
}

// isTLSConfigLiteral reports whether literal has type crypto/tls.Config through a selector import name.
func isTLSConfigLiteral(literal *ast.CompositeLit, tlsPackages map[string]bool) bool {
	selector, ok := literal.Type.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Config" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && tlsPackages[receiver.Name]
}

// isTrueLiteral reports whether expr is the boolean literal true.
func isTrueLiteral(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "true"
}

// unsafeTLSMinVersion reports obsolete crypto/tls version selectors that should not be a minimum version.
func unsafeTLSMinVersion(expr ast.Expr, tlsPackages map[string]bool) (string, bool) {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !tlsPackages[receiver.Name] {
		return "", false
	}
	switch selector.Sel.Name {
	case "VersionSSL30", "VersionTLS10", "VersionTLS11":
		return receiver.Name + "." + selector.Sel.Name, true
	default:
		return "", false
	}
}

// tlsConfigFinding builds a finding located at the unsafe tls.Config field key.
func tlsConfigFinding(unit parser.Unit, keyValue *ast.KeyValueExpr, message string, field string, value string) finding.Finding {
	position := unit.FileSet.Position(keyValue.Key.Pos())
	return finding.Finding{
		Message:  message,
		File:     unit.File.Path,
		Location: &finding.Location{Line: position.Line, Column: position.Column},
		Metadata: map[string]any{
			"field": field,
			"value": value,
		},
	}
}

// ArchivePathTraversalRule flags archive extraction paths that use entry names without containment evidence.
type ArchivePathTraversalRule struct{}

// Definition declares the security.archive-path-traversal rule for parser-only archive extraction evidence.
func (ArchivePathTraversalRule) Definition() Definition {
	return Definition{
		ID:             "security.archive-path-traversal",
		Title:          "Archive path traversal",
		Description:    "Flags archive extraction paths built from entry names without an obvious containment check.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"archive", "security"},
		Remediation:    "Clean the joined path and verify it stays within the extraction root before creating files.",
	}
}

// AnalyzeUnit emits findings for archive entry names joined into extraction paths without nearby containment checks.
func (ArchivePathTraversalRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !importsArchivePackage(unit.AST) {
		return nil
	}
	pathPackages := packageImportNames(unit.AST, "path/filepath", "filepath")
	for name := range packageImportNames(unit.AST, "path", "path") {
		pathPackages[name] = true
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		archiveNameVars := collectArchiveNameVars(fn.Body)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok || !isPathJoinCall(call, pathPackages) {
				return true
			}
			entryExpr, ok := archiveEntryNameArg(call.Args, archiveNameVars)
			if !ok {
				return true
			}
			if archiveJoinHasContainmentEvidence(fn.Body, call) {
				return true
			}
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "archive entry path is joined without containment check",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Metadata: map[string]any{
					"entry":        formatExpr(entryExpr),
					"missingCheck": "containment",
				},
			})
			return true
		})
	}
	return findings
}

// importsArchivePackage reports whether the file imports a standard archive package.
func importsArchivePackage(file *ast.File) bool {
	return len(packageImportNames(file, "archive/zip", "zip")) > 0 || len(packageImportNames(file, "archive/tar", "tar")) > 0
}

// collectArchiveNameVars records locals assigned from archive entry Name fields.
func collectArchiveNameVars(body *ast.BlockStmt) map[string]ast.Expr {
	vars := map[string]ast.Expr{}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch stmt := node.(type) {
		case *ast.ValueSpec:
			for i, name := range stmt.Names {
				if name.Name == "_" || i >= len(stmt.Values) || !isArchiveNameExpr(stmt.Values[i]) {
					continue
				}
				vars[name.Name] = stmt.Values[i]
			}
		case *ast.AssignStmt:
			for i, lhs := range stmt.Lhs {
				name, ok := lhs.(*ast.Ident)
				if !ok || name.Name == "_" || i >= len(stmt.Rhs) || !isArchiveNameExpr(stmt.Rhs[i]) {
					continue
				}
				vars[name.Name] = stmt.Rhs[i]
			}
		}
		return true
	})
	return vars
}

// isPathJoinCall reports whether call is path/filepath.Join or path.Join through an imported package name.
func isPathJoinCall(call *ast.CallExpr, pathPackages map[string]bool) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Join" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && pathPackages[receiver.Name]
}

// archiveEntryNameArg returns the first archive entry name expression among call arguments.
func archiveEntryNameArg(args []ast.Expr, archiveNameVars map[string]ast.Expr) (ast.Expr, bool) {
	for _, arg := range args {
		if isArchiveNameExpr(arg) {
			return arg, true
		}
		ident, ok := arg.(*ast.Ident)
		if !ok {
			continue
		}
		if original, ok := archiveNameVars[ident.Name]; ok {
			return original, true
		}
	}
	return nil, false
}

// isArchiveNameExpr recognises field access to an archive entry's Name field.
func isArchiveNameExpr(expr ast.Expr) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Name"
}

// callName returns a best-effort selector or function identifier name.
func callName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fun.Sel.Name
	case *ast.Ident:
		return fun.Name
	default:
		return ""
	}
}

// formatExpr renders an AST expression for metadata without requiring type information.
func formatExpr(expr ast.Expr) string {
	var out bytes.Buffer
	if err := printer.Fprint(&out, token.NewFileSet(), expr); err != nil {
		return "archive entry name"
	}
	return out.String()
}
