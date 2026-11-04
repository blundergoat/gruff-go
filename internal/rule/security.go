// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds two parser-only security rules, security.tls-insecure-config and security.archive-path-traversal.
// Both read only the syntax tree, with no type information, so they flag what the file spells out and miss values that come from elsewhere.
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
//
// It backs the security.tls-insecure-config rule ID, on by default at warning severity.
// Only values written inside the literal count, so cfg.InsecureSkipVerify = true or a field set from a variable is not flagged.
type TLSInsecureConfigRule struct{}

// Definition declares the security.tls-insecure-config rule for direct TLS misconfiguration evidence.
// It returns the same populated Definition on every call: security pillar, warning severity, high confidence, enabled by default.
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
//
// unit is the parsed file; Config literals are matched only through its crypto/tls import names, anywhere in the file.
// It returns one finding per InsecureSkipVerify set to the literal true or MinVersion set to VersionSSL30, VersionTLS10 or VersionTLS11.
// The result is nil when unit has no AST or FileSet, and empty but non-nil when no insecure field is found.
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
			// A numeric MinVersion such as 0x0301 or one held in a variable is not flagged; only the named SSL 3.0, TLS 1.0 and TLS 1.1 constants are.
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
// tlsPackages holds the file's local names for crypto/tls; a Config literal written without a package selector reports false.
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
//
// expr is the MinVersion value and tlsPackages the file's local names for crypto/tls; only VersionSSL30, VersionTLS10 and VersionTLS11 count.
// It returns the selector text with its import name, such as tls.VersionTLS10, and true; any other expr gives an empty string and false.
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

// tlsConfigFinding builds a finding located at the unsafe tls.Config field key, so the report points at that key's line and column.
//
// unit supplies the file path and the FileSet that turns the keyValue key into a line and column; message becomes the finding message.
// It returns a Finding with only Message, File, Location and Metadata set; field and value are stored as metadata under their own names.
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
//
// It backs the security.archive-path-traversal rule ID, on by default at advisory severity.
// A zip or tar entry named ../../etc/passwd, joined straight onto an extraction directory, can land outside it; this rule looks for that join.
type ArchivePathTraversalRule struct{}

// Definition declares the security.archive-path-traversal rule for parser-only archive extraction evidence.
// It returns the same populated Definition on every call: security pillar, advisory severity, medium confidence, enabled by default.
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
//
// unit is the parsed file; with an archive/zip or archive/tar import name, only function and method bodies are scanned, skipping function literals.
// In those bodies it returns one finding per path or path/filepath Join call that has no containment evidence and takes an archive entry name.
// An archive entry name is a Name selector argument, or an identifier that collectArchiveNameVars recorded as assigned from one.
//
// The result is nil without an AST or FileSet, or when packageImportNames finds no archive/zip or archive/tar import name in unit.
// Otherwise it is empty but non-nil when no join is flagged.
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
			// Extraction code inside a func literal, such as a goroutine or a callback, is never checked by this rule.
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

// importsArchivePackage reports whether file imports archive/zip or archive/tar, excluding blank and dot imports.
// A file that reaches either package only through a dot import is never checked by security.archive-path-traversal.
func importsArchivePackage(file *ast.File) bool {
	return len(packageImportNames(file, "archive/zip", "zip")) > 0 || len(packageImportNames(file, "archive/tar", "tar")) > 0
}

// collectArchiveNameVars records locals assigned from archive entry Name fields, so name := header.Name then a Join on name is still caught.
//
// body is a function body; var declarations and assignments are scanned, skipping nested function literals and the blank identifier.
// It returns a map from each such local name to the Name selector assigned to it; the map is empty, not nil, when no local qualifies.
//
// A later non-Name assignment does not clear a recorded local, so name = filepath.Base(name) still counts as an entry name.
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
// pathPackages holds the file's local names for path and path/filepath; a Join call without such a package selector reports false.
func isPathJoinCall(call *ast.CallExpr, pathPackages map[string]bool) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Join" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && pathPackages[receiver.Name]
}

// archiveEntryNameArg returns the first archive entry name expression among call arguments.
//
// args are the Join call arguments; an identifier counts when archiveNameVars maps it, and its recorded Name selector is returned instead.
// So the finding's entry metadata shows the Name selector, such as header.Name, even when the Join used a local copy.
// When no argument qualifies it returns nil and false.
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
// It reports true for any selector expr ending in .Name, so non-archive Name fields match too; any other expr gives false.
func isArchiveNameExpr(expr ast.Expr) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Name"
}

// callName returns a best-effort selector or function identifier name.
// call is read by its callee: a selector gives the selected name, an identifier its own name, and any other callee an empty string.
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
//
// expr is printed by go/printer with a fresh token.FileSet rather than the file's own.
// It returns the printed source text, or the fixed text archive entry name when printing fails.
func formatExpr(expr ast.Expr) string {
	var out bytes.Buffer
	if err := printer.Fprint(&out, token.NewFileSet(), expr); err != nil {
		return "archive entry name"
	}
	return out.String()
}
