// Package rule defines gruff-go's rule registry and analysers.
// This file implements parser-only unsafe-deserialization and XXE checks.
package rule

import (
	"go/ast"
	"go/token"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// UnsafeDeserializationRule flags decoding of request-controlled input through
// formats that execute or over-trust their payload (encoding/gob, gopkg.in/yaml).
type UnsafeDeserializationRule struct{}

// Definition declares the security.unsafe-deserialization rule for bounded
// same-function evidence of untrusted decoding.
func (UnsafeDeserializationRule) Definition() Definition {
	return Definition{
		ID:             "security.unsafe-deserialization",
		Title:          "Unsafe deserialization",
		Description:    "Flags decoding of request-controlled input via encoding/gob or gopkg.in/yaml, which over-trust their payload. Decoding a concrete typed struct from a trusted local source is not flagged. Uses bounded same-function evidence and candidate wording.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"deserialization", "security"},
		Remediation:    "Decode untrusted input into a concrete typed struct with a vetted format (such as encoding/json with a size limit) rather than gob or unrestricted YAML.",
	}
}

// AnalyzeUnit emits findings for decoders that consume request-controlled input.
func (UnsafeDeserializationRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	httpPackages := packageImportNames(unit.AST, "net/http", "http")
	if len(httpPackages) == 0 {
		return nil
	}
	gobPackages := packageImportNames(unit.AST, "encoding/gob", "gob")
	yamlPackages := packageImportNames(unit.AST, "gopkg.in/yaml.v3", "yaml")
	for name := range packageImportNames(unit.AST, "gopkg.in/yaml.v2", "yaml") {
		yamlPackages[name] = true
	}
	if len(gobPackages) == 0 && len(yamlPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	forEachRequestFunc(unit.AST, httpPackages, func(scope *requestTaintScope, body *ast.BlockStmt) {
		ast.Inspect(body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			format, sourceIndex, ok := unsafeDecodeSource(call, gobPackages, yamlPackages)
			if !ok || sourceIndex >= len(call.Args) {
				return true
			}
			source, ok := scope.exprHasRequest(call.Args[sourceIndex], call.Pos())
			if !ok {
				return true
			}
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "request-controlled input decoded via " + format + " (possible unsafe deserialization)",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Metadata: map[string]any{"format": format, "source": source},
			})
			return true
		})
	})
	return findings
}

// unsafeDecodeSource reports the decoded format and the argument index of the
// untrusted source for gob/yaml decoder constructors and yaml.Unmarshal.
func unsafeDecodeSource(call *ast.CallExpr, gobPackages, yamlPackages map[string]bool) (string, int, bool) {
	if selectorCallMatches(call, gobPackages, "NewDecoder") {
		return "gob", 0, true
	}
	if selectorCallMatches(call, yamlPackages, "NewDecoder") {
		return "yaml", 0, true
	}
	if selectorCallMatches(call, yamlPackages, "Unmarshal") {
		return "yaml", 0, true
	}
	return "", 0, false
}

// XXECandidateRule flags XML decoders configured to resolve custom entities.
// The Go standard library encoding/xml does not expand external entities, so the
// rule fires only on the explicit entity-resolving configuration.
type XXECandidateRule struct{}

// Definition declares the security.xxe-candidate rule for explicit entity-resolving
// XML decoder configuration.
func (XXECandidateRule) Definition() Definition {
	return Definition{
		ID:             "security.xxe-candidate",
		Title:          "XML external entity candidate",
		Description:    "Flags xml.Decoder configurations that populate a custom entity map, which re-enables entity resolution (possible XXE). The Go standard library encoding/xml does not expand external entities by default, so a plain decoder is not flagged. Candidate wording.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"security", "xml", "xxe"},
		Remediation:    "Leave xml.Decoder.Entity unset so encoding/xml's safe default applies, or validate and constrain any custom entity map fed from untrusted input.",
	}
}

// AnalyzeUnit emits findings for xml.Decoder entity-map configuration.
func (XXECandidateRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	xmlPackages := packageImportNames(unit.AST, "encoding/xml", "xml")
	if len(xmlPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	emit := func(pos token.Pos) {
		position := unit.FileSet.Position(pos)
		findings = append(findings, finding.Finding{
			Message:  "XML decoder configured to resolve custom entities (possible XXE)",
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Metadata: map[string]any{"evidence": "entity-map"},
		})
	}
	// A composite literal xml.Decoder{Entity: ...} is self-evidencing (type and the
	// Entity field are both in the literal), so it is matched file-wide.
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		if literal, ok := node.(*ast.CompositeLit); ok && isXMLDecoderLiteralWithEntity(literal, xmlPackages) {
			emit(literal.Pos())
		}
		return true
	})
	// `dec.Entity = ...` evidence is scoped lexically. Collecting decoder vars
	// file-wide would let an unrelated `dec` of a different type in another function
	// produce a cross-scope false XXE finding, and descending into nested closures
	// during collection would let a closure's decoder taint a same-named outer
	// variable. Each function body is therefore its own scope, while enclosing
	// decoder bindings stay visible to nested closures so a closure that configures
	// an outer decoder is still flagged.
	var walk func(body *ast.BlockStmt, enclosing map[string]bool)
	walk = func(body *ast.BlockStmt, enclosing map[string]bool) {
		visible := map[string]bool{}
		for name := range enclosing {
			visible[name] = true
		}
		for name := range collectXMLDecoderVars(body, xmlPackages) {
			visible[name] = true
		}
		if len(visible) > 0 {
			ast.Inspect(body, func(node ast.Node) bool {
				if _, nested := node.(*ast.FuncLit); nested {
					return false // a closure is visited as its own scope below
				}
				if assign, ok := node.(*ast.AssignStmt); ok {
					for _, lhs := range assign.Lhs {
						if isDecoderEntityTarget(lhs, visible) {
							emit(lhs.Pos())
						}
					}
				}
				return true
			})
		}
		for _, lit := range directFuncLits(body) {
			walk(lit.Body, visible)
		}
	}
	for _, decl := range unit.AST.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			walk(fn.Body, nil)
		}
	}
	return findings
}

// directFuncLits returns the function literals nested directly in body, stopping
// at each one rather than descending: walk recurses into each returned literal in
// turn, so a deeper closure is reached as the direct child of its own parent.
func directFuncLits(body *ast.BlockStmt) []*ast.FuncLit {
	var lits []*ast.FuncLit
	ast.Inspect(body, func(node ast.Node) bool {
		if lit, ok := node.(*ast.FuncLit); ok {
			lits = append(lits, lit)
			return false
		}
		return true
	})
	return lits
}

// collectXMLDecoderVars records locals bound to xml.NewDecoder results within the
// given scope (one function body), without descending into nested closures whose
// decoders belong to their own scope. Scoping this way keeps a same-named variable
// in another function - or in a nested closure - from being treated as the same
// decoder.
func collectXMLDecoderVars(scope ast.Node, xmlPackages map[string]bool) map[string]bool {
	vars := map[string]bool{}
	ast.Inspect(scope, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch stmt := node.(type) {
		case *ast.AssignStmt:
			for i, lhs := range stmt.Lhs {
				name, ok := lhs.(*ast.Ident)
				if !ok || name.Name == "_" || i >= len(stmt.Rhs) {
					continue
				}
				if call, ok := stmt.Rhs[i].(*ast.CallExpr); ok && selectorCallMatches(call, xmlPackages, "NewDecoder") {
					vars[name.Name] = true
				}
			}
		case *ast.ValueSpec:
			for i, name := range stmt.Names {
				if name.Name == "_" || i >= len(stmt.Values) {
					continue
				}
				if call, ok := stmt.Values[i].(*ast.CallExpr); ok && selectorCallMatches(call, xmlPackages, "NewDecoder") {
					vars[name.Name] = true
				}
			}
		}
		return true
	})
	return vars
}

// isDecoderEntityTarget reports whether lhs assigns the Entity field of a known
// xml.Decoder variable.
func isDecoderEntityTarget(lhs ast.Expr, decoderVars map[string]bool) bool {
	selector, ok := lhs.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Entity" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && decoderVars[receiver.Name]
}

// isXMLDecoderLiteralWithEntity reports whether literal constructs an xml.Decoder
// with an Entity field set in the composite literal.
func isXMLDecoderLiteralWithEntity(literal *ast.CompositeLit, xmlPackages map[string]bool) bool {
	selector, ok := literal.Type.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Decoder" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !xmlPackages[receiver.Name] {
		return false
	}
	for _, element := range literal.Elts {
		keyValue, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := keyValue.Key.(*ast.Ident); ok && key.Name == "Entity" {
			return true
		}
	}
	return false
}
