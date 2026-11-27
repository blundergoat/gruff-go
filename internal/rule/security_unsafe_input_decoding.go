// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements parser-only unsafe-deserialization and XXE checks.
// Both rules are on by default, skip files outside production code, and report advisory findings worded as possible issues.
package rule

import (
	"go/ast"
	"go/token"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// UnsafeDeserializationRule flags request-controlled input fed to encoding/gob or gopkg.in/yaml, formats that over-trust their payload.
//
// It backs security.unsafe-deserialization and fires on the decoder constructor or yaml.Unmarshal call, so no later Decode call is needed.
// Only files importing net/http are checked, and only in the function bodies forEachRequestFunc visits.
type UnsafeDeserializationRule struct{}

// Definition declares the security.unsafe-deserialization rule for bounded same-function evidence of untrusted decoding.
// It returns a Definition enabled by default at advisory severity and medium confidence, tagged deserialization and security.
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
//
// It returns nil when unit lacks an AST or file set, is outside production code, or does not import both net/http and gob or yaml.
// Otherwise the result holds one finding per gob.NewDecoder, yaml.NewDecoder or yaml.Unmarshal call whose first argument has request evidence.
// No later Decode call is needed, and the result is empty when nothing matches.
//
// Calls are searched in each body forEachRequestFunc visits, skipping nested function literals.
func (UnsafeDeserializationRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	httpPackages := packageImportNames(unit.AST, "net/http", "http")
	// Without a net/http import in this file the rule cannot recognise request parameters, so it skips the file even if a request reaches it.
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
			// Decoding input with no request evidence, such as a file the handler opens itself, lands here and is not flagged.
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

// unsafeDecodeSource reports the format and untrusted-argument index for a gob or yaml decoder constructor or yaml.Unmarshal call.
//
// call matches NewDecoder from gobPackages or NewDecoder and Unmarshal from yamlPackages; the index is always 0, and other calls give false.
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

// XXECandidateRule flags an explicit Entity field in an xml.Decoder literal, or an Entity assignment on a variable set from xml.NewDecoder.
//
// The Go standard library encoding/xml does not expand external entities, so a plain decoder is never flagged.
// The assigned map is never inspected, so Entity: nil or an empty map is reported too, and no decoding call is required.
type XXECandidateRule struct{}

// Definition declares security.xxe-candidate for an explicit Entity field or assignment on an XML decoder, including nil and empty maps.
// It returns a Definition enabled by default at advisory severity and medium confidence, tagged security, xml and xxe.
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
//
// It returns nil when unit lacks an AST or file set, is outside production code, or does not import encoding/xml.
// Otherwise the result holds a finding per xml.Decoder composite literal setting Entity anywhere in the file and per matching Entity assignment.
//
// An assignment matches when its receiver name was given an xml.NewDecoder result in its own or an enclosing body under a function declaration.
// Shadowing is not resolved and the assigned value is never inspected, so dec.Entity = nil on such a name is reported too.
// The result is empty when neither kind of evidence is found.
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
	// Entity assignments are matched per function body, so a dec of another type in another function never counts as a decoder.
	//
	// A closure's own decoders never mark same-named outer variables, while outer decoder names stay visible inside nested closures
	// so a closure that configures an outer decoder is still flagged, and so is a closure-local variable that reuses a decoder's name.
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
	// Only func declarations are walked, so an Entity assignment inside a package-level var func literal is not reported.
	for _, decl := range unit.AST.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			walk(fn.Body, nil)
		}
	}
	return findings
}

// directFuncLits returns the function literals nested directly in body, in source order, and nil when body holds none.
//
// It stops at each literal rather than descending: walk recurses into each returned literal in turn,
// so a deeper closure is reached as the direct child of its own parent.
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

// collectXMLDecoderVars records names assigned or declared from xml.NewDecoder results within scope, one function body.
//
// A same-named variable in another function is never collected, and nested closures are skipped as their own scope.
// Skipping closures keeps their decoder names from marking same-named outer variables; it does not resolve shadowing.
//
// xmlPackages holds the names encoding/xml is imported under, and the result maps each matched variable name to true, empty when none is found.
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
				// A struct field target such as s.dec = xml.NewDecoder(r) is not tracked, so a later s.dec.Entity assignment is not reported.
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

// isDecoderEntityTarget reports whether lhs assigns the Entity field of a known xml.Decoder variable.
//
// decoderVars holds the visible decoder variable names, and only a selector of the form name.Entity with name in decoderVars gives true.
// The match is by name alone, so a local that shadows a decoder's name also gives true.
func isDecoderEntityTarget(lhs ast.Expr, decoderVars map[string]bool) bool {
	selector, ok := lhs.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Entity" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && decoderVars[receiver.Name]
}

// isXMLDecoderLiteralWithEntity reports whether literal constructs an xml.Decoder with an Entity field set in the composite literal.
//
// xmlPackages holds the names encoding/xml is imported under, and the literal type must select Decoder from one of them.
// The Entity value is never inspected, so Entity: nil or an empty map also gives true.
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
