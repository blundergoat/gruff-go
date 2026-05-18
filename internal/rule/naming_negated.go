package rule

import (
	"fmt"
	"go/ast"
	"strings"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

var defaultNegatedBooleanPrefixes = []string{"No", "Not", "Disable", "Disallow", "Without", "Suppress"}

var defaultNegatedBooleanAllowList = []string{"NoOp", "Notify", "Notice", "Now", "NoCopy", "Notation", "Notebook"}

type NegatedBooleanRule struct {
	Prefixes  []string
	AllowList []string
	Scope     string
}

func (r NegatedBooleanRule) Definition() Definition {
	return Definition{
		ID:             "naming.negated-boolean",
		Title:          "Negated boolean",
		Description:    "Flags boolean identifiers whose names start with negation prefixes (No, Not, Disable, etc.), which force double-negation at call sites.",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Tags:           []string{"go-style", "naming", "opt-in"},
		Options: map[string]any{
			"prefixes":  defaultNegatedBooleanPrefixes,
			"allowList": defaultNegatedBooleanAllowList,
			"scope":     "exported",
		},
		Remediation: "Rename to the positive form (e.g. Skip… instead of No…) so call sites read without double negation.",
	}
}

func (r NegatedBooleanRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	ctx := r.buildContext()
	if ctx == nil {
		return nil
	}
	var findings []finding.Finding
	for _, decl := range unit.AST.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			findings = append(findings, ctx.analyzeGenDecl(unit, d)...)
		case *ast.FuncDecl:
			findings = append(findings, ctx.analyzeFuncDecl(unit, d)...)
		}
	}
	return findings
}

type negatedContext struct {
	prefixes []string
	allow    map[string]bool
	scope    string
}

func (r NegatedBooleanRule) buildContext() *negatedContext {
	prefixes := r.prefixSet()
	if len(prefixes) == 0 {
		return nil
	}
	return &negatedContext{
		prefixes: prefixes,
		allow:    r.allowSet(),
		scope:    r.scopeValue(),
	}
}

func (c *negatedContext) check(unit parser.Unit, ident *ast.Ident) (finding.Finding, bool) {
	if ident == nil || ident.Name == "" || ident.Name == "_" {
		return finding.Finding{}, false
	}
	if !negatedScopeAllows(c.scope, ast.IsExported(ident.Name)) {
		return finding.Finding{}, false
	}
	if !matchesNegatedPrefix(ident.Name, c.prefixes, c.allow) {
		return finding.Finding{}, false
	}
	return makeNegatedFinding(unit, ident), true
}

func (c *negatedContext) checkIdents(unit parser.Unit, idents []*ast.Ident) []finding.Finding {
	var out []finding.Finding
	for _, ident := range idents {
		if f, ok := c.check(unit, ident); ok {
			out = append(out, f)
		}
	}
	return out
}

func (c *negatedContext) checkBoolField(unit parser.Unit, field *ast.Field) []finding.Finding {
	if !isBoolType(field.Type) {
		return nil
	}
	return c.checkIdents(unit, field.Names)
}

func (c *negatedContext) checkBoolValueSpec(unit parser.Unit, spec *ast.ValueSpec) []finding.Finding {
	if !isBoolType(spec.Type) {
		return nil
	}
	return c.checkIdents(unit, spec.Names)
}

func (c *negatedContext) checkStruct(unit parser.Unit, st *ast.StructType) []finding.Finding {
	if st == nil || st.Fields == nil {
		return nil
	}
	var out []finding.Finding
	for _, field := range st.Fields.List {
		out = append(out, c.checkBoolField(unit, field)...)
		if nested, ok := field.Type.(*ast.StructType); ok {
			out = append(out, c.checkStruct(unit, nested)...)
		}
	}
	return out
}

func (c *negatedContext) analyzeGenDecl(unit parser.Unit, decl *ast.GenDecl) []finding.Finding {
	var out []finding.Finding
	for _, spec := range decl.Specs {
		switch s := spec.(type) {
		case *ast.ValueSpec:
			out = append(out, c.checkBoolValueSpec(unit, s)...)
		case *ast.TypeSpec:
			if st, ok := s.Type.(*ast.StructType); ok {
				out = append(out, c.checkStruct(unit, st)...)
			}
		}
	}
	return out
}

func (c *negatedContext) analyzeFuncDecl(unit parser.Unit, decl *ast.FuncDecl) []finding.Finding {
	var out []finding.Finding
	out = append(out, c.checkFuncReturn(unit, decl)...)
	out = append(out, c.checkFuncParams(unit, decl)...)
	if c.scope == "locals" || c.scope == "all" {
		out = append(out, c.checkFuncBody(unit, decl)...)
	}
	return out
}

func (c *negatedContext) checkFuncReturn(unit parser.Unit, decl *ast.FuncDecl) []finding.Finding {
	if decl.Name == nil || decl.Type == nil || decl.Type.Results == nil {
		return nil
	}
	if len(decl.Type.Results.List) != 1 {
		return nil
	}
	if !isBoolType(decl.Type.Results.List[0].Type) {
		return nil
	}
	if f, ok := c.check(unit, decl.Name); ok {
		return []finding.Finding{f}
	}
	return nil
}

func (c *negatedContext) checkFuncParams(unit parser.Unit, decl *ast.FuncDecl) []finding.Finding {
	if decl.Type == nil || decl.Type.Params == nil {
		return nil
	}
	var out []finding.Finding
	for _, field := range decl.Type.Params.List {
		out = append(out, c.checkBoolField(unit, field)...)
	}
	return out
}

func (c *negatedContext) checkFuncBody(unit parser.Unit, decl *ast.FuncDecl) []finding.Finding {
	if decl.Body == nil {
		return nil
	}
	var out []finding.Finding
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		if spec, ok := n.(*ast.ValueSpec); ok {
			out = append(out, c.checkBoolValueSpec(unit, spec)...)
		}
		return true
	})
	return out
}

func (r NegatedBooleanRule) prefixSet() []string {
	source := r.Prefixes
	if len(source) == 0 {
		source = defaultNegatedBooleanPrefixes
	}
	out := make([]string, 0, len(source))
	for _, p := range source {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func (r NegatedBooleanRule) allowSet() map[string]bool {
	source := r.AllowList
	if len(source) == 0 {
		source = defaultNegatedBooleanAllowList
	}
	out := make(map[string]bool, len(source))
	for _, name := range source {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			out[trimmed] = true
		}
	}
	return out
}

func (r NegatedBooleanRule) scopeValue() string {
	switch r.Scope {
	case "all", "locals", "exported":
		return r.Scope
	default:
		return "exported"
	}
}

func negatedScopeAllows(scope string, exported bool) bool {
	switch scope {
	case "locals":
		return !exported
	case "all":
		return true
	default:
		return exported
	}
}

func matchesNegatedPrefix(name string, prefixes []string, allow map[string]bool) bool {
	if allow[name] {
		return false
	}
	for _, prefix := range prefixes {
		if tryNegatedPrefix(name, prefix) {
			return true
		}
		if len(prefix) > 0 {
			lowered := strings.ToLower(prefix[:1]) + prefix[1:]
			if lowered != prefix && tryNegatedPrefix(name, lowered) {
				return true
			}
		}
	}
	return false
}

func tryNegatedPrefix(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) <= len(prefix) {
		return false
	}
	return unicode.IsUpper(rune(name[len(prefix)]))
}

func isBoolType(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "bool"
}

func makeNegatedFinding(unit parser.Unit, ident *ast.Ident) finding.Finding {
	position := unit.FileSet.Position(ident.NamePos)
	return finding.Finding{
		Message:  fmt.Sprintf("identifier %q uses negated form; rename to the positive equivalent to avoid double-negation at call sites", ident.Name),
		File:     unit.File.Path,
		Location: &finding.Location{Line: position.Line, Column: position.Column},
		Symbol:   ident.Name,
		Metadata: map[string]any{"identifier": ident.Name},
	}
}
