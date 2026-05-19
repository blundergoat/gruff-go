// Package rule defines gruff-go's rule registry and analysers.
// This file holds structural metric rules (parameter count, nesting depth, exported-symbol comments).
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// Default thresholds for parameter-count and nesting-depth rules.
const (
	parameterCountThreshold = 8
	nestingDepthThreshold   = 5
)

// ParameterCountRule flags functions and methods whose parameter list exceeds the maximum.
type ParameterCountRule struct {
	// MaxParameters is the per-function parameter cap (excluding the receiver) before a finding is emitted.
	MaxParameters int
}

// maxParameters returns the effective parameter-count threshold for this rule.
func (r ParameterCountRule) maxParameters() int {
	if r.MaxParameters <= 0 {
		return parameterCountThreshold
	}
	return r.MaxParameters
}

// Definition declares the size.parameter-count rule with a default maximum of 8 non-receiver parameters and low severity.
func (r ParameterCountRule) Definition() Definition {
	max := r.maxParameters()
	return Definition{
		ID:             "size.parameter-count",
		Title:          "Parameter count",
		Description:    "Flags functions and methods whose parameter list exceeds the configured maximum, excluding the method receiver.",
		Pillar:         finding.PillarSize,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Thresholds:     map[string]float64{"maxParameters": float64(max)},
		Tags:           []string{"opt-in"},
		Remediation:    "Group related parameters into a struct, accept an options type, or split the function.",
	}
}

// AnalyzeUnit emits findings for every function whose parameter count exceeds the threshold.
func (r ParameterCountRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	max := r.maxParameters()
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Type == nil {
			continue
		}
		count := paramCount(fn)
		if count <= max {
			continue
		}
		start := unit.FileSet.Position(fn.Pos())
		end := unit.FileSet.Position(fn.End())
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("function has %d parameters, above threshold %d", count, max),
			File:     unit.File.Path,
			Location: &finding.Location{Line: start.Line, EndLine: end.Line},
			Symbol:   functionName(fn),
			Metadata: map[string]any{"parameters": count, "threshold": max},
		})
	}
	return findings
}

// paramCount returns the total number of declared parameters, excluding the receiver.
func paramCount(fn *ast.FuncDecl) int {
	if fn.Type == nil || fn.Type.Params == nil {
		return 0
	}
	count := 0
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			count++
			continue
		}
		count += len(field.Names)
	}
	return count
}

// NestingDepthRule flags functions whose maximum control-flow nesting exceeds the threshold.
type NestingDepthRule struct {
	// MaxDepth is the per-function control-flow nesting cap; function literals reset the count.
	MaxDepth int
}

// maxDepth returns the effective nesting-depth threshold for this rule.
func (r NestingDepthRule) maxDepth() int {
	if r.MaxDepth <= 0 {
		return nestingDepthThreshold
	}
	return r.MaxDepth
}

// Definition declares the complexity.nesting-depth rule with a default maximum of 5 control-flow levels under the complexity pillar.
func (r NestingDepthRule) Definition() Definition {
	max := r.maxDepth()
	return Definition{
		ID:             "complexity.nesting-depth",
		Title:          "Nesting depth",
		Description:    "Flags functions whose maximum control-flow nesting depth exceeds the configured threshold. Function literals reset the count.",
		Pillar:         finding.PillarComplexity,
		Severity:       finding.SeverityMedium,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Thresholds:     map[string]float64{"maxDepth": float64(max)},
		Tags:           []string{"opt-in"},
		Remediation:    "Extract nested branches into named helpers or return early on guard conditions.",
	}
}

// AnalyzeUnit emits findings for every function whose nesting depth exceeds the threshold.
func (r NestingDepthRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	max := r.maxDepth()
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		depth := blockNestingDepth(fn.Body, 0)
		if depth <= max {
			continue
		}
		start := unit.FileSet.Position(fn.Pos())
		end := unit.FileSet.Position(fn.End())
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("function nesting depth is %d, above threshold %d", depth, max),
			File:     unit.File.Path,
			Location: &finding.Location{Line: start.Line, EndLine: end.Line},
			Symbol:   functionName(fn),
			Metadata: map[string]any{"depth": depth, "threshold": max},
		})
	}
	return findings
}

// blockNestingDepth returns the deepest nesting depth reachable from the given block.
func blockNestingDepth(block *ast.BlockStmt, depth int) int {
	if block == nil {
		return depth
	}
	best := depth
	for _, stmt := range block.List {
		if d := stmtNestingDepth(stmt, depth); d > best {
			best = d
		}
	}
	return best
}

// stmtNestingDepth returns the deepest nesting depth reachable from the given statement.
func stmtNestingDepth(stmt ast.Stmt, depth int) int {
	switch s := stmt.(type) {
	case *ast.IfStmt:
		next := depth + 1
		best := blockNestingDepth(s.Body, next)
		if s.Else != nil {
			switch el := s.Else.(type) {
			case *ast.BlockStmt:
				if d := blockNestingDepth(el, next); d > best {
					best = d
				}
			case *ast.IfStmt:
				if d := stmtNestingDepth(el, depth); d > best {
					best = d
				}
			}
		}
		return best
	case *ast.ForStmt:
		return blockNestingDepth(s.Body, depth+1)
	case *ast.RangeStmt:
		return blockNestingDepth(s.Body, depth+1)
	case *ast.SwitchStmt:
		return clausesNestingDepth(s.Body, depth+1)
	case *ast.TypeSwitchStmt:
		return clausesNestingDepth(s.Body, depth+1)
	case *ast.SelectStmt:
		return clausesNestingDepth(s.Body, depth+1)
	case *ast.BlockStmt:
		return blockNestingDepth(s, depth)
	}
	return depth
}

// clausesNestingDepth returns the deepest nesting depth across switch/select case bodies.
func clausesNestingDepth(body *ast.BlockStmt, depth int) int {
	if body == nil {
		return depth
	}
	best := depth
	for _, clause := range body.List {
		switch c := clause.(type) {
		case *ast.CaseClause:
			for _, stmt := range c.Body {
				if d := stmtNestingDepth(stmt, depth); d > best {
					best = d
				}
			}
		case *ast.CommClause:
			for _, stmt := range c.Body {
				if d := stmtNestingDepth(stmt, depth); d > best {
					best = d
				}
			}
		}
	}
	return best
}

// ExportedSymbolCommentRule flags exported declarations that lack a doc comment.
type ExportedSymbolCommentRule struct {
	// IgnoreInternalPackages skips files living under any internal/ directory when true.
	IgnoreInternalPackages bool
}

// Definition declares the docs.exported-symbol-comment rule that flags undocumented exported declarations and skips internal packages by default.
func (ExportedSymbolCommentRule) Definition() Definition {
	return Definition{
		ID:             "docs.exported-symbol-comment",
		Title:          "Exported symbol comment",
		Description:    "Flags exported top-level Go declarations (functions, methods on exported types, types, vars, consts) that have no doc comment.",
		Pillar:         finding.PillarDocumentation,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Options:        map[string]any{"ignoreInternalPackages": true},
		Tags:           []string{"opt-in"},
		Remediation:    "Add a Go-style doc comment that begins with the symbol name.",
	}
}

// AnalyzeUnit emits findings for exported declarations in a unit that have no doc comment.
func (r ExportedSymbolCommentRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	if strings.HasSuffix(unit.File.Path, "_test.go") {
		return nil
	}
	if r.IgnoreInternalPackages && isInternalPackagePath(unit.File.Path) {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		findings = append(findings, exportedDeclFindings(unit, decl)...)
	}
	return findings
}

// isInternalPackagePath reports whether the file path lives under an internal/ directory.
func isInternalPackagePath(path string) bool {
	parts := strings.Split(path, "/")
	for _, part := range parts[:len(parts)-1] {
		if part == "internal" {
			return true
		}
	}
	return false
}

// exportedDeclFindings dispatches doc-comment checks for a single top-level declaration.
func exportedDeclFindings(unit parser.Unit, decl ast.Decl) []finding.Finding {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return exportedFuncFinding(unit, d)
	case *ast.GenDecl:
		return exportedGenDeclFindings(unit, d)
	}
	return nil
}

// exportedFuncFinding emits a finding when an exported function or method has no doc comment.
func exportedFuncFinding(unit parser.Unit, fn *ast.FuncDecl) []finding.Finding {
	if !isExportedFunc(fn) || hasDoc(fn.Doc) {
		return nil
	}
	position := unit.FileSet.Position(fn.Pos())
	return []finding.Finding{{
		Message:  fmt.Sprintf("exported %s %q has no doc comment", funcKind(fn), fn.Name.Name),
		File:     unit.File.Path,
		Location: &finding.Location{Line: position.Line},
		Symbol:   functionName(fn),
		Metadata: map[string]any{"symbol": fn.Name.Name, "kind": funcKind(fn)},
	}}
}

// exportedGenDeclFindings emits findings for exported types, vars, and consts missing doc comments.
func exportedGenDeclFindings(unit parser.Unit, decl *ast.GenDecl) []finding.Finding {
	findings := []finding.Finding{}
	for _, spec := range decl.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			if !ast.IsExported(s.Name.Name) || hasDoc(decl.Doc) || hasDoc(s.Doc) {
				continue
			}
			position := unit.FileSet.Position(s.Pos())
			findings = append(findings, finding.Finding{
				Message:  fmt.Sprintf("exported type %q has no doc comment", s.Name.Name),
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line},
				Symbol:   s.Name.Name,
				Metadata: map[string]any{"symbol": s.Name.Name, "kind": "type"},
			})
		case *ast.ValueSpec:
			for _, name := range s.Names {
				if !ast.IsExported(name.Name) || hasDoc(decl.Doc) || hasDoc(s.Doc) {
					continue
				}
				position := unit.FileSet.Position(name.Pos())
				findings = append(findings, finding.Finding{
					Message:  fmt.Sprintf("exported %s %q has no doc comment", valueKind(decl.Tok), name.Name),
					File:     unit.File.Path,
					Location: &finding.Location{Line: position.Line},
					Symbol:   name.Name,
					Metadata: map[string]any{"symbol": name.Name, "kind": valueKind(decl.Tok)},
				})
			}
		}
	}
	return findings
}

// isExportedFunc reports whether a function or method is externally visible.
func isExportedFunc(fn *ast.FuncDecl) bool {
	if !ast.IsExported(fn.Name.Name) {
		return false
	}
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return ast.IsExported(receiverTypeName(fn.Recv.List[0]))
	}
	return true
}

// receiverTypeName extracts the type name of a method receiver field.
func receiverTypeName(field *ast.Field) string {
	switch expr := field.Type.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.StarExpr:
		if ident, ok := expr.X.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return ""
}

// hasDoc reports whether a comment group contains any non-whitespace text.
func hasDoc(group *ast.CommentGroup) bool {
	return group != nil && strings.TrimSpace(group.Text()) != ""
}

// funcKind returns "function" or "method" for use in user-facing messages.
func funcKind(fn *ast.FuncDecl) string {
	if fn.Recv != nil {
		return "method"
	}
	return "function"
}

// valueKind maps a value-decl token to a user-friendly noun (const, var, value).
func valueKind(tok token.Token) string {
	switch tok {
	case token.CONST:
		return "const"
	case token.VAR:
		return "var"
	}
	return "value"
}
