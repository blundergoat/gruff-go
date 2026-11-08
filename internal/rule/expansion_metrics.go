// Package rule defines the checks users see in gruff-go scan results.
//
// This file holds size.parameter-count, complexity.nesting-depth and docs.exported-symbol-comment, all enabled by default.
// Each finding names a structural symptom with advice, which can be to avoid further growth rather than to change existing code.
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
//
// A rule uses its default when its configured limit is zero or negative, and each finding shows the limit it was measured against.
const (
	parameterCountThreshold = 8
	nestingDepthThreshold   = 5
)

// ParameterCountRule finds functions whose input list exceeds the project limit.
//
// Users see it when an API may be easier to call with options or smaller steps.
// Method receivers are excluded, even when a caller passes one explicitly through a method expression.
type ParameterCountRule struct {
	// MaxParameters is the most parameters a function may take, receiver excluded, before a finding is emitted; zero or negative means 8.
	MaxParameters int
}

// maxParameters returns the configured parameter limit, or the built-in default of 8 when MaxParameters is zero or negative.
// A zero value means use the default, not flag every function that takes inputs.
func (r ParameterCountRule) maxParameters() int {
	// An omitted or invalid limit means the user accepted the built-in default.
	if r.MaxParameters <= 0 {
		return parameterCountThreshold
	}
	return r.MaxParameters
}

// Definition declares the size.parameter-count rule with a default maximum of 8 non-receiver parameters and advisory severity.
// It returns metadata whose maxParameters threshold is the configured MaxParameters, or 8 when that is zero or negative.
func (r ParameterCountRule) Definition() Definition {
	maximumParameters := r.maxParameters()
	return Definition{
		ID:             "size.parameter-count",
		Title:          "Parameter count",
		Description:    "Flags functions and methods whose parameter list exceeds the configured maximum, excluding the method receiver.",
		Pillar:         finding.PillarSize,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Thresholds:     map[string]float64{"maxParameters": float64(maximumParameters)},
		Remediation:    "Group the parameters that travel together into one object, or split the function by caller.",
		FalsePositiveShapes: []FalsePositiveShape{{
			Shape:      "A framework callback, interface implementation, exported ABI, or compatibility surface may require a wide signature the user cannot reshape.",
			Mitigation: "Keep the required signature, then raise maxParameters or disable size.parameter-count in project configuration after review.",
		}},
	}
}

// AnalyzeUnit emits findings for every function whose parameter count exceeds the threshold.
//
// Functions come from measuredFuncDecls, and each finding spans the function's lines and records its parameter count and the threshold.
// It returns nil when unit has no parsed AST or FileSet, and an empty slice when every measured function is within the limit.
func (r ParameterCountRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	// A parse failure has no trustworthy signature to show the user.
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	maximumParameters := r.maxParameters()
	findings := []finding.Finding{}
	// Each declaration can represent a separate API a caller must understand.
	for _, functionDeclaration := range measuredFuncDecls(unit.AST) {
		// A declaration without a signature has no parameter list to assess.
		if functionDeclaration.Type == nil {
			continue
		}
		parameterTotal := paramCount(functionDeclaration)
		// Signatures within the configured limit stay out of the findings list.
		if parameterTotal <= maximumParameters {
			continue
		}
		start := unit.FileSet.Position(functionDeclaration.Pos())
		end := unit.FileSet.Position(functionDeclaration.End())
		findings = append(findings, withLimitBand(finding.Finding{
			Message:  fmt.Sprintf("function has %d parameters, above threshold %d", parameterTotal, maximumParameters),
			File:     unit.File.Path,
			Location: &finding.Location{Line: start.Line, EndLine: end.Line},
			Symbol:   functionName(functionDeclaration),
			Metadata: map[string]any{"parameters": parameterTotal, "threshold": maximumParameters},
		}, parameterTotal, maximumParameters, lowerBandParameterAdvice, r.Definition().Remediation))
	}
	return findings
}

// paramCount expands grouped names and counts each unnamed input once.
//
// It reads the Go AST, so nested function types cannot truncate the signature.
// Receivers live outside Params and do not appear in the user-facing count.
//
// It returns the number of inputs a caller passes to fn, counting a variadic parameter once, and zero when fn takes none.
func paramCount(fn *ast.FuncDecl) int {
	// A missing parameter list means callers provide no inputs.
	if fn.Type == nil || fn.Type.Params == nil {
		return 0
	}
	parameterTotal := 0
	// Grouped names still represent separate inputs in the user's signature.
	for _, field := range fn.Type.Params.List {
		// An unnamed type such as func(int) still consumes one argument.
		if len(field.Names) == 0 {
			parameterTotal++
			continue
		}
		parameterTotal += len(field.Names)
	}
	return parameterTotal
}

// NestingDepthRule flags functions whose maximum control-flow nesting exceeds the threshold.
//
// It backs complexity.nesting-depth, a warning on by default; each if, for, range, switch, type switch and select it visits adds one level.
// An else if chain counts as one level, and a labeled statement is not visited, so it and everything inside it add nothing.
type NestingDepthRule struct {
	// MaxDepth is the per-function control-flow nesting cap; zero or negative means 5, and nested function literals are not measured.
	MaxDepth int
}

// maxDepth returns the configured nesting cap, or nestingDepthThreshold of 5 when MaxDepth is zero or negative.
// It follows the same zero-means-default convention as maxParameters, whose doc gives the rationale.
func (r NestingDepthRule) maxDepth() int {
	if r.MaxDepth <= 0 {
		return nestingDepthThreshold
	}
	return r.MaxDepth
}

// Definition declares the complexity.nesting-depth rule with a default maximum of 5 control-flow levels under the complexity pillar.
// It returns metadata whose maxDepth threshold is the configured MaxDepth, or 5 when that is zero or negative, at warning severity.
func (r NestingDepthRule) Definition() Definition {
	maximumDepth := r.maxDepth()
	return Definition{
		ID:             "complexity.nesting-depth",
		Title:          "Nesting depth",
		Description:    "Flags functions whose maximum control-flow nesting depth exceeds the configured threshold. Function literals reset the count.",
		Pillar:         finding.PillarComplexity,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Thresholds:     map[string]float64{"maxDepth": float64(maximumDepth)},
		Remediation:    simplifyExecutionPathAdvice,
	}
}

// AnalyzeUnit emits findings for every function whose nesting depth exceeds the threshold.
//
// Each function body from measuredFuncDecls over unit is measured from depth zero, and each finding records the depth and the threshold.
// It returns nil when unit has no parsed AST or FileSet, and an empty slice when every measured function is within the limit.
func (r NestingDepthRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	maximumDepth := r.maxDepth()
	findings := []finding.Finding{}
	for _, fn := range measuredFuncDecls(unit.AST) {
		// A declaration with no body, such as a function implemented in assembly, has nothing to measure.
		if fn.Body == nil {
			continue
		}
		depth := blockNestingDepth(fn.Body, 0)
		if depth <= maximumDepth {
			continue
		}
		start := unit.FileSet.Position(fn.Pos())
		end := unit.FileSet.Position(fn.End())
		findings = append(findings, withLimitBand(finding.Finding{
			Message:  fmt.Sprintf("function nesting depth is %d, above threshold %d", depth, maximumDepth),
			File:     unit.File.Path,
			Location: &finding.Location{Line: start.Line, EndLine: end.Line},
			Symbol:   functionName(fn),
			Metadata: map[string]any{"depth": depth, "threshold": maximumDepth},
		}, depth, maximumDepth, lowerBandFunctionAdvice, simplifyExecutionPathAdvice))
	}
	return findings
}

// blockNestingDepth finds the deepest control-flow nesting in block, in mutual recursion with stmtNestingDepth and clausesNestingDepth.
//
// depth is the level inherited from the caller, not a fresh zero, so a block inside an already-nested if reports the outer nesting too.
// It returns the deepest level any statement in block reaches, and depth itself for a nil or empty block.
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

// stmtNestingDepth is where depth increments: each if, for, range, switch, type switch or select adds one level.
//
// An else if arm is walked at the original depth, so a long if/else-if chain counts as one level, matching how a person reads it.
// A literal else block uses depth+1 like any other body.
//
// stmt is one statement and depth is the nesting level of the block that holds it.
// It returns the deepest level reached inside stmt, never less than depth.
//
// A bare block is walked at the same depth, and any other statement kind gives depth unchanged.
// So a labeled loop, with everything inside it, and the body of any function literal add no depth.
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

// clausesNestingDepth walks switch, type switch and select clauses, whose bodies are bare statement lists that blockNestingDepth cannot take.
//
// body is the switch, type switch or select body; every clause shares depth, which already includes that statement's own level.
// It returns the deepest level reached in any clause, and depth itself for a nil body or clauses with no control flow.
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
//
// It backs docs.exported-symbol-comment, on by default; findings name the symbol, plus any doc requests signatureDocAsks finds for a function.
// Test files are never checked, and files under an internal/ directory are skipped when IgnoreInternalPackages is true.
type ExportedSymbolCommentRule struct {
	// IgnoreInternalPackages skips files living under any internal/ directory when true.
	IgnoreInternalPackages bool
}

// Definition declares the docs.exported-symbol-comment rule that flags undocumented exported declarations and skips internal packages by default.
// It returns the same metadata whatever IgnoreInternalPackages holds, with the ignoreInternalPackages option advertised as true.
func (ExportedSymbolCommentRule) Definition() Definition {
	return Definition{
		ID:             "docs.exported-symbol-comment",
		Title:          "Exported symbol comment",
		Description:    "Flags exported top-level Go declarations (functions, methods on exported types, types, vars, consts) that have no doc comment.",
		Pillar:         finding.PillarDocumentation,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Options:        map[string]any{"ignoreInternalPackages": true},
		Remediation:    "Add a Go-style doc comment that begins with the symbol name.",
	}
}

// AnalyzeUnit emits findings for exported declarations in a unit that have no doc comment.
//
// It returns nil for a unit without a parsed AST or FileSet, a _test.go file, or an internal directory path when IgnoreInternalPackages is set.
// Otherwise it returns one finding per undocumented exported top-level name, except methods on unexported types, or an empty slice if none.
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
// Only directory segments split on forward slashes count, so a file named internal at the end of path does not match.
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
//
// unit supplies the file path and positions, and decl is one entry of unit.AST.Decls.
// It returns the findings from exportedFuncFinding or exportedGenDeclFindings, and nil for a BadDecl.
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
//
// The message adds the doc requests signatureDocAsks builds from the signature, or no suffix when it finds none.
// unit supplies the file path and position, and fn is the declaration checked.
// It returns one finding at the line fn starts on, and nil when fn is unexported, a method on an unexported type, or already documented.
func exportedFuncFinding(unit parser.Unit, fn *ast.FuncDecl) []finding.Finding {
	if !isExportedFunc(fn) || hasDoc(fn.Doc) {
		return nil
	}
	position := unit.FileSet.Position(fn.Pos())
	return []finding.Finding{{
		Message:  fmt.Sprintf("exported %s %q has no doc comment", funcKind(fn), fn.Name.Name) + signatureDocAsks(fn.Type),
		File:     unit.File.Path,
		Location: &finding.Location{Line: position.Line},
		Symbol:   functionName(fn),
		Metadata: map[string]any{"symbol": fn.Name.Name, "kind": funcKind(fn)},
	}}
}

// signatureDocAsks returns the message suffix that tells the user what a doc comment for this signature should cover.
//
// It asks to describe each named parameter, skipping blanks and context, HTTP and testing handles only in their standard package spellings.
// Returned values are asked for only when a non-error result exists, and when an error is returned only when a result has type error.
//
// fnType is the signature of the function being reported, read by undocumentedParameters and undocumentedReturns.
// It returns "" when the signature asks for none of these.
func signatureDocAsks(fnType *ast.FuncType) string {
	asks := []string{}
	if params := undocumentedParameters(fnType, nil); len(params) > 0 {
		asks = append(asks, "describe "+parameterPhrase(params))
	}
	gap := undocumentedReturns(fnType, nil)
	if gap.value {
		asks = append(asks, "describe "+returnedValuePhrase(gap.values))
	}
	if gap.failure {
		asks = append(asks, "say when an error is returned")
	}
	if len(asks) == 0 {
		return ""
	}
	return "; " + strings.Join(asks, "; ")
}

// exportedGenDeclFindings emits findings for exported types, vars, and consts missing doc comments.
//
// unit supplies the file path and positions; decl is one type, var, const or import declaration, and a doc on it or on a spec counts.
// It returns one finding per undocumented exported type or value name, and an empty slice when there are none, as for any import declaration.
func exportedGenDeclFindings(unit parser.Unit, decl *ast.GenDecl) []finding.Finding {
	findings := []finding.Finding{}
	// A doc comment on the whole declaration counts for every spec in it, so one comment above a grouped const or type block clears them all.
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

// isExportedFunc reports whether fn qualifies for the exported-symbol documentation check.
//
// fn qualifies when its name is exported and, for a method, the receiver type name from parser.ReceiverTypeName is exported too.
// So an exported method on an unexported type is not checked, even though other packages can call it through an exported value.
func isExportedFunc(fn *ast.FuncDecl) bool {
	if !ast.IsExported(fn.Name.Name) {
		return false
	}
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return ast.IsExported(parser.ReceiverTypeName(fn.Recv.List[0]))
	}
	return true
}

// hasDoc reports whether a comment group contains any non-whitespace text.
// A nil group, or one whose Text is empty because it holds only blank lines or directives such as go:generate, reports false.
func hasDoc(group *ast.CommentGroup) bool {
	return group != nil && strings.TrimSpace(group.Text()) != ""
}

// funcKind picks the noun, method or function, that the finding message and its kind metadata use for fn.
//
// This only changes wording; eligibility, such as skipping methods on unexported types, is decided by isExportedFunc, not here.
// fn is the declaration being reported; a non-nil Recv gives "method", and anything else gives "function".
func funcKind(fn *ast.FuncDecl) string {
	if fn.Recv != nil {
		return "method"
	}
	return "function"
}

// valueKind maps a value-decl token to a user-friendly noun (const, var, value).
// tok is the GenDecl token; it returns const for token.CONST, var for token.VAR, and value for any other token.
func valueKind(tok token.Token) string {
	switch tok {
	case token.CONST:
		return "const"
	case token.VAR:
		return "var"
	}
	return "value"
}
