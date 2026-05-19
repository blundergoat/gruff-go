// Package rule defines gruff-go's rule registry and analysers.
// This file defines the core builtin rule pack (size, complexity, docs, sensitive data).
package rule

import (
	"fmt"
	"go/ast"
	"go/scanner"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/pathfilter"
	"github.com/blundergoat/gruff-go/internal/source"
)

// Default thresholds and secret-detection patterns used by the builtin rule pack.
const (
	fileLengthThreshold     = 500
	functionLengthThreshold = 80
	cyclomaticThreshold     = 20
	secretKeyPattern        = `api[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization|bearer|secret|token|password`
	secretAssignmentPattern = `(?i)(?:^|[^A-Za-z0-9_-])((?:` + secretKeyPattern + `)\s*(?::=|=|:)\s*["']?(?:Bearer\s+)?[A-Za-z0-9_./+=-]{20,})`
)

// secretPattern is the compiled regex used by SensitiveDataRule to flag secret-like assignments.
var secretPattern = regexp.MustCompile(secretAssignmentPattern)

// FileLengthRule flags Go files whose line count exceeds the configured maximum.
type FileLengthRule struct {
	// MaxLines is the per-file line cap; files whose line count exceeds it produce a finding.
	MaxLines int
}

// maxLines returns the effective file-length threshold for this rule.
func (r FileLengthRule) maxLines() int {
	if r.MaxLines <= 0 {
		return fileLengthThreshold
	}
	return r.MaxLines
}

// Definition declares the size.file-length rule with a default 500-line cap, medium severity, and high confidence.
func (r FileLengthRule) Definition() Definition {
	maxLines := r.maxLines()
	return Definition{
		ID:             "size.file-length",
		Title:          "File length",
		Description:    "Flags Go files that exceed the default line-count threshold.",
		Pillar:         finding.PillarSize,
		Severity:       finding.SeverityMedium,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Thresholds:     map[string]float64{"maxLines": float64(maxLines)},
		Remediation:    "Split the file by responsibility or move focused behavior into smaller files.",
	}
}

// AnalyzeUnit emits one finding when a Go file's line count exceeds the threshold.
func (r FileLengthRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	maxLines := r.maxLines()
	if unit.File.Type != source.FileTypeGo || unit.LineCount <= maxLines {
		return nil
	}
	metadata := map[string]any{"lines": unit.LineCount, "threshold": maxLines}
	if isGoTestFile(unit.File.Path) {
		metadata["testFile"] = true
	}
	return []finding.Finding{{
		Message: fmt.Sprintf("file has %d lines, above threshold %d", unit.LineCount, maxLines),
		File:    unit.File.Path,
		Location: &finding.Location{
			Line: maxLines + 1,
		},
		Metadata: metadata,
	}}
}

// FunctionLengthRule flags Go functions whose body length exceeds the configured maximum.
type FunctionLengthRule struct {
	// MaxLines is the per-function line cap; functions longer than this trigger a finding.
	MaxLines int
}

// maxLines returns the effective per-function line threshold for this rule.
func (r FunctionLengthRule) maxLines() int {
	if r.MaxLines <= 0 {
		return functionLengthThreshold
	}
	return r.MaxLines
}

// Definition declares the size.function-length rule with a default 80-line body cap, medium severity, and high confidence.
func (r FunctionLengthRule) Definition() Definition {
	maxLines := r.maxLines()
	return Definition{
		ID:             "size.function-length",
		Title:          "Function length",
		Description:    "Flags Go functions that exceed the default line-count threshold.",
		Pillar:         finding.PillarSize,
		Severity:       finding.SeverityMedium,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Thresholds:     map[string]float64{"maxLines": float64(maxLines)},
		Remediation:    "Extract cohesive helper functions or split independent branches.",
	}
}

// AnalyzeUnit emits a finding for every function in the unit longer than the threshold.
//
// "Length" is measured in *code-bearing* lines — lines that contain at least
// one Go token after stripping whitespace and comments. The change keeps the
// threshold honest: a heavily documented but short function shouldn't be
// flagged just because its doc/inline comments inflate the raw span. The
// rule also honors a directly attached `//nolint:funlen` (or `//nolint:all`)
// doc comment so authors can opt out of a single function without configuring
// the rule globally.
func (r FunctionLengthRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.File.Type != source.FileTypeGo {
		return nil
	}
	maxLines := r.maxLines()
	codeLines := codeBearingLines(unit.Source)
	nolintNames := funlenNolintNames(unit.AST)
	findings := []finding.Finding{}
	for _, fn := range unit.Functions {
		if nolintNames[fn.Name] {
			continue
		}
		rawLength := fn.EndLine - fn.Line + 1
		length := countLinesInRange(codeLines, fn.Line, fn.EndLine)
		if length == 0 {
			length = rawLength
		}
		if length <= maxLines {
			continue
		}
		metadata := map[string]any{"lines": length, "threshold": maxLines, "rawLines": rawLength}
		if isGoTestFile(unit.File.Path) {
			metadata["testFile"] = true
		}
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("function has %d code lines, above threshold %d", length, maxLines),
			File:     unit.File.Path,
			Location: &finding.Location{Line: fn.Line, EndLine: fn.EndLine},
			Symbol:   fn.Name,
			Metadata: metadata,
		})
	}
	return findings
}

// codeBearingLines runs go/scanner over the source and returns the set of
// 1-based line numbers that hold at least one non-comment, non-whitespace
// token. Blank lines, doc-only lines, and lines inside `/* */` blocks are
// excluded. Returns nil for non-Go input or empty source.
func codeBearingLines(src string) map[int]bool {
	if src == "" {
		return nil
	}
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	// Suppress scanner errors: this rule should never fail because a partial
	// parse left junk behind; we only want token-line positions.
	s.Init(file, []byte(src), func(token.Position, string) {}, 0)
	out := map[int]bool{}
	for {
		pos, tok, _ := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.ILLEGAL {
			continue
		}
		out[file.Position(pos).Line] = true
	}
	return out
}

// countLinesInRange returns how many lines in [start, end] are code-bearing.
// When codeLines is nil (e.g. for non-Go input) the caller substitutes the raw
// span, so we don't silently emit zero-length findings.
func countLinesInRange(codeLines map[int]bool, start, end int) int {
	if codeLines == nil {
		return 0
	}
	count := 0
	for line := start; line <= end; line++ {
		if codeLines[line] {
			count++
		}
	}
	return count
}

// funlenNolintNames walks the file's function declarations and returns the
// names (matching parser.Function.Name, including the receiver prefix for
// methods) of those carrying a directly attached `//nolint:funlen` or
// `//nolint:all` directive in their doc comment. golangci-lint's broader nolint
// syntax (block-scoped directives, etc.) is intentionally not supported here —
// this is the narrow opt-out for a single function decl.
func funlenNolintNames(file *ast.File) map[string]bool {
	out := map[string]bool{}
	if file == nil {
		return out
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Doc == nil {
			continue
		}
		if !docMentionsFunlenNolint(fn.Doc) {
			continue
		}
		out[funcDeclSymbol(fn)] = true
	}
	return out
}

// docMentionsFunlenNolint reports whether a comment group contains a
// `//nolint:funlen`-style suppression entry. The parsing is intentionally
// liberal so reasonable variations (`//nolint: funlen`, `//nolint:funlen,goconst`,
// trailing explanatory `// reason`) all match.
func docMentionsFunlenNolint(doc *ast.CommentGroup) bool {
	for _, c := range doc.List {
		text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		if !strings.HasPrefix(text, "nolint") {
			continue
		}
		rest := strings.TrimPrefix(text, "nolint")
		if rest == "" {
			return true
		}
		if rest[0] != ':' {
			continue
		}
		rest = rest[1:]
		if i := strings.IndexAny(rest, " \t/"); i >= 0 {
			rest = rest[:i]
		}
		for _, name := range strings.Split(rest, ",") {
			name = strings.TrimSpace(name)
			if name == "funlen" || name == "all" {
				return true
			}
		}
	}
	return false
}

// funcDeclSymbol mirrors parser.functions' Name construction so nolint lookups
// align with the names attached to parser.Function entries.
func funcDeclSymbol(fn *ast.FuncDecl) string {
	name := fn.Name.Name
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return name
	}
	switch expr := fn.Recv.List[0].Type.(type) {
	case *ast.Ident:
		return expr.Name + "." + name
	case *ast.StarExpr:
		if ident, ok := expr.X.(*ast.Ident); ok {
			return ident.Name + "." + name
		}
	}
	return "receiver." + name
}

// CyclomaticComplexityRule flags Go functions with cyclomatic complexity above the threshold.
type CyclomaticComplexityRule struct {
	// MaxComplexity is the per-function branch-count cap; functions above this fire a finding.
	MaxComplexity int
}

// maxComplexity returns the effective cyclomatic-complexity threshold for this rule.
func (r CyclomaticComplexityRule) maxComplexity() int {
	if r.MaxComplexity <= 0 {
		return cyclomaticThreshold
	}
	return r.MaxComplexity
}

// Definition declares the complexity.cyclomatic rule with a default branch threshold of 20 under the complexity pillar.
func (r CyclomaticComplexityRule) Definition() Definition {
	maxComplexity := r.maxComplexity()
	return Definition{
		ID:             "complexity.cyclomatic",
		Title:          "Cyclomatic complexity",
		Description:    "Flags Go functions whose branch count exceeds the default cyclomatic threshold.",
		Pillar:         finding.PillarComplexity,
		Severity:       finding.SeverityMedium,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Thresholds:     map[string]float64{"maxComplexity": float64(maxComplexity)},
		Remediation:    "Split independent decisions or move branches into named helpers.",
	}
}

// AnalyzeUnit emits findings for every function whose cyclomatic complexity exceeds the threshold.
func (r CyclomaticComplexityRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	maxComplexity := r.maxComplexity()
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		complexity := cyclomaticComplexity(fn)
		if complexity <= maxComplexity {
			continue
		}
		start := unit.FileSet.Position(fn.Pos())
		end := unit.FileSet.Position(fn.End())
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("function cyclomatic complexity is %d, above threshold %d", complexity, maxComplexity),
			File:     unit.File.Path,
			Location: &finding.Location{Line: start.Line, EndLine: end.Line},
			Symbol:   functionName(fn),
			Metadata: map[string]any{"complexity": complexity, "threshold": maxComplexity},
		})
	}
	return findings
}

// PackageCommentRule flags Go packages that lack a package-level comment in any file.
type PackageCommentRule struct{}

// Definition declares the docs.package-comment rule that emits one low-severity finding per Go package missing a package-level summary.
func (PackageCommentRule) Definition() Definition {
	return Definition{
		ID:             "docs.package-comment",
		Title:          "Package comment",
		Description:    "Flags Go packages that do not have a package-level comment in any file.",
		Pillar:         finding.PillarDocumentation,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Remediation:    "Add a package comment that explains the package responsibility.",
	}
}

// AnalyzeProject emits one finding per Go package that has no package-level comment.
func (PackageCommentRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	type packageState struct {
		name       string
		file       string
		hasDoc     bool
		hasCode    bool
		hasNonTest bool
	}
	packages := map[string]packageState{}
	for _, unit := range units {
		if unit.AST == nil {
			continue
		}
		key := filepath.Dir(unit.File.Path) + ":" + unit.AST.Name.Name
		state := packages[key]
		if state.file == "" || unit.File.Path < state.file {
			state.file = unit.File.Path
		}
		state.name = unit.AST.Name.Name
		state.hasCode = true
		if !isGoTestFile(unit.File.Path) {
			state.hasNonTest = true
		}
		if unit.AST.Doc != nil {
			state.hasDoc = true
		}
		packages[key] = state
	}
	findings := []finding.Finding{}
	for _, state := range packages {
		if !state.hasCode || state.hasDoc {
			continue
		}
		if !state.hasNonTest && strings.HasSuffix(state.name, "_test") {
			continue
		}
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("package %s has no package comment", state.name),
			File:     state.file,
			Location: &finding.Location{Line: 1},
			Metadata: map[string]any{"package": state.name},
		})
	}
	return findings
}

// SensitiveDataRule flags secret-like key/value assignments in Go and text/config files.
type SensitiveDataRule struct {
	// PreviewAllowlist lists file path globs whose findings may include a redacted preview of the matched literal.
	PreviewAllowlist []string
}

// Definition declares the sensitive-data.secret-pattern rule that flags secret-like key/value assignments with high severity.
func (SensitiveDataRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.secret-pattern",
		Title:          "Secret-like literal",
		Description:    "Flags high-risk secret-like key/value assignments in Go and text/config files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityHigh,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Remediation:    "Move secrets to a secret manager or environment-specific runtime configuration.",
	}
}

// AnalyzeUnit emits findings for every line that matches the secret-assignment pattern.
func (r SensitiveDataRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	findings := []finding.Finding{}
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		matches := secretPattern.FindStringSubmatch(line)
		if len(matches) < 2 || matches[1] == "" {
			continue
		}
		match := matches[1]
		metadata := map[string]any{}
		if len(r.PreviewAllowlist) == 0 || pathfilter.MatchesAny(r.PreviewAllowlist, unit.File.Path) {
			metadata["preview"] = redact(match)
		}
		findings = append(findings, finding.Finding{
			Message:  "secret-like assignment detected",
			File:     unit.File.Path,
			Location: &finding.Location{Line: lineNumber + 1},
			Metadata: metadata,
		})
	}
	return findings
}

// cyclomaticComplexity counts the cyclomatic complexity of a function body.
func cyclomaticComplexity(fn *ast.FuncDecl) int {
	complexity := 1
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt:
			complexity++
		case *ast.CaseClause:
			if len(current.List) > 0 {
				complexity++
			}
		case *ast.CommClause:
			complexity++
		case *ast.BinaryExpr:
			if current.Op.String() == "&&" || current.Op.String() == "||" {
				complexity++
			}
		}
		return true
	})
	return complexity
}

// functionName returns the rendered function or method name (Receiver.Name when applicable).
func functionName(fn *ast.FuncDecl) string {
	name := fn.Name.Name
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		switch expr := fn.Recv.List[0].Type.(type) {
		case *ast.Ident:
			return expr.Name + "." + name
		case *ast.StarExpr:
			if ident, ok := expr.X.(*ast.Ident); ok {
				return ident.Name + "." + name
			}
		}
	}
	return name
}

// isGoTestFile reports whether the file path is a Go test file (_test.go suffix).
func isGoTestFile(path string) bool {
	return strings.HasSuffix(path, "_test.go")
}

// redact masks a secret-like value, keeping only enough characters for triage.
func redact(value string) string {
	if len(value) <= 12 {
		return "[redacted]"
	}
	return value[:6] + "..." + value[len(value)-4:]
}
