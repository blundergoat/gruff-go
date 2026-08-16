// Package rule defines the checks users see in gruff-go scan results.
// This file implements core size, complexity, documentation, and secret checks.
// Each finding points users toward code that is easier to review or safer to ship.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// Default thresholds and secret-detection patterns used by the builtin rule pack.
const (
	fileLengthThreshold     = 1000
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

// Definition declares the size.file-length rule with a default 1000 substantive-line cap, error severity, and high confidence.
func (r FileLengthRule) Definition() Definition {
	maxLines := r.maxLines()
	return Definition{
		ID:             "size.file-length",
		Title:          "File length",
		Description:    "Flags Go files whose substantive line count (blank and comment-only lines are free) exceeds the threshold.",
		Pillar:         finding.PillarSize,
		Severity:       finding.SeverityError,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Thresholds:     map[string]float64{"maxLines": float64(maxLines)},
		Remediation:    "Split the file by responsibility or move focused behavior into smaller files.",
	}
}

// AnalyzeUnit emits one finding when a Go file exceeds the substantive-line limit.
// Blank and comment-only lines are free, so documentation does not inflate the result.
func (r FileLengthRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	maxLines := r.maxLines()
	// Non-Go inputs use their own checks and never show a Go file-length finding.
	if unit.File.Type != source.FileTypeGo {
		return nil
	}
	codeLines := substantiveLineNumbers(unit)
	substantiveLines := len(codeLines)
	// Files within the configured limit stay out of the user's findings list.
	if substantiveLines <= maxLines {
		return nil
	}
	metadata := map[string]any{"lines": substantiveLines, "threshold": maxLines}
	// Test metadata lets the registry soften fixture-size findings for users.
	if isGoTestFile(unit.File.Path) {
		metadata["testFile"] = true
	}
	return []finding.Finding{{
		Message: fmt.Sprintf("file has %d substantive lines, above threshold %d", substantiveLines, maxLines),
		File:    unit.File.Path,
		Location: &finding.Location{
			// Anchor to where the threshold is actually crossed. The count skips
			// blanks and comments, so the physical line of the (maxLines+1)th code
			// line is what a reviewer opens and what changed-region filtering matches.
			Line: codeLines[maxLines],
		},
		Metadata: metadata,
	}}
}

// substantiveLineNumbers returns the 1-based physical line number of every line
// carrying code, in source order. Blank and comment-only lines are omitted, so the
// caller gets both the count (via len) and where each counted line actually sits -
// the two differ whenever a file carries documentation or spacing.
// Comment ranges come from the parsed AST, so strings containing comment markers stay substantive;
// parse-failed files fall back to counting non-blank raw lines.
func substantiveLineNumbers(unit parser.Unit) []int {
	sourceWithoutComments := []byte(unit.Source)
	// Parsed comment positions keep quoted comment markers visible as user code.
	if unit.AST != nil && unit.FileSet != nil {
		maskParsedComments(sourceWithoutComments, unit)
	}
	lineNumbers := []int{}
	// Every remaining non-empty line represents code the user must review.
	for index, line := range strings.Split(string(sourceWithoutComments), "\n") {
		if strings.TrimSpace(line) != "" {
			lineNumbers = append(lineNumbers, index+1)
		}
	}
	return lineNumbers
}

// maskParsedComments replaces parsed comment text with spaces while preserving lines.
// The scanner can then count code without mistaking comments inside strings for prose.
func maskParsedComments(sourceWithoutComments []byte, unit parser.Unit) {
	cgoPreamble := cgoPreambleComment(unit.AST)
	// Each group may contain adjacent line comments or one block comment.
	for _, commentGroup := range unit.AST.Comments {
		// A cgo preamble is compiled C source, not prose, so it stays countable.
		if cgoPreamble != nil && commentGroup == cgoPreamble {
			continue
		}
		for _, comment := range commentGroup.List {
			commentStart := unit.FileSet.Position(comment.Pos()).Offset
			commentEnd := unit.FileSet.Position(comment.End()).Offset
			maskSourceRange(sourceWithoutComments, commentStart, commentEnd)
		}
	}
}

// cgoPreambleComment returns the comment group holding the C source that precedes
// `import "C"`. go/parser reports it as an ordinary comment, but cgo compiles it
// as part of the program, so masking it would drop real code from every line
// count and let a large mixed Go/C file slip past the size rules unreported.
func cgoPreambleComment(file *ast.File) *ast.CommentGroup {
	if file == nil {
		return nil
	}
	for _, declaration := range file.Decls {
		importDecl, isGenDecl := declaration.(*ast.GenDecl)
		if !isGenDecl || importDecl.Tok != token.IMPORT {
			continue
		}
		for _, spec := range importDecl.Specs {
			importSpec, isImport := spec.(*ast.ImportSpec)
			if !isImport || importSpec.Path == nil || importSpec.Path.Value != `"C"` {
				continue
			}
			// A grouped import carries the preamble on the spec; the single-import
			// form cgo requires for a preamble carries it on the declaration.
			if importSpec.Doc != nil {
				return importSpec.Doc
			}
			return importDecl.Doc
		}
	}
	return nil
}

// maskSourceRange clears one comment span but retains newline boundaries.
// Keeping those boundaries preserves the line numbers users see in findings.
func maskSourceRange(sourceWithoutComments []byte, commentStart int, commentEnd int) {
	for byteIndex := commentStart; byteIndex < commentEnd && byteIndex < len(sourceWithoutComments); byteIndex++ {
		// Newlines stay in place so later UI locations still match the source file.
		if sourceWithoutComments[byteIndex] == '\n' {
			continue
		}
		sourceWithoutComments[byteIndex] = ' '
	}
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
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Thresholds:     map[string]float64{"maxLines": float64(maxLines)},
		Remediation:    "Extract cohesive helper functions or split independent branches.",
	}
}

// AnalyzeUnit emits findings for functions longer than the threshold, measured
// in code-bearing lines. Direct `//nolint:funlen` or `//nolint:all` doc comments
// suppress the rule for one function without global configuration.
func (r FunctionLengthRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.File.Type != source.FileTypeGo {
		return nil
	}
	maxLines := r.maxLines()
	hasCandidate := false
	for _, fn := range unit.Functions {
		if fn.EndLine-fn.Line+1 > maxLines {
			hasCandidate = true
			break
		}
	}
	if !hasCandidate {
		return nil
	}
	codeLines := codeBearingLines(unit.Source)
	nolintNames := funlenNolintNames(unit.AST)
	funcDecls := funcDeclsBySymbol(unit.AST)
	findings := []finding.Finding{}
	for _, fn := range unit.Functions {
		rawLength := fn.EndLine - fn.Line + 1
		if rawLength <= maxLines {
			continue
		}
		if nolintNames[fn.Name] {
			continue
		}
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
			if decl := funcDecls[fn.Name]; decl != nil {
				tableLines := countLinesInLineRanges(codeLines, tableFixtureLineRanges(unit.FileSet, decl))
				if tableLines > 0 {
					length -= tableLines
					metadata["tableFixtureLines"] = tableLines
					metadata["lines"] = length
				}
			}
		}
		if length <= maxLines {
			continue
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
		Severity:       finding.SeverityWarning,
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
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Remediation:    "Add a package comment that explains the package responsibility.",
	}
}

// AnalyzeProject emits one finding per Go package that has no package-level comment.
func (PackageCommentRule) AnalyzeProject(units []parser.Unit, ctx Context) []finding.Finding {
	type packageState struct {
		name        string
		file        string
		primaryFile string
		hasDoc      bool
		hasCode     bool
		hasNonTest  bool
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
		// Prefer a reportable file as the anchor so an explicit-file scan still
		// reports a genuine package-comment violation instead of dropping a
		// finding anchored to a context-only sibling.
		if ctx.isReportable(unit.File.Path) && (state.primaryFile == "" || unit.File.Path < state.primaryFile) {
			state.primaryFile = unit.File.Path
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
		file := state.primaryFile
		if file == "" {
			file = state.file
		}
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("package %s has no package comment", state.name),
			File:     file,
			Location: &finding.Location{Line: 1},
			Metadata: map[string]any{"package": state.name},
		})
	}
	return findings
}

// SensitiveDataRule flags secret-like key/value assignments in Go and text/config files.
type SensitiveDataRule struct {
	previews sensitivePreviewPolicy
}

// Definition declares the sensitive-data.secret-pattern rule that flags secret-like key/value assignments with high severity.
func (SensitiveDataRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.secret-pattern",
		Title:          "Secret-like literal",
		Description:    "Flags high-risk secret-like key/value assignments in Go and text/config files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityError,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Remediation:    "Move secrets to a secret manager or environment-specific runtime configuration.",
	}
}

// AnalyzeUnit emits findings for every code-bearing line that matches the secret-assignment pattern.
func (r SensitiveDataRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	findings := []finding.Finding{}
	inBlockComment := false
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		if unit.File.Type == source.FileTypeGo && !lineIsCodeBearing(line, &inBlockComment) {
			continue
		}
		if unit.File.Type != source.FileTypeGo && textLineIsComment(line) {
			continue
		}
		matches := secretPattern.FindStringSubmatch(line)
		if len(matches) < 2 || matches[1] == "" {
			continue
		}
		match := matches[1]
		if unit.File.Type == source.FileTypeGo && !goSecretAssignmentLooksLiteral(match) {
			continue
		}
		if isPlaceholderSecretAssignment(match) {
			continue
		}
		metadata := map[string]any{
			"preview": r.previews.format(unit.File.Path, previewGeneric, match),
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

// goSecretAssignmentLooksLiteral keeps the generic secret rule focused on
// literals in Go code. Function calls such as password := generateToken() are
// not embedded secrets even when the variable name is secret-shaped.
func goSecretAssignmentLooksLiteral(match string) bool {
	for _, separator := range []string{":=", "=", ":"} {
		index := strings.Index(match, separator)
		if index < 0 {
			continue
		}
		value := strings.TrimSpace(match[index+len(separator):])
		return strings.HasPrefix(value, `"`) || strings.HasPrefix(value, "'") || strings.HasPrefix(value, "`")
	}
	return false
}

// textLineIsComment reports whether a non-Go config/text line is comment-only.
// Go comment handling lives in lineIsCodeBearing; this covers the line-comment
// markers that dominate config formats (#, //, ;) so a secret-shaped example a
// maintainer commented out (e.g. `# api_key = "your-key"` in a .env or .toml)
// is not flagged as a live secret assignment.
func textLineIsComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, ";")
}

// placeholderSecretTokens are documentation-placeholder markers that mark an
// otherwise secret-shaped value as an example rather than a real credential.
// They are matched as a value prefix (not a substring) so a real secret that
// merely contains one of these runs is not skipped.
var placeholderSecretTokens = []string{
	"changeme", "change-me", "change_me",
	"replaceme", "replace-me", "replace_me",
	"placeholder", "redacted", "dummy", "xxxxxxxx",
}

// isPlaceholderSecretAssignment reports whether a generic key/value match uses
// an obvious documentation placeholder rather than a secret-shaped value, so
// example configs (${VAR}, your-api-key, CHANGEME, REDACTED) do not flag while
// real high-entropy credentials still do.
func isPlaceholderSecretAssignment(match string) bool {
	value := secretAssignmentValue(match)
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") && len(value) > 3 {
		return true
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "your-") || strings.HasPrefix(lower, "your_") {
		return true
	}
	for _, token := range placeholderSecretTokens {
		if strings.HasPrefix(lower, token) {
			return true
		}
	}
	return false
}

// secretAssignmentValue extracts the right-hand value from a generic secret assignment match.
func secretAssignmentValue(match string) string {
	for _, separator := range []string{":=", "=", ":"} {
		index := strings.Index(match, separator)
		if index < 0 {
			continue
		}
		value := strings.TrimSpace(match[index+len(separator):])
		value = strings.Trim(value, `"'`)
		return strings.TrimPrefix(value, "Bearer ")
	}
	return ""
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
