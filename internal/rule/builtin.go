// Package rule defines the checks users see in gruff-go scan results.
//
// This file holds the file-length, function-length, cyclomatic-complexity, package-comment and secret-pattern rules.
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
//
// A rule whose MaxLines or MaxComplexity is zero or negative falls back to these thresholds.
// secretAssignmentPattern finds a secret-shaped key, then :=, = or :, an optional quote and Bearer prefix, and 20 or more token characters.
const (
	fileLengthThreshold     = 1000
	functionLengthThreshold = 80
	cyclomaticThreshold     = 20
	secretKeyPattern        = `api[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization|bearer|secret|token|password`
	secretAssignmentPattern = `(?i)(?:^|[^A-Za-z0-9_-])((?:` + secretKeyPattern + `)\s*(?::=|=|:)\s*["']?(?:Bearer\s+)?[A-Za-z0-9_./+=-]{20,})`
)

// secretPattern is the compiled regex used by SensitiveDataRule to flag secret-like assignments.
var secretPattern = regexp.MustCompile(secretAssignmentPattern)

// FileLengthRule is size.file-length: it flags a Go file whose substantive lines exceed MaxLines.
//
// Blank and comment-only lines are free in a file that parsed, so documentation never pushes it over the limit; a cgo preamble still counts.
type FileLengthRule struct {
	// MaxLines is the per-file line cap; files whose line count exceeds it produce a finding.
	MaxLines int
}

// maxLines returns the effective file-length threshold for this rule.
// It returns MaxLines when positive, else the 1000-line default, so a zero or negative MaxLines never disables the rule.
func (r FileLengthRule) maxLines() int {
	if r.MaxLines <= 0 {
		return fileLengthThreshold
	}
	return r.MaxLines
}

// Definition declares the size.file-length rule with a default 1000 substantive-line cap, error severity, and high confidence.
// It returns the rule metadata, enabled by default, with maxLines set from MaxLines, or 1000 when that is zero or negative.
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
		Remediation:    "Split this file by responsibility, one responsibility per file.",
	}
}

// AnalyzeUnit emits one finding when a Go file exceeds the substantive-line limit.
//
// Blank and comment-only lines are free when the file parsed, so documentation does not inflate the result; a cgo preamble still counts as code.
// The unit is the scanned file; a non-Go unit or one within the limit gives nil, and the finding sits on the first code line past the limit.
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
	return []finding.Finding{withLimitBand(finding.Finding{
		Message: fmt.Sprintf("file has %d substantive lines, above threshold %d", substantiveLines, maxLines),
		File:    unit.File.Path,
		Location: &finding.Location{
			// Anchor to where the threshold is actually crossed.
			//
			// The count skips blanks and comments, so the (maxLines+1)th code line is what a reviewer opens and what changed-region filtering matches.
			Line: codeLines[maxLines],
		},
		Metadata: metadata,
	}, substantiveLines, maxLines, lowerBandFileAdvice, r.Definition().Remediation)}
}

// substantiveLineNumbers returns the 1-based line number of every line carrying code, in source order.
//
// Blank lines and comment-only lines outside a cgo preamble are omitted, so callers get the count through len and where each counted line sits.
// Comment ranges come from the parsed AST, so a string holding comment markers stays code; with no AST, every non-blank raw line counts.
//
// The unit supplies the source text and, when its AST and FileSet are both set, the comment positions to mask.
// The result is empty, not nil, when the source has no code line.
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

// maskParsedComments replaces parsed comment text, except a cgo preamble, with spaces while preserving lines.
//
// The scanner can then count code without mistaking comments inside strings for prose.
// It overwrites sourceWithoutComments in place, which must hold the bytes of unit.Source; unit must carry a non-nil AST and FileSet.
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

// cgoPreambleComment returns the comment group holding the C source that precedes import "C".
//
// go/parser reports it as an ordinary comment, but cgo compiles it as part of the program.
// Masking it would drop real code from every line count and let a large mixed Go/C file slip past the size rules unreported.
//
// The file is the parsed Go file; the result is nil when file is nil or has no import "C" carrying a preamble comment.
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
//
// Keeping those boundaries preserves the line numbers users see in findings.
// It overwrites sourceWithoutComments in place from byte offset commentStart up to but excluding commentEnd, stopping at the end of the buffer.
//
// A negative commentStart below commentEnd panics with an index out of range.
func maskSourceRange(sourceWithoutComments []byte, commentStart int, commentEnd int) {
	for byteIndex := commentStart; byteIndex < commentEnd && byteIndex < len(sourceWithoutComments); byteIndex++ {
		// Newlines stay in place so finding line numbers still match the source file.
		if sourceWithoutComments[byteIndex] == '\n' {
			continue
		}
		sourceWithoutComments[byteIndex] = ' '
	}
}

// FunctionLengthRule is size.function-length: it flags a Go function whose adjusted code-line count exceeds MaxLines.
//
// The count covers code-bearing lines from the func keyword, or the var name for a package-level function literal, to the declaration's end.
type FunctionLengthRule struct {
	// MaxLines is the per-function line cap; functions longer than this trigger a finding.
	MaxLines int
}

// maxLines returns the effective per-function line threshold for this rule.
// It returns MaxLines when positive, else the 80-line default, so a zero or negative MaxLines never disables the rule.
func (r FunctionLengthRule) maxLines() int {
	if r.MaxLines <= 0 {
		return functionLengthThreshold
	}
	return r.MaxLines
}

// Definition declares the size.function-length rule with a default 80-line cap, warning severity, and high confidence.
// It returns the rule metadata, enabled by default, with maxLines set from MaxLines, or 80 when that is zero or negative.
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
		Remediation:    "Split this function at its steps, one step per function.",
	}
}

// AnalyzeUnit emits a finding for each function whose adjusted code-line count over its recorded span exceeds the threshold.
//
// The span starts at the func keyword, or at the var name for a package-level function literal, and ends where the declaration ends.
// A //nolint:funlen, //nolint:all or bare //nolint on that start line, or alone on the line above, suppresses the finding.
// analysis.ApplyInlineSuppressions honours and counts it after the rules run, so this method still emits the finding.
//
// In a test file, table-fixture lines are subtracted; in any file, a keyed literal passed directly to a call counts as one line.
// The unit is the scanned file; it returns one finding per function still over the limit after those discounts.
// A non-Go unit, or one with no function whose raw line span exceeds the limit, yields nil; otherwise the result is non-nil and may be empty.
func (r FunctionLengthRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.File.Type != source.FileTypeGo {
		return nil
	}
	maxLines := r.maxLines()
	hasCandidate := false
	// A cheap raw-span pass first: when every function fits before any discount, the file is done and the result is nil.
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
	funcDecls := funcDeclsBySymbol(unit.AST)
	findings := []finding.Finding{}
	for _, fn := range unit.Functions {
		rawLength := fn.EndLine - fn.Line + 1
		if rawLength <= maxLines {
			continue
		}
		length := countLinesInRange(codeLines, fn.Line, fn.EndLine)
		// With no code-bearing line found in the span, the raw span is used, so a function is never measured as empty.
		if length == 0 {
			length = rawLength
		}
		if length <= maxLines {
			continue
		}
		metadata := map[string]any{"threshold": maxLines, "rawLines": rawLength}
		decl := funcDecls[fn.Name]
		var tableRanges []lineRange
		// In a _test.go file, table-driven fixture rows are data: they come off the count and the finding carries testFile metadata.
		if isGoTestFile(unit.File.Path) {
			metadata["testFile"] = true
			tableRanges = tableFixtureLineRanges(unit.FileSet, decl)
			if tableLines := countLinesInLineRanges(codeLines, tableRanges); tableLines > 0 {
				length -= tableLines
				metadata["tableFixtureLines"] = tableLines
			}
		}
		// A keyed literal passed straight to a call is data, so it counts as one line in every file.
		if literalLines := countLinesInLineRangesExcept(codeLines, keyedLiteralArgumentLineRanges(unit.FileSet, decl), tableRanges); literalLines > 0 {
			length -= literalLines
			metadata["literalArgumentLines"] = literalLines
		}
		metadata["lines"] = length
		// The discounts can bring a function back under the limit, and then the user sees no finding for it.
		if length <= maxLines {
			continue
		}
		findings = append(findings, withLimitBand(finding.Finding{
			Message:  fmt.Sprintf("function has %d code lines, above threshold %d", length, maxLines),
			File:     unit.File.Path,
			Location: &finding.Location{Line: fn.Line, EndLine: fn.EndLine},
			Symbol:   fn.Name,
			Metadata: metadata,
		}, length, maxLines, lowerBandFunctionAdvice, r.Definition().Remediation))
	}
	return findings
}

// CyclomaticComplexityRule is complexity.cyclomatic: it flags a non-test Go function whose cyclomatic complexity exceeds MaxComplexity.
//
// The rule is disabled by default, so users see these findings only after enabling it; package-level var function literals are measured too.
type CyclomaticComplexityRule struct {
	// MaxComplexity is the per-function branch-count cap; functions above this fire a finding.
	MaxComplexity int
}

// maxComplexity returns the effective cyclomatic-complexity threshold for this rule.
// It returns MaxComplexity when positive, else the default of 20, so a zero or negative MaxComplexity never disables the check.
func (r CyclomaticComplexityRule) maxComplexity() int {
	if r.MaxComplexity <= 0 {
		return cyclomaticThreshold
	}
	return r.MaxComplexity
}

// Definition declares the complexity.cyclomatic rule with a default branch threshold of 20 under the complexity pillar.
// It returns the rule metadata, disabled by default, with maxComplexity set from MaxComplexity, or 20 when that is zero or negative.
func (r CyclomaticComplexityRule) Definition() Definition {
	maxComplexity := r.maxComplexity()
	return Definition{
		ID:             "complexity.cyclomatic",
		Title:          "Cyclomatic complexity",
		Description:    "Flags Go functions outside test files whose branch count exceeds the default cyclomatic threshold; a switch, type switch or select counts once.",
		Pillar:         finding.PillarComplexity,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: false,
		Thresholds:     map[string]float64{"maxComplexity": float64(maxComplexity)},
		Remediation:    simplifyExecutionPathAdvice,
	}
}

// measuredFuncDecls lists the declarations that size and complexity rules measure in file.
//
// It returns each function and method declaration, then each function literal held by a package-level var, named after that var.
// The result is empty, not nil, when file is nil or declares neither.
//
// Documentation rules find package-level function literals on their own, so this list does not decide which ones need docs.
// FAMILY-CONTRACT.md section 12 covers these literals; search it for "function literal assigned to a package-level".
func measuredFuncDecls(file *ast.File) []*ast.FuncDecl {
	out := []*ast.FuncDecl{}
	if file == nil {
		return out
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			out = append(out, fn)
		}
	}
	for _, varFunc := range parser.PackageVarFuncs(file) {
		out = append(out, &ast.FuncDecl{Doc: varFunc.Doc, Name: varFunc.Name, Type: varFunc.Lit.Type, Body: varFunc.Lit.Body})
	}
	return out
}

// AnalyzeUnit emits findings for every function whose cyclomatic complexity exceeds the threshold.
//
// The unit is the scanned file; a test file, or a unit without AST or FileSet, yields nil.
// Otherwise the result holds one finding per function or package-level var function literal over the threshold, empty when none is.
func (r CyclomaticComplexityRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	// A test's branches are its assertion sequence, which M14's measurement found not worth splitting.
	if unit.AST == nil || unit.FileSet == nil || isGoTestFile(unit.File.Path) {
		return nil
	}
	maxComplexity := r.maxComplexity()
	findings := []finding.Finding{}
	for _, fn := range measuredFuncDecls(unit.AST) {
		// A declaration without a body, such as an assembly-backed func, has no branches to measure.
		if fn.Body == nil {
			continue
		}
		complexity := cyclomaticComplexity(fn)
		if complexity <= maxComplexity {
			continue
		}
		start := unit.FileSet.Position(fn.Pos())
		end := unit.FileSet.Position(fn.End())
		findings = append(findings, withLimitBand(finding.Finding{
			Message:  fmt.Sprintf("function cyclomatic complexity is %d, above threshold %d", complexity, maxComplexity),
			File:     unit.File.Path,
			Location: &finding.Location{Line: start.Line, EndLine: end.Line},
			Symbol:   functionName(fn),
			Metadata: map[string]any{"complexity": complexity, "threshold": maxComplexity},
		}, complexity, maxComplexity, lowerBandFunctionAdvice, simplifyExecutionPathAdvice))
	}
	return findings
}

// PackageCommentRule is docs.package-comment: it flags a Go package where no file carries a package comment.
//
// It judges the whole scan at once, so one documented file clears its package, and a finding sits on line 1 of one file in the package.
type PackageCommentRule struct{}

// Definition declares the docs.package-comment rule that emits one low-severity finding per Go package missing a package-level summary.
// It returns fixed rule metadata, enabled by default with high confidence and no thresholds.
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
//
// The units are grouped by directory and package name, skipping any without an AST; ctx prefers a reportable file as the line-1 anchor.
// It returns the findings in no fixed order, skipping test-only _test packages; the slice is empty when every package has a comment.
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
		// A unit without an AST gives no package-comment evidence, so it neither clears its package nor anchors a finding.
		if unit.AST == nil {
			continue
		}
		key := filepath.Dir(unit.File.Path) + ":" + unit.AST.Name.Name
		state := packages[key]
		// The lexically first file is the fallback anchor, so the finding lands on the same file every run.
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
		// Only a package named with an _test suffix and built only from _test.go files is exempt; other test-only packages are still checked.
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

// SensitiveDataRule is sensitive-data.secret-pattern: it flags secret-like key/value assignments in Go and text/config files.
//
// Its previews policy formats the preview metadata each finding carries for the matched text.
type SensitiveDataRule struct {
	previews sensitivePreviewPolicy
}

// goRawStringLines reports every 1-based line that lies inside a Go raw-string literal, mapping each to true.
//
// The opening and closing lines are included, and a one-line raw string marks its own line too.
// The whole line is marked, so ordinary code sharing a line with a raw string is skipped by the secret rule as well.
//
// The unit must carry its parsed AST and FileSet for any exclusion; when either is nil the result is an empty, non-nil map.
// Such a unit's raw-string lines then go through the secret scan like any other line and can be reported.
func goRawStringLines(unit parser.Unit) map[int]bool {
	lines := map[int]bool{}
	if unit.AST == nil || unit.FileSet == nil {
		return lines
	}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING || !strings.HasPrefix(literal.Value, "`") {
			return true
		}
		start := unit.FileSet.Position(literal.Pos()).Line
		end := unit.FileSet.Position(literal.End()).Line
		for line := start; line <= end; line++ {
			lines[line] = true
		}
		return true
	})
	return lines
}

// Definition declares the sensitive-data.secret-pattern rule that flags secret-like key/value assignments with warning severity.
// It returns fixed rule metadata, enabled by default with medium confidence and no thresholds, for Go and text or config files alike.
func (SensitiveDataRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.secret-pattern",
		Title:          "Secret-like literal",
		Description:    "Flags high-risk secret-like key/value assignments in Go and text/config files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Remediation:    "Move secrets to a secret manager or environment-specific runtime configuration.",
	}
}

// AnalyzeUnit emits findings for every code-bearing line that matches the secret-assignment pattern.
//
// With a Go AST and FileSet, every line inside a raw-string literal is skipped, so a real credential inside a backtick string is missed too.
// Backtick strings commonly hold documentation, templates and sample payloads, such as gosec's g101_samples fixture.
// The exclusion comes from the syntax tree and is applied here, not in lineIsCodeBearing, so other rules sharing that guard are unaffected.
//
// For a Go unit, only code-bearing lines whose value starts with a quote or backtick count; any other unit skips comment lines.
// It returns at most one finding per line, dropping a whole match that isPlaceholderSecretAssignment or isDocumentedSample accepts.
// The result is empty, not nil, when nothing matches.
func (r SensitiveDataRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	findings := []finding.Finding{}
	inBlockComment := false
	rawStringLines := goRawStringLines(unit)
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		if unit.File.Type == source.FileTypeGo && rawStringLines[lineNumber+1] {
			continue
		}
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
		// Only a value starting with a quote counts in Go, so a credential inside a call or other computed expression is skipped.
		if unit.File.Type == source.FileTypeGo && !goSecretAssignmentLooksLiteral(match) {
			continue
		}
		// A placeholder, or a vendor-documented sample such as AWS's example key pasted from its docs, is not a credential.
		if isPlaceholderSecretAssignment(match) || isDocumentedSample(match) {
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

// goSecretAssignmentLooksLiteral keeps the generic secret rule focused on literals in Go code.
//
// A call such as password := generateToken() is skipped even when the name is secret-shaped, so a credential inside a call is missed too.
// It reports true when the value in match after its separator, tried as := then = then :, starts with a double quote, single quote or backtick.
// It reports false for any other value, or when match holds none of those separators.
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

// textLineIsComment reports whether a non-Go config or text line is comment-only; Go comments are handled by lineIsCodeBearing.
//
// It reports true when the trimmed line starts with #, // or ;, the line-comment markers that dominate config formats, and false otherwise.
// A commented-out example such as # api_key = "your-key" in a .env or .toml file is therefore not flagged as a live secret.
func textLineIsComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, ";")
}

// placeholderSecretTokens are documentation-placeholder markers that mark a secret-shaped value as an example rather than a real credential.
//
// Each is matched as a lowercased value prefix, not a substring: a real secret starting with one is skipped, one containing it later is not.
var placeholderSecretTokens = []string{
	"changeme", "change-me", "change_me",
	"replaceme", "replace-me", "replace_me",
	"placeholder", "redacted", "dummy", "xxxxxxxx",
}

// isPlaceholderSecretAssignment reports whether a generic key/value match holds a documentation placeholder instead of a real-looking value.
//
// It reports true when match's value is a ${VAR} reference or starts with your-, your_ or a placeholderSecretTokens entry, in any letter case.
// It reports false for any other value, or when match has no value after a separator, leaving the match to the caller's other checks.
// The check reads spelling only, so a real credential that starts with a placeholder marker is skipped too.
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
//
// It returns the text after the := separator, else = or :, trimmed of outer spaces, then single and double quotes, then a leading Bearer prefix.
// The result is empty when match has no separator or nothing is left after that trimming; spaces inside the quotes survive.
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
//
// A switch, type switch or select is one dispatch decision however many cases it has, as gruff-rs counts one per match.
// Counting the dispatch once keeps a flat dispatch over many cases from producing a finding through its case count alone.
//
// fn must have a Body; it returns 1 plus one per if, for, range, switch, type switch, select, && and ||, so a branch-free body gives 1.
// Function literals inside the body are skipped, so their branches add nothing.
func cyclomaticComplexity(fn *ast.FuncDecl) int {
	complexity := 1
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
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

// functionName returns the rendered function or method name, BaseType.Name for a method, generic or not.
//
// It comes from the parser's one canonical renderer, so a finding's symbol matches the function metadata it is positioned against.
// fn is the function or method declaration to name; it is passed unchanged to parser.FuncDeclSymbol.
func functionName(fn *ast.FuncDecl) string {
	return parser.FuncDeclSymbol(fn)
}

// isGoTestFile reports whether path names a Go test file, by its _test.go suffix.
// A false result means the rules here treat the file as production code: no testFile metadata, no table-fixture discount, full complexity checks.
func isGoTestFile(path string) bool {
	return strings.HasSuffix(path, "_test.go")
}
