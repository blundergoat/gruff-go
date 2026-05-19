// Package rule defines gruff-go's rule registry and analysers.
// This file defines the core builtin rule pack (size, complexity, docs, sensitive data).
package rule

import (
	"fmt"
	"go/ast"
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
func (r FunctionLengthRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.File.Type != source.FileTypeGo {
		return nil
	}
	maxLines := r.maxLines()
	findings := []finding.Finding{}
	for _, fn := range unit.Functions {
		length := fn.EndLine - fn.Line + 1
		if length <= maxLines {
			continue
		}
		metadata := map[string]any{"lines": length, "threshold": maxLines}
		if isGoTestFile(unit.File.Path) {
			metadata["testFile"] = true
		}
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("function has %d lines, above threshold %d", length, maxLines),
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
