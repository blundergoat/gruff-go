// Package parser builds parser-only source units from discovered files.
// It uses the standard library go/parser without type-checking or imports resolution.
package parser

import (
	"go/ast"
	stdparser "go/parser"
	"go/scanner"
	"go/token"
	"os"
	"strings"

	"github.com/blundergoat/gruff-go/internal/source"
)

// Unit is a parsed source file with the data rules need for analysis.
type Unit struct {
	// File describes the discovered source file metadata (path, classification).
	File source.File
	// Source is the raw file contents read from disk.
	Source string
	// AST is the parsed Go syntax tree; nil for non-Go files or parse failures.
	AST *ast.File
	// FileSet is the position information backing AST; nil when AST is nil.
	FileSet *token.FileSet
	// LineCount is the total line count of Source.
	LineCount int
	// Functions lists top-level function and method declarations extracted from AST.
	Functions []Function
}

// Function describes a top-level function or method discovered during parsing.
type Function struct {
	// Name is the function identifier, prefixed with the receiver type for methods (e.g. "Foo.Bar").
	Name string
	// Line is the 1-based line where the declaration begins.
	Line int
	// EndLine is the 1-based line where the declaration ends.
	EndLine int
}

// Diagnostic reports a parser failure or read error attached to a specific file.
type Diagnostic struct {
	// File is the repo-relative path of the source file the diagnostic targets.
	File string `json:"file,omitempty"`
	// Line is the 1-based line where the failure was reported; zero when unknown.
	Line int `json:"line,omitempty"`
	// Column is the 1-based column where the failure was reported; zero when unknown.
	Column int `json:"column,omitempty"`
	// Message is the parser or I/O error text.
	Message string `json:"message"`
}

// Parse converts discovered source files into Units and parser diagnostics.
func Parse(files []source.File) ([]Unit, []Diagnostic) {
	units := make([]Unit, 0, len(files))
	diagnostics := []Diagnostic{}
	fset := token.NewFileSet()

	for _, file := range files {
		data, err := os.ReadFile(file.AbsPath)
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic{
				File:    file.Path,
				Message: "read failed: " + err.Error(),
			})
			continue
		}
		sourceText := string(data)
		unit := Unit{
			File:      file,
			Source:    sourceText,
			LineCount: countLines(sourceText),
		}
		if file.Type != source.FileTypeGo {
			units = append(units, unit)
			continue
		}
		parsed, err := stdparser.ParseFile(fset, file.AbsPath, data, stdparser.ParseComments)
		if err != nil {
			diagnostics = append(diagnostics, parseDiagnostics(file.Path, err)...)
			continue
		}
		unit.AST = parsed
		unit.FileSet = fset
		unit.Functions = functions(fset, parsed)
		units = append(units, unit)
	}

	return units, diagnostics
}

// parseDiagnostics converts a parser error or error list into per-file diagnostics.
func parseDiagnostics(path string, err error) []Diagnostic {
	if list, ok := err.(scanner.ErrorList); ok {
		out := make([]Diagnostic, 0, len(list))
		for _, item := range list {
			out = append(out, Diagnostic{
				File:    path,
				Line:    item.Pos.Line,
				Column:  item.Pos.Column,
				Message: item.Msg,
			})
		}
		return out
	}
	return []Diagnostic{{
		File:    path,
		Message: strings.ReplaceAll(err.Error(), path+":", ""),
	}}
}

// functions extracts top-level function metadata from a parsed AST file.
func functions(fset *token.FileSet, file *ast.File) []Function {
	out := []Function{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		start := fset.Position(fn.Pos())
		end := fset.Position(fn.End())
		name := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			name = receiverName(fn.Recv.List[0]) + "." + name
		}
		out = append(out, Function{Name: name, Line: start.Line, EndLine: end.Line})
	}
	return out
}

// receiverName returns the receiver type name for method declarations.
func receiverName(field *ast.Field) string {
	switch expr := field.Type.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.StarExpr:
		if ident, ok := expr.X.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return "receiver"
}

// countLines returns the total newline-terminated line count of the source text.
func countLines(text string) int {
	if text == "" {
		return 0
	}
	lines := strings.Count(text, "\n")
	if !strings.HasSuffix(text, "\n") {
		lines++
	}
	return lines
}
