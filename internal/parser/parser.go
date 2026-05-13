// Package parser builds parser-only source units from discovered files.
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

type Unit struct {
	File      source.File
	Source    string
	AST       *ast.File
	FileSet   *token.FileSet
	LineCount int
	Functions []Function
}

type Function struct {
	Name    string
	Line    int
	EndLine int
}

type Diagnostic struct {
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	Message string `json:"message"`
}

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
		unit := Unit{
			File:      file,
			Source:    string(data),
			LineCount: countLines(string(data)),
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
