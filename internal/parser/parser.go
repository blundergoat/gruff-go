// Package parser builds parser-only source Units from the files a scan discovered.
//
// It uses the standard library go/parser without type-checking or import resolution, so a Go file with type errors still parses.
// A file that cannot be read, or a Go file that fails to parse, gets no Unit and is reported as a Diagnostic instead.
// Under a deep-scan budget, an oversized Go file keeps its raw text but no AST, and a non-fatal bounded-deep-scan Diagnostic records the skip.
package parser

import (
	"fmt"
	"go/ast"
	stdparser "go/parser"
	"go/scanner"
	"go/token"
	"os"
	"strings"

	"github.com/blundergoat/gruff-go/internal/source"
)

// Unit is a parsed source file with the data rules need for analysis.
//
// Every file that was read gets one, Go or not; only a Go file parsed within the deep-scan budget carries AST, FileSet and Functions.
// A Go file that failed to parse gets no Unit; its parser errors come back as diagnostics instead.
type Unit struct {
	// File describes the discovered source file metadata (path, classification).
	File source.File
	// Source is the raw file contents read from disk.
	Source string
	// AST is the parsed Go syntax tree; nil for non-Go files and Go files kept as raw text by the deep-scan budget.
	AST *ast.File
	// FileSet is the position information backing AST; nil when AST is nil.
	FileSet *token.FileSet
	// LineCount is the total line count of Source.
	LineCount int
	// Functions lists top-level functions, methods and var-assigned function literals extracted from AST; nil when AST is nil.
	Functions []Function
}

// Function describes a top-level function, method or var-assigned function literal discovered during parsing.
type Function struct {
	// Name is the FuncDeclSymbol rendering, such as "Foo.Bar" for a method, or the var name for a var-assigned function literal.
	Name string
	// Line is the 1-based line where the declaration begins.
	Line int
	// EndLine is the 1-based line where the declaration ends.
	EndLine int
}

// Diagnostic reports a read error, parser error or deep-scan skip attached to a specific file.
//
// A Go file with a syntax error, such as a missing closing brace, gets one per reported parser error, with its line and column.
// A file deleted between discovery and reading gets one with no position, whose message starts with read failed.
type Diagnostic struct {
	// Type identifies a stable diagnostic contract such as bounded-deep-scan; empty for read and parse failures.
	Type string `json:"diagnosticType,omitempty"`
	// File is the source file's path as discovery reported it, which may be absolute for an input outside the discovery root.
	File string `json:"file,omitempty"`
	// Line is the 1-based line where the failure was reported; zero when unknown.
	Line int `json:"line,omitempty"`
	// Column is the 1-based column where the failure was reported; zero when unknown.
	Column int `json:"column,omitempty"`
	// Message is the read failure text, the parser error text, or the explanation of a deep-scan skip.
	Message string `json:"message"`
	// NonFatal keeps an informational degradation from invalidating the run.
	NonFatal bool `json:"-"`
}

// DeepScanBudget controls whether expensive Go AST construction runs for one source file.
//
// When Enabled is true, a Go file over MaxLines lines or MaxBytes bytes keeps raw text but no AST, and gets a bounded-deep-scan diagnostic.
// Override is echoed in that diagnostic's message; the zero value turns the budget off, which is what Parse uses.
type DeepScanBudget struct {
	Enabled  bool
	MaxLines int
	MaxBytes int
	Override string
}

// Parse converts discovered source files into Units and parser diagnostics.
//
// It applies no deep-scan budget and returns a Unit for every file that was read, except Go files that failed to parse, in input order.
// The diagnostics hold one entry per unreadable file and per parser error, and are empty, never nil, when nothing failed.
func Parse(files []source.File) ([]Unit, []Diagnostic) {
	return ParseWithBudget(files, DeepScanBudget{})
}

// ParseWithBudget parses files while degrading over-budget Go sources to raw-text units.
//
// When budget is enabled, a Go file over MaxLines lines or MaxBytes bytes keeps no AST and gets a non-fatal bounded-deep-scan Diagnostic.
// It returns a Unit for every file that was read, except Go files that failed to parse, in input order, with all parsed ASTs sharing one FileSet.
// The diagnostics hold one entry per unreadable file, per parser error and per over-budget file, and are empty, never nil, when none occurred.
func ParseWithBudget(files []source.File, budget DeepScanBudget) ([]Unit, []Diagnostic) {
	units := make([]Unit, 0, len(files))
	diagnostics := []Diagnostic{}
	fset := token.NewFileSet()

	for _, file := range files {
		data, err := os.ReadFile(file.AbsPath)
		// A file deleted or made unreadable after discovery gets a read failed diagnostic and no Unit; the remaining files still parse.
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
		// An oversized Go file, such as a large generated file, skips AST rules; its NonFatal diagnostic does not invalidate the run.
		if budget.Enabled && (unit.LineCount > budget.MaxLines || len(data) > budget.MaxBytes) {
			diagnostics = append(diagnostics, Diagnostic{
				Type:     "bounded-deep-scan",
				File:     file.Path,
				Line:     1,
				NonFatal: true,
				Message:  fmt.Sprintf("path=%s; lines=%d; bytes=%d; maxLines=%d; maxBytes=%d; override=%s. Text-level rules (size, sensitive-data, config) still ran; masking, block parsing, AST walking, and other deep script analysis were skipped.", file.Path, unit.LineCount, len(data), budget.MaxLines, budget.MaxBytes, budget.Override),
			})
			units = append(units, unit)
			continue
		}
		parsed, err := stdparser.ParseFile(fset, file.AbsPath, data, stdparser.ParseComments)
		// A syntax error, such as a missing closing brace, lands here: the file gets no Unit and one diagnostic per parser error.
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
//
// Every Diagnostic carries path unchanged from the discovered file and is built from err, the error the Go parser returned for that file.
// It returns one Diagnostic per entry, with its line and column, when err is a scanner.ErrorList, and an empty slice for an empty list.
// Any other err gives a single Diagnostic with no position whose message is the err text with every occurrence of path plus a colon removed.
func parseDiagnostics(path string, err error) []Diagnostic {
	// go/parser reports syntax errors as a scanner.ErrorList, so each one keeps its own line and column.
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

// functions extracts top-level function metadata from a parsed AST file, including the function literals selected by PackageVarFuncs.
//
// Each such literal's findings take their identity from the var's span, and symbol-scope changed-region filtering uses that span too.
// ParseWithBudget stores the result as Unit.Functions.
// fset is the FileSet file was parsed with; it turns each declaration's start and end positions into 1-based lines.
//
// It returns each function and method declaration in source order, named by FuncDeclSymbol, then each var-assigned literal named by its var.
// The result is empty, never nil, when file declares neither.
func functions(fset *token.FileSet, file *ast.File) []Function {
	out := []Function{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		start := fset.Position(fn.Pos())
		end := fset.Position(fn.End())
		out = append(out, Function{Name: FuncDeclSymbol(fn), Line: start.Line, EndLine: end.Line})
	}
	for _, varFunc := range PackageVarFuncs(file) {
		start := fset.Position(varFunc.Name.Pos())
		end := fset.Position(varFunc.Lit.End())
		out = append(out, Function{Name: varFunc.Name.Name, Line: start.Line, EndLine: end.Line})
	}
	return out
}

// VarFunc is a function literal assigned to a package-level var, such as var Mix = func(seed int) int { ... }.
//
// The size and complexity rules measure it like a declared function, and the opt-in parameter and return doc rules read its var comment.
// See FAMILY-CONTRACT.md section 12, and search for "function literal assigned to a package-level".
type VarFunc struct {
	// Name is the var the literal is assigned to, which names the function in findings.
	Name *ast.Ident
	// Doc is the comment above the var, or above its declaration when that declaration has only this one spec.
	Doc *ast.CommentGroup
	// Lit is the assigned function literal.
	Lit *ast.FuncLit
}

// PackageVarFuncs lists unparenthesised function literals assigned by name to package-level vars, in source order.
//
// file is the parsed source to scan, and a nil file gives no entries.
// Blank names, and specs whose names and values do not pair one to one, are skipped.
// It returns one VarFunc per literal, holding the var name, its doc comment and the literal, and an empty slice, never nil, when there is none.
func PackageVarFuncs(file *ast.File) []VarFunc {
	out := []VarFunc{}
	if file == nil {
		return out
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			// Only a one-to-one pairing of names and values says which name a literal is assigned to.
			if !ok || len(value.Names) != len(value.Values) {
				continue
			}
			for index, name := range value.Names {
				lit, isLiteral := value.Values[index].(*ast.FuncLit)
				// The blank identifier names nothing a reader could find.
				if !isLiteral || name.Name == "_" {
					continue
				}
				doc := value.Doc
				if doc == nil && len(gen.Specs) == 1 {
					doc = gen.Doc
				}
				out = append(out, VarFunc{Name: name, Doc: doc, Lit: lit})
			}
		}
	}
	return out
}

// FuncDeclSymbol renders a function declaration's symbol, the name Function metadata and the rules that call it give the declaration.
//
// A free function renders as its name and a method as BaseType.Method, with no pointer marker and no type arguments.
// So a Push method on the generic *Stack renders as Stack.Push, exactly as one on *Plain renders as Plain.Push.
//
// fn is the declaration to render, read only for its name and its first receiver field.
// It returns the rendered symbol, or receiver.Method when the base type cannot be resolved, which valid Go never produces.
// The symbol is never empty for a declaration the Go parser produced.
func FuncDeclSymbol(fn *ast.FuncDecl) string {
	name := fn.Name.Name
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return name
	}
	if base := ReceiverTypeName(fn.Recv.List[0]); base != "" {
		return base + "." + name
	}
	return "receiver." + name
}

// ReceiverTypeName returns the declared base type of a method receiver, unwrapping parentheses, pointers and generic type arguments.
//
// Type arguments arrive as IndexExpr for one and IndexListExpr for several, and both unwrap to the base type name.
// It returns an empty string for any other shape, and FuncDeclSymbol then falls back to receiver.Method.
// field is a method's receiver entry, and only its Type expression is inspected.
func ReceiverTypeName(field *ast.Field) string {
	expr := field.Type
	for {
		switch item := expr.(type) {
		case *ast.Ident:
			return item.Name
		case *ast.StarExpr:
			expr = item.X
		case *ast.ParenExpr:
			expr = item.X
		case *ast.IndexExpr:
			expr = item.X
		case *ast.IndexListExpr:
			expr = item.X
		default:
			return ""
		}
	}
}

// countLines returns the number of lines in text, the file contents, including a final line without a newline, or zero for empty text.
// ParseWithBudget stores it as Unit.LineCount, which the deep-scan budget compares with MaxLines.
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
