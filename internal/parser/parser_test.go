// Package parser tests exercise how gruff-go turns source files into analysis units and parse diagnostics.
//
// Most tests write temp files and run Parse or ParseWithBudget on them.
// Each test checks the AST, line count, function names, or the diagnostics reported for broken or oversized Go files.
package parser

import (
	"go/ast"
	stdparser "go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/blundergoat/gruff-go/internal/source"
)

// TestParseBuildsUnitsAndFunctionMetadata verifies AST and function info on a healthy file.
// A clean four-line main.go must give one unit with an AST, LineCount 4, one function named main, and no diagnostics.
func TestParseBuildsUnitsAndFunctionMetadata(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "main.go")
	if err := os.WriteFile(path, []byte("package main\n\nfunc main() {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	units, diagnostics := Parse([]source.File{{Path: "main.go", AbsPath: path, Type: source.FileTypeGo}})
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v, want none", diagnostics)
	}
	if len(units) != 1 {
		t.Fatalf("units = %d, want 1", len(units))
	}
	if units[0].AST == nil {
		t.Fatal("AST is nil")
	}
	if units[0].LineCount != 4 {
		t.Fatalf("line count = %d, want 4", units[0].LineCount)
	}
	if len(units[0].Functions) != 1 || units[0].Functions[0].Name != "main" {
		t.Fatalf("functions = %#v, want main", units[0].Functions)
	}
}

// TestFuncDeclSymbolRendersTheBaseTypeForEveryReceiverShape checks how FuncDeclSymbol names functions and methods for every receiver shape.
//
// Generic receivers drop pointers and type arguments like plain ones, so FuncDeclSymbol and Parse metadata name them Stack.Method or Pair.Method.
// A parenthesised receiver renders its base type, and a selector receiver such as pkg.Foreign renders as receiver.OnSelector.
func TestFuncDeclSymbolRendersTheBaseTypeForEveryReceiverShape(t *testing.T) {
	src := `package sample

func Free() {}
func (v Value) OnValue() {}
func (p *Pointer) OnPointer() {}
func (s Stack[T]) OnGeneric() {}
func (s *Stack[T]) OnGenericPointer() {}
func (p Pair[K, V]) OnPair() {}
func (p *Pair[K, V]) OnPairPointer() {}
func (q (*Paren)) OnParen() {}
func (s pkg.Foreign) OnSelector() {}
`
	file, err := stdparser.ParseFile(token.NewFileSet(), "sample.go", src, stdparser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"Free",
		"Value.OnValue",
		"Pointer.OnPointer",
		"Stack.OnGeneric",
		"Stack.OnGenericPointer",
		"Pair.OnPair",
		"Pair.OnPairPointer",
		"Paren.OnParen",
		"receiver.OnSelector",
	}
	got := []string{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			got = append(got, FuncDeclSymbol(fn))
		}
	}
	if len(got) != len(want) {
		t.Fatalf("symbols = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("symbol %d = %q, want %q (all: %v)", index, got[index], want[index], got)
		}
	}

	// Parse must store the same rendered name in function metadata, not the raw receiver text.
	root := t.TempDir()
	path := filepath.Join(root, "stack.go")
	if err := os.WriteFile(path, []byte("package sample\n\nfunc (s *Stack[T]) Push(item T) {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	units, diagnostics := Parse([]source.File{{Path: "stack.go", AbsPath: path, Type: source.FileTypeGo}})
	if len(diagnostics) != 0 || len(units) != 1 {
		t.Fatalf("units = %#v, diagnostics = %#v, want one clean unit", units, diagnostics)
	}
	if len(units[0].Functions) != 1 || units[0].Functions[0].Name != "Stack.Push" {
		t.Fatalf("functions = %#v, want Stack.Push", units[0].Functions)
	}
}

// TestParseReportsParseDiagnostics confirms broken source produces diagnostics not units.
// A syntax error must yield no unit and a diagnostic with the file path and a nonzero line, so the user can find what failed to parse.
func TestParseReportsParseDiagnostics(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "broken.go")
	if err := os.WriteFile(path, []byte("package main\nfunc broken( {\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	units, diagnostics := Parse([]source.File{{Path: "broken.go", AbsPath: path, Type: source.FileTypeGo}})
	if len(units) != 0 {
		t.Fatalf("units = %d, want 0", len(units))
	}
	if len(diagnostics) == 0 {
		t.Fatal("expected diagnostics")
	}
	if diagnostics[0].File != "broken.go" || diagnostics[0].Line == 0 {
		t.Fatalf("diagnostic = %#v, want file and line", diagnostics[0])
	}
}

// TestParseWithBudgetDegradesOnlyGoFiles covers independent line and byte bounds for the bounded deep scan.
//
// Each case trips one limit alone and checks for two units, with nonempty source and no AST in the first.
// It also requires exactly one non-fatal bounded-deep-scan diagnostic for main.go.
func TestParseWithBudgetDegradesOnlyGoFiles(t *testing.T) {
	root := t.TempDir()
	goPath := filepath.Join(root, "main.go")
	textPath := filepath.Join(root, "notes.md")
	if err := os.WriteFile(goPath, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(textPath, []byte("ordinary text\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	files := []source.File{
		{Path: "main.go", AbsPath: goPath, Type: source.FileTypeGo},
		{Path: "notes.md", AbsPath: textPath, Type: source.FileTypeText},
	}
	for _, budget := range []DeepScanBudget{
		{Enabled: true, MaxLines: 1, MaxBytes: 10_000, Override: "config"},
		{Enabled: true, MaxLines: 100, MaxBytes: 1, Override: "cli"},
	} {
		units, diagnostics := ParseWithBudget(files, budget)
		if len(units) != 2 || units[0].AST != nil || units[0].Source == "" {
			t.Fatalf("units = %#v, want raw Go unit without AST plus text unit", units)
		}
		if len(diagnostics) != 1 || diagnostics[0].Type != "bounded-deep-scan" || diagnostics[0].File != "main.go" || !diagnostics[0].NonFatal {
			t.Fatalf("diagnostics = %#v, want one non-fatal Go budget diagnostic", diagnostics)
		}
	}
}
