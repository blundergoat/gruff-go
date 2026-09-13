// Package parser tests exercise unit construction and diagnostic reporting.
// They write temp files and run Parse to confirm AST and function metadata.
package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blundergoat/gruff-go/internal/source"
)

// TestParseBuildsUnitsAndFunctionMetadata verifies AST and function info on a healthy file.
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

// TestParseReportsParseDiagnostics confirms broken source produces diagnostics not units.
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

// TestParseWithBudgetDegradesOnlyGoFiles covers independent line/byte bounds and the non-code sentinel.
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
