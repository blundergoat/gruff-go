package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blundergoat/gruff-go/internal/source"
)

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
