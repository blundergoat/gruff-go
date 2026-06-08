// Package rule tests the parser-only go.mod dependency-posture rules.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// goModUnit builds a go.mod text unit for dependency-rule tests.
func goModUnit(src string) parser.Unit {
	return parser.Unit{
		File:   source.File{Path: "go.mod", Type: source.FileTypeText},
		Source: src,
	}
}

// TestGoModReplaceRules covers local and remote replace directives across the
// single-line and block forms, and the no-replace / non-go.mod cases.
func TestGoModReplaceRules(t *testing.T) {
	tests := []struct {
		name       string
		src        string
		wantLocal  int
		wantRemote int
	}{
		{
			name:       "single local replace",
			src:        "module example.com/app\n\ngo 1.25.0\n\nreplace example.com/lib => ../lib\n",
			wantLocal:  1,
			wantRemote: 0,
		},
		{
			name:       "single remote replace",
			src:        "module example.com/app\n\nreplace example.com/lib v1.0.0 => example.com/fork v1.0.1\n",
			wantLocal:  0,
			wantRemote: 1,
		},
		{
			name:       "block with both",
			src:        "module example.com/app\n\nreplace (\n\texample.com/a => ./vendored/a\n\texample.com/b v1.2.0 => example.com/b-fork v1.2.1\n)\n",
			wantLocal:  1,
			wantRemote: 1,
		},
		{
			name:       "absolute local path",
			src:        "module example.com/app\n\nreplace example.com/lib => /opt/lib\n",
			wantLocal:  1,
			wantRemote: 0,
		},
		{
			// go.mod permits a quoted replace target; the quotes must be stripped
			// before classifying or "../lib" reads as a remote module path.
			name:       "quoted local path",
			src:        "module example.com/app\n\nreplace example.com/lib => \"../lib\"\n",
			wantLocal:  1,
			wantRemote: 0,
		},
		{
			name:       "no replace directives",
			src:        "module example.com/app\n\ngo 1.25.0\n\nrequire example.com/dep v1.0.0\n",
			wantLocal:  0,
			wantRemote: 0,
		},
		{
			name:       "commented-out replace is ignored",
			src:        "module example.com/app\n\n// replace example.com/lib => ../lib\nrequire example.com/dep v1.0.0 // see replace note a => b\n",
			wantLocal:  0,
			wantRemote: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := goModUnit(tt.src)
			if got := (GoModLocalReplaceRule{}).AnalyzeUnit(unit, Context{}); len(got) != tt.wantLocal {
				t.Fatalf("local findings = %#v, want %d", got, tt.wantLocal)
			}
			if got := (GoModRemoteReplaceRule{}).AnalyzeUnit(unit, Context{}); len(got) != tt.wantRemote {
				t.Fatalf("remote findings = %#v, want %d", got, tt.wantRemote)
			}
		})
	}
}

// TestGoModRulesIgnoreNonGoMod confirms the rules only run on go.mod, not other
// files that happen to contain an arrow token.
func TestGoModRulesIgnoreNonGoMod(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "notes.txt", Type: source.FileTypeText},
		Source: "replace example.com/lib => ../lib\n",
	}
	if got := (GoModLocalReplaceRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("local findings on non-go.mod = %#v, want none", got)
	}
	if got := (GoModRemoteReplaceRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("remote findings on non-go.mod = %#v, want none", got)
	}
}
