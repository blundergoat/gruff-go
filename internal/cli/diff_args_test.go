// Package cli implements the gruff-go command-line interface.
// This file exercises the bare-`--diff` argument normaliser.
package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNormalizeAnalyseDiffArgs covers the bare-`--diff` optional-value rewrite and
// the filesystem fallback: a prefix-less token that names an existing file is kept
// as a positional scan path, while an unknown token is consumed as the base ref.
func TestNormalizeAnalyseDiffArgs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scanme.go"), []byte("package x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"stdin sentinel", []string{"--diff", "-"}, []string{"--diff=-"}},
		{"bare diff at end", []string{"--diff"}, []string{"--diff=working-tree"}},
		{"bare diff before flag", []string{"--diff", "--format", "json"}, []string{"--diff=working-tree", "--format", "json"}},
		{"dot-prefixed path", []string{"--diff", "./x"}, []string{"--diff=working-tree", "./x"}},
		{"existing relative path stays a path", []string{"--diff", "scanme.go"}, []string{"--diff=working-tree", "scanme.go"}},
		{"unknown ref consumed as base", []string{"--diff", "no-such-ref-xyz"}, []string{"--diff", "no-such-ref-xyz"}},
		{"explicit value untouched", []string{"--diff=staged"}, []string{"--diff=staged"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeAnalyseDiffArgs(tt.args)
			if len(got) != len(tt.want) {
				t.Fatalf("normalizeAnalyseDiffArgs(%q) = %q, want %q", tt.args, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("normalizeAnalyseDiffArgs(%q) = %q, want %q", tt.args, got, tt.want)
				}
			}
		})
	}
}
