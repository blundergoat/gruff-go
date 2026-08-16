// Package cli tests that a `-` flag value does not strand the global flags after it.
package cli

import (
	"os"
	"slices"
	"testing"
)

// TestNormalizeGlobalStdinFlagValues pins that a stdin patch value is folded into
// its flag token, so the bare dash never reaches a global extractor as a terminator.
func TestNormalizeGlobalStdinFlagValues(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "double dash diff folds its value",
			args: []string{"analyse", "--diff", "-", "--quiet", "."},
			want: []string{"analyse", "--diff=-", "--quiet", "."},
		},
		{
			name: "single dash diff folds its value",
			args: []string{"analyse", "-diff", "-", "--quiet", "."},
			want: []string{"analyse", "-diff=-", "--quiet", "."},
		},
		{
			name: "since folds its value too",
			args: []string{"analyse", "--since", "-", "--quiet", "."},
			want: []string{"analyse", "--since=-", "--quiet", "."},
		},
		{
			name: "an already folded value is unchanged",
			args: []string{"analyse", "--diff=-", "--quiet", "."},
			want: []string{"analyse", "--diff=-", "--quiet", "."},
		},
		{
			name: "a non-stdin diff value is unchanged",
			args: []string{"analyse", "--diff", "working-tree", "--quiet", "."},
			want: []string{"analyse", "--diff", "working-tree", "--quiet", "."},
		},
		{
			name: "an unrelated flag keeps its dash value",
			args: []string{"analyse", "--config", "-", "--quiet", "."},
			want: []string{"analyse", "--config", "-", "--quiet", "."},
		},
		{
			name: "a standalone stdin operand still protects later tokens",
			args: []string{"analyse", "-", "--diff", "-"},
			want: []string{"analyse", "-", "--diff", "-"},
		},
		{
			name: "a terminator still protects later tokens",
			args: []string{"analyse", "--", "--diff", "-"},
			want: []string{"analyse", "--", "--diff", "-"},
		},
		{
			name: "a trailing flag with no value is unchanged",
			args: []string{"analyse", "--diff"},
			want: []string{"analyse", "--diff"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeGlobalStdinFlagValues(tt.args)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("normalized = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestGlobalFlagsSurviveStdinPatchValue runs the real entrypoint: a global flag
// placed after `--diff -` or `--since -` must still take effect instead of
// reaching the analyse FlagSet, which would reject it as an undefined flag.
func TestGlobalFlagsSurviveStdinPatchValue(t *testing.T) {
	globalFlags := []string{"--quiet", "-q", "--silent", "-v", "--verbose", "--no-ansi", "--no-interaction"}
	for _, patchFlag := range []string{"--diff", "--since"} {
		for _, globalFlag := range globalFlags {
			t.Run(patchFlag+" "+globalFlag, func(t *testing.T) {
				withEmptyStdin(t)
				exitCode, _, stderr := captureCLIResult([]string{"analyse", patchFlag, "-", globalFlag, "."})
				if exitCode == 2 {
					t.Fatalf("exit = 2 for %s after %s -, stderr = %q", globalFlag, patchFlag, stderr)
				}
				if stderr != "" {
					t.Fatalf("stderr = %q, want none for %s after %s -", stderr, globalFlag, patchFlag)
				}
			})
		}
	}
}

// TestQuietSuppressesOutputAfterStdinPatchValue confirms the recovered flag is
// applied rather than merely accepted: quiet still discards the command's stdout.
func TestQuietSuppressesOutputAfterStdinPatchValue(t *testing.T) {
	withEmptyStdin(t)
	_, stdout, _ := captureCLIResult([]string{"analyse", "--diff", "-", "--quiet", "."})
	if len(stdout) != 0 {
		t.Fatalf("stdout = %q, want none under --quiet", stdout)
	}
}

// withEmptyStdin points os.Stdin at an already-closed pipe for one test. Reading a
// `-` patch drains stdin, so an inherited terminal would otherwise block the suite.
func withEmptyStdin(t *testing.T) {
	t.Helper()
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if err := writeEnd.Close(); err != nil {
		t.Fatalf("close write end: %v", err)
	}
	original := os.Stdin
	os.Stdin = readEnd
	t.Cleanup(func() {
		os.Stdin = original
		readEnd.Close()
	})
}
