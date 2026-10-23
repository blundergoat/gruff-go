// Package cli check-ignore command tests: verdict + pattern correctness, the
// JSON agent contract, git-style exit codes, and that the command shares the
// analyse ignore engine rather than reimplementing matching.
package cli

import (
	"bytes"
	"encoding/json"
	"testing"
)

// writeIgnoreConfig writes a .gruff-go.yaml that ignores the ignored/ subtree,
// the shared fixture for the check-ignore tests.
func writeIgnoreConfig(t *testing.T, root string) {
	t.Helper()
	writeFile(t, root, ".gruff-go.yaml", "schemaVersion: gruff-go.config.v0.1\npaths:\n  ignore:\n    - \"ignored/**\"\n")
}

// TestCheckIgnoreJSONReportsVerdictAndPattern checks the JSON contract: an
// ignored path reports source+pattern, a non-ignored path reports ignored=false
// with no source, and exit code 0 signals "at least one ignored" like git.
func TestCheckIgnoreJSONReportsVerdictAndPattern(t *testing.T) {
	root := t.TempDir()
	writeIgnoreConfig(t, root)
	writeFile(t, root, "ignored/bad.go", "package ignored\n")
	writeFile(t, root, "main.go", "package main\n")
	t.Chdir(root)

	var out, errOut bytes.Buffer
	code := Main([]string{"check-ignore", "--format", "json", "ignored/bad.go", "main.go"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (>=1 path ignored); stderr = %s", code, errOut.String())
	}
	var results []checkIgnoreResult
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	if len(results) != 2 {
		t.Fatalf("results = %#v, want 2 entries", results)
	}
	if !results[0].Ignored || results[0].Source != "config" || results[0].Pattern != "ignored/**" {
		t.Fatalf("results[0] = %#v, want ignored config ignored/**", results[0])
	}
	if results[1].Ignored || results[1].Source != "" {
		t.Fatalf("results[1] = %#v, want main.go not ignored", results[1])
	}
}

// TestCheckIgnoreExitCodesMirrorGit checks the git check-ignore exit-code
// contract: 1 when no path is ignored, 2 on a usage error (no paths).
func TestCheckIgnoreExitCodesMirrorGit(t *testing.T) {
	root := t.TempDir()
	writeIgnoreConfig(t, root)
	writeFile(t, root, "main.go", "package main\n")
	t.Chdir(root)

	var noneOut, noneErr bytes.Buffer
	if code := Main([]string{"check-ignore", "main.go"}, &noneOut, &noneErr); code != 1 {
		t.Fatalf("no-ignored exit = %d, want 1; stdout = %q", code, noneOut.String())
	}
	if noneOut.String() != "" {
		t.Fatalf("text mode printed a non-ignored path: %q", noneOut.String())
	}

	var errStdout, errStderr bytes.Buffer
	if code := Main([]string{"check-ignore"}, &errStdout, &errStderr); code != 2 {
		t.Fatalf("no-args exit = %d, want 2", code)
	}
}

// TestCheckIgnoreTextListsOnlyIgnored checks the text format mirrors git
// check-ignore: only ignored paths print, one per line.
func TestCheckIgnoreTextListsOnlyIgnored(t *testing.T) {
	root := t.TempDir()
	writeIgnoreConfig(t, root)
	writeFile(t, root, "ignored/bad.go", "package ignored\n")
	writeFile(t, root, "main.go", "package main\n")
	t.Chdir(root)

	var out, errOut bytes.Buffer
	if code := Main([]string{"check-ignore", "ignored/bad.go", "main.go"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr = %s", code, errOut.String())
	}
	if got := out.String(); got != "ignored/bad.go\n" {
		t.Fatalf("text output = %q, want just the ignored path", got)
	}
}

// TestCheckIgnoreSharesEngineWithAnalyse proves check-ignore and analyse agree:
// for the same config, every path check-ignore calls ignored is absent from the
// analyse scanned set, and the matched pattern is identical. This guards the
// single-source-of-truth requirement at the command boundary.
func TestCheckIgnoreSharesEngineWithAnalyse(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gruff-go.yaml", "schemaVersion: gruff-go.config.v0.1\npaths:\n  ignore:\n    - \"*_stub.go\"\n")
	writeFile(t, root, "bad_stub.go", "package main\n")
	writeFile(t, root, "main.go", "package main\n")
	t.Chdir(root)

	var ciOut bytes.Buffer
	if code := Main([]string{"check-ignore", "--format", "json", "bad_stub.go", "main.go"}, &ciOut, &bytes.Buffer{}); code != 0 {
		t.Fatalf("check-ignore exit = %d", code)
	}
	var results []checkIgnoreResult
	if err := json.Unmarshal(ciOut.Bytes(), &results); err != nil {
		t.Fatal(err)
	}

	var anOut bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "--fail-on", "none", "."}, &anOut, &bytes.Buffer{}); code != 0 {
		t.Fatalf("analyse exit = %d", code)
	}
	var report struct {
		Paths struct {
			Details []struct {
				Path    string `json:"path"`
				Source  string `json:"source"`
				Pattern string `json:"pattern"`
			} `json:"details"`
			Extensions struct {
				Go struct {
					Paths struct {
						Scanned []string `json:"scanned"`
					} `json:"paths"`
				} `json:"go"`
			} `json:"extensions"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(anOut.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	scanned := map[string]bool{}
	for _, p := range report.Paths.Extensions.Go.Paths.Scanned {
		scanned[p] = true
	}
	skipPattern := map[string]string{}
	for _, s := range report.Paths.Details {
		if s.Source == "config" {
			skipPattern[s.Path] = s.Pattern
		}
	}
	for _, r := range results {
		if r.Ignored {
			if scanned[r.Path] {
				t.Fatalf("check-ignore says %s ignored but analyse scanned it", r.Path)
			}
			if r.Source == "config" && skipPattern[r.Path] != r.Pattern {
				t.Fatalf("pattern mismatch for %s: check-ignore %q vs analyse %q", r.Path, r.Pattern, skipPattern[r.Path])
			}
		} else if !scanned[r.Path] {
			t.Fatalf("check-ignore says %s not ignored but analyse did not scan it", r.Path)
		}
	}
}

// TestCheckIgnoreDirectoryPatternFormsAgreeWithAnalyse proves the documented
// trailing-slash shorthand and trailing recursive suffix agree at the CLI
// boundary for both directory walks and explicit-file analysis.
func TestCheckIgnoreDirectoryPatternFormsAgreeWithAnalyse(t *testing.T) {
	for _, pattern := range []string{"ignored/", "ignored/**"} {
		t.Run(pattern, func(t *testing.T) {
			root := t.TempDir()
			config := "schemaVersion: gruff-go.config.v0.1\npaths:\n  ignore:\n    - 'other/**'\n    - '" + pattern + "'\n    - 'later/*.go'\n"
			writeFile(t, root, ".gruff-go.yaml", config)
			writeFile(t, root, "ignored/nested/bad.go", "package ignored\n")
			writeFile(t, root, "main.go", "package main\n")
			t.Chdir(root)

			var checkOut, checkErr bytes.Buffer
			code := Main([]string{"check-ignore", "--format", "json", "ignored/nested/bad.go"}, &checkOut, &checkErr)
			if code != 0 {
				t.Fatalf("check-ignore exit = %d, want 0; stderr = %s", code, checkErr.String())
			}
			var results []checkIgnoreResult
			if err := json.Unmarshal(checkOut.Bytes(), &results); err != nil {
				t.Fatalf("invalid check-ignore JSON: %v\n%s", err, checkOut.String())
			}
			if len(results) != 1 || !results[0].Ignored || results[0].Source != "config" || results[0].Pattern != pattern {
				t.Fatalf("check-ignore pattern %q results = %#v, want one config match naming %q", pattern, results, pattern)
			}

			assertAnalyseConfigSkip(t, []string{"ignored/nested/bad.go"}, "ignored/nested/bad.go", pattern, 2)
			assertAnalyseConfigSkip(t, []string{"."}, "ignored", pattern, 0)
		})
	}
}

// assertAnalyseConfigSkip runs an analysis shape and verifies the named path
// is excluded by the expected verbatim config pattern.
func assertAnalyseConfigSkip(t *testing.T, inputs []string, skippedPath, pattern string, wantExit int) {
	t.Helper()
	args := append([]string{"analyse", "--format", "json", "--fail-on", "none"}, inputs...)
	var out, errOut bytes.Buffer
	if code := Main(args, &out, &errOut); code != wantExit {
		t.Fatalf("analyse %v exit = %d, want %d; stderr = %s", inputs, code, wantExit, errOut.String())
	}
	var report struct {
		Paths struct {
			Details []struct {
				Path    string `json:"path"`
				Source  string `json:"source"`
				Pattern string `json:"pattern"`
			} `json:"details"`
			Extensions struct {
				Go struct {
					Paths struct {
						Scanned []string `json:"scanned"`
					} `json:"paths"`
				} `json:"go"`
			} `json:"extensions"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("invalid analyse JSON: %v\n%s", err, out.String())
	}
	for _, scanned := range report.Paths.Extensions.Go.Paths.Scanned {
		if scanned == skippedPath {
			t.Fatalf("analyse %v scanned %q despite pattern %q", inputs, skippedPath, pattern)
		}
	}
	for _, skipped := range report.Paths.Details {
		if skipped.Path == skippedPath {
			if skipped.Source != "config" || skipped.Pattern != pattern {
				t.Fatalf("analyse %v skip = %#v, want source=config pattern=%q", inputs, skipped, pattern)
			}
			return
		}
	}
	t.Fatalf("analyse %v skips = %#v, want %q from pattern %q", inputs, report.Paths.Details, skippedPath, pattern)
}
