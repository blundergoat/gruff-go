// Package cli tests check-ignore's path decisions, the config pattern it reports, and its agreement with analyse on these fixtures.
//
//   - The verdict and the matched pattern are correct.
//   - The JSON output keeps the agent contract.
//   - Exit 0 and 1 follow git check-ignore; gruff-go uses 2 for usage errors.
//   - The command shares the analyse ignore engine rather than reimplementing matching.
package cli

import (
	"bytes"
	"encoding/json"
	"testing"
)

// writeIgnoreConfig writes the shared check-ignore fixture, a .gruff-go.yaml whose paths.ignore skips the ignored/ subtree.
//
// The file is written into root, so callers pass the project directory they later change into.
func writeIgnoreConfig(t *testing.T, root string) {
	t.Helper()
	writeFile(t, root, ".gruff-go.yaml", "schemaVersion: gruff-go.config.v0.1\npaths:\n  ignore:\n    - \"ignored/**\"\n")
}

// TestCheckIgnoreJSONReportsVerdictAndPattern checks the check-ignore JSON contract that agents read.
//
// An ignored path reports source config and the pattern that matched; a non-ignored path reports ignored false with no source.
// Exit 0 signals that at least one path was ignored, as with git check-ignore.
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

// TestCheckIgnoreExitCodesMirrorGit checks that check-ignore exits 1 when no path is ignored, as git does, and 2 when no paths are supplied.
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

// TestCheckIgnoreTextListsOnlyIgnored checks the text format mirrors git check-ignore: only ignored paths print, one per line.
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

// TestCheckIgnoreSharesEngineWithAnalyse proves check-ignore and analyse agree for the same config.
//
// Every path check-ignore calls ignored must be missing from the analyse scanned set, with the same config pattern in the path details.
// Every path it calls not ignored must be scanned; a failure means the two commands match paths differently.
func TestCheckIgnoreSharesEngineWithAnalyse(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gruff-go.yaml", "schemaVersion: gruff-go.config.v0.1\npaths:\n  ignore:\n    - \"*_stub.go\"\n")
	writeFile(t, root, "bad_stub.go", "package main\n")
	writeFile(t, root, "main.go", "package main\n")
	t.Chdir(root)

	var checkIgnoreOut bytes.Buffer
	if code := Main([]string{"check-ignore", "--format", "json", "bad_stub.go", "main.go"}, &checkIgnoreOut, &bytes.Buffer{}); code != 0 {
		t.Fatalf("check-ignore exit = %d", code)
	}
	var results []checkIgnoreResult
	if err := json.Unmarshal(checkIgnoreOut.Bytes(), &results); err != nil {
		t.Fatal(err)
	}

	var analyseOut bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "--fail-on", "none", "."}, &analyseOut, &bytes.Buffer{}); code != 0 {
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
	if err := json.Unmarshal(analyseOut.Bytes(), &report); err != nil {
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

// TestCheckIgnoreDirectoryPatternFormsAgreeWithAnalyse proves the documented ignored/ and ignored/** pattern forms skip the same file.
//
// The trailing-slash shorthand and the trailing recursive suffix must agree at the CLI boundary.
// Each form is checked through check-ignore, an explicit-file analyse run and a directory walk from the project root.
func TestCheckIgnoreDirectoryPatternFormsAgreeWithAnalyse(t *testing.T) {
	for _, pattern := range []string{"ignored/", "ignored/**"} {
		t.Run(pattern, func(t *testing.T) {
			root := t.TempDir()
			// The decoy patterns before and after the one under test prove the reported pattern is the one that matched, not the first or last listed.
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

			// Naming only the ignored file must exit 2 and still record the skip under the file's own path.
			// Walking the project root must exit 0 and record the skip on the ignored directory.
			assertAnalyseConfigSkip(t, []string{"ignored/nested/bad.go"}, "ignored/nested/bad.go", pattern, 2)
			assertAnalyseConfigSkip(t, []string{"."}, "ignored", pattern, 0)
		})
	}
}

// assertAnalyseConfigSkip runs analyse over one input shape and checks that skippedPath was skipped by exactly the given config pattern.
//
// It runs analyse in JSON with --fail-on none over inputs and fails the test unless the exit code equals wantExit.
// skippedPath must be absent from the scanned paths and must appear in the path details with source config and exactly pattern.
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
	// Reaching here means analyse did not scan skippedPath but listed no skip for it either, or listed the skip under another path.
	t.Fatalf("analyse %v skips = %#v, want %q from pattern %q", inputs, report.Paths.Details, skippedPath, pattern)
}
