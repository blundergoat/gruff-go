// Package diff computes changed-line filters from git diffs.
// It powers the changed-lines-only scan mode used by CI integrations.
package diff

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// ChangedLines describes the set of lines per file altered relative to a git base.
type ChangedLines struct {
	// Base is the git revision the diff was computed against.
	Base string
	// LinesByFile maps repo-relative file paths to the set of line numbers that changed.
	LinesByFile map[string]map[int]struct{}
	// ChangedFiles is the sorted list of files present in LinesByFile.
	ChangedFiles []string
}

// FilterResult is the outcome of filtering findings against a ChangedLines set.
type FilterResult struct {
	// Findings holds the findings that overlap the changed-line set.
	Findings []finding.Finding
	// FilteredFindings is the count of findings dropped because they do not overlap the diff.
	FilteredFindings int
}

// hunkPattern matches the unified-diff hunk header used to recover added line ranges.
var hunkPattern = regexp.MustCompile(`@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// FromGit runs `git diff` against base and returns the changed lines under paths.
func FromGit(root string, base string, paths []string) (ChangedLines, error) {
	if base == "" {
		return ChangedLines{}, fmt.Errorf("diff base must not be empty")
	}
	args := []string{"diff", "--unified=0", "--no-ext-diff", "--relative", base, "--"}
	if len(paths) == 0 {
		args = append(args, ".")
	} else {
		args = append(args, paths...)
	}
	// #nosec G204 -- arguments are passed directly to git without shell expansion.
	command := exec.Command("git", args...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return ChangedLines{}, fmt.Errorf("git diff failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return ChangedLines{}, err
	}
	return Parse(base, output), nil
}

// Parse converts a unified-diff patch into a ChangedLines map keyed by file path.
func Parse(base string, patch []byte) ChangedLines {
	result := ChangedLines{
		Base:        base,
		LinesByFile: map[string]map[int]struct{}{},
	}
	var currentFile string
	for _, raw := range bytes.Split(patch, []byte("\n")) {
		line := string(raw)
		if strings.HasPrefix(line, "+++ ") {
			currentFile = parseNewFile(line)
			if currentFile != "" {
				if _, ok := result.LinesByFile[currentFile]; !ok {
					result.LinesByFile[currentFile] = map[int]struct{}{}
				}
			}
			continue
		}
		if currentFile == "" || !strings.HasPrefix(line, "@@ ") {
			continue
		}
		matches := hunkPattern.FindStringSubmatch(line)
		if len(matches) == 0 {
			continue
		}
		start, _ := strconv.Atoi(matches[1])
		count := 1
		if matches[2] != "" {
			count, _ = strconv.Atoi(matches[2])
		}
		for offset := 0; offset < count; offset++ {
			result.LinesByFile[currentFile][start+offset] = struct{}{}
		}
	}
	for file := range result.LinesByFile {
		result.ChangedFiles = append(result.ChangedFiles, file)
	}
	slices.Sort(result.ChangedFiles)
	return result
}

// Filter keeps findings whose file and line ranges overlap the changed set.
func Filter(findings []finding.Finding, changed ChangedLines) FilterResult {
	kept := make([]finding.Finding, 0, len(findings))
	filtered := 0
	for _, item := range findings {
		if matchesFinding(item, changed) {
			kept = append(kept, item)
			continue
		}
		filtered++
	}
	return FilterResult{Findings: kept, FilteredFindings: filtered}
}

// matchesFinding reports whether a finding overlaps the changed-line set.
func matchesFinding(item finding.Finding, changed ChangedLines) bool {
	lines, ok := changed.LinesByFile[item.File]
	if !ok {
		return false
	}
	if item.Location == nil || item.Location.Line == 0 {
		return true
	}
	start := item.Location.Line
	end := item.Location.EndLine
	if end == 0 || end < start {
		end = start
	}
	for line := start; line <= end; line++ {
		if _, ok := lines[line]; ok {
			return true
		}
	}
	return false
}

// parseNewFile extracts the destination file path from a unified diff header.
func parseNewFile(line string) string {
	path := strings.TrimSpace(strings.TrimPrefix(line, "+++ "))
	if path == "/dev/null" {
		return ""
	}
	if strings.HasPrefix(path, "b/") {
		return strings.TrimPrefix(path, "b/")
	}
	return path
}
