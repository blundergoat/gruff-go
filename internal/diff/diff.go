// Package diff computes changed-line filters from git diffs.
// It powers the changed-lines-only scan mode used by CI integrations.
package diff

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
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
	// WholeFiles marks files where every current finding should be considered changed.
	WholeFiles map[string]struct{}
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

// FromMode resolves gruff's CLI diff modes into changed-line data.
func FromMode(root string, mode string, paths []string) (ChangedLines, error) {
	switch mode {
	case "", "working-tree":
		staged, err := gitDiff(root, "working-tree", []string{"diff", "--cached", "--unified=0", "--no-ext-diff", "--relative", "--"}, paths)
		if err != nil {
			return ChangedLines{}, err
		}
		unstaged, err := gitDiff(root, "working-tree", []string{"diff", "--unified=0", "--no-ext-diff", "--relative", "--"}, paths)
		if err != nil {
			return ChangedLines{}, err
		}
		untracked, err := untrackedFiles(root, paths)
		if err != nil {
			return ChangedLines{}, err
		}
		return Merge("working-tree", staged, unstaged, WholeFiles("working-tree", untracked)), nil
	case "staged":
		return gitDiff(root, mode, []string{"diff", "--cached", "--unified=0", "--no-ext-diff", "--relative", "--"}, paths)
	case "unstaged":
		return gitDiff(root, mode, []string{"diff", "--unified=0", "--no-ext-diff", "--relative", "--"}, paths)
	default:
		base, err := FromGit(root, mode, paths)
		if err != nil {
			return ChangedLines{}, err
		}
		untracked, err := untrackedFiles(root, paths)
		if err != nil {
			return ChangedLines{}, err
		}
		return Merge(mode, base, WholeFiles(mode, untracked)), nil
	}
}

// ExplicitRanges applies one ranges string to every already-discovered path.
func ExplicitRanges(base string, ranges string, files []string) (ChangedLines, error) {
	lineSet, err := parseRangeSet(ranges)
	if err != nil {
		return ChangedLines{}, err
	}
	changed := ChangedLines{Base: base, LinesByFile: map[string]map[int]struct{}{}, WholeFiles: map[string]struct{}{}}
	for _, file := range files {
		changed.LinesByFile[file] = copyLineSet(lineSet)
	}
	changed.refreshChangedFiles()
	return changed, nil
}

// WholeFiles creates a changed set where every finding in each file is in scope.
func WholeFiles(base string, files []string) ChangedLines {
	changed := ChangedLines{Base: base, LinesByFile: map[string]map[int]struct{}{}, WholeFiles: map[string]struct{}{}}
	for _, file := range files {
		changed.WholeFiles[filepath.ToSlash(file)] = struct{}{}
	}
	changed.refreshChangedFiles()
	return changed
}

// Merge combines multiple changed-line sets while preserving whole-file scope.
func Merge(base string, sets ...ChangedLines) ChangedLines {
	merged := ChangedLines{Base: base, LinesByFile: map[string]map[int]struct{}{}, WholeFiles: map[string]struct{}{}}
	for _, set := range sets {
		for file := range set.WholeFiles {
			merged.WholeFiles[file] = struct{}{}
			delete(merged.LinesByFile, file)
		}
		for file, lines := range set.LinesByFile {
			if _, whole := merged.WholeFiles[file]; whole {
				continue
			}
			if _, ok := merged.LinesByFile[file]; !ok {
				merged.LinesByFile[file] = map[int]struct{}{}
			}
			for line := range lines {
				merged.LinesByFile[file][line] = struct{}{}
			}
		}
	}
	merged.refreshChangedFiles()
	return merged
}

// Parse converts a unified-diff patch into a ChangedLines map keyed by file path.
func Parse(base string, patch []byte) ChangedLines {
	result := ChangedLines{
		Base:        base,
		LinesByFile: map[string]map[int]struct{}{},
		WholeFiles:  map[string]struct{}{},
	}
	var currentFile string
	newFile := false
	for _, raw := range bytes.Split(patch, []byte("\n")) {
		line := string(raw)
		if strings.HasPrefix(line, "diff --git ") {
			currentFile = ""
			newFile = false
			continue
		}
		if strings.HasPrefix(line, "new file mode ") || line == "--- /dev/null" {
			newFile = true
			continue
		}
		if strings.HasPrefix(line, "+++ ") {
			currentFile = parseNewFile(line)
			if currentFile != "" {
				if newFile {
					result.WholeFiles[currentFile] = struct{}{}
				} else if _, ok := result.LinesByFile[currentFile]; !ok {
					result.LinesByFile[currentFile] = map[int]struct{}{}
				}
			}
			continue
		}
		if currentFile == "" || !strings.HasPrefix(line, "@@ ") {
			continue
		}
		if _, whole := result.WholeFiles[currentFile]; whole {
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
	for file := range result.WholeFiles {
		if _, ok := result.LinesByFile[file]; !ok {
			result.ChangedFiles = append(result.ChangedFiles, file)
		}
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
	if _, ok := changed.WholeFiles[item.File]; ok {
		return true
	}
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

// FileChanged reports whether any hunk or whole-file marker exists for file.
func FileChanged(changed ChangedLines, file string) bool {
	if _, ok := changed.WholeFiles[file]; ok {
		return true
	}
	_, ok := changed.LinesByFile[file]
	return ok
}

// RangeChanged reports whether [start,end] overlaps the changed set for file.
func RangeChanged(changed ChangedLines, file string, start int, end int) bool {
	if _, ok := changed.WholeFiles[file]; ok {
		return true
	}
	lines, ok := changed.LinesByFile[file]
	if !ok {
		return false
	}
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

func gitDiff(root string, base string, args []string, paths []string) (ChangedLines, error) {
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

func untrackedFiles(root string, paths []string) ([]string, error) {
	args := []string{"ls-files", "--others", "--exclude-standard", "--"}
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
			return nil, fmt.Errorf("git ls-files failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, err
	}
	files := []string{}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) != "" {
			files = append(files, filepath.ToSlash(line))
		}
	}
	return files, nil
}

func parseRangeSet(raw string) (map[int]struct{}, error) {
	out := map[int]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		bounds := strings.Split(trimmed, "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid --changed-ranges entry: %s", trimmed)
		}
		start, err := strconv.Atoi(bounds[0])
		if err != nil || start < 1 {
			return nil, fmt.Errorf("invalid --changed-ranges entry: %s", trimmed)
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.Atoi(bounds[1])
			if err != nil || end < start {
				return nil, fmt.Errorf("invalid --changed-ranges entry: %s", trimmed)
			}
		}
		for line := start; line <= end; line++ {
			out[line] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--changed-ranges must include at least one range")
	}
	return out, nil
}

func copyLineSet(lines map[int]struct{}) map[int]struct{} {
	out := map[int]struct{}{}
	for line := range lines {
		out[line] = struct{}{}
	}
	return out
}

func (changed *ChangedLines) refreshChangedFiles() {
	seen := map[string]struct{}{}
	changed.ChangedFiles = changed.ChangedFiles[:0]
	for file := range changed.LinesByFile {
		seen[file] = struct{}{}
	}
	for file := range changed.WholeFiles {
		seen[file] = struct{}{}
	}
	for file := range seen {
		changed.ChangedFiles = append(changed.ChangedFiles, file)
	}
	slices.Sort(changed.ChangedFiles)
}
