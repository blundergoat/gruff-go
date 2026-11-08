// Package diff computes changed-line filters from git diffs.
//
// It powers the changed-lines-only scan mode used by CI integrations, built from a git base, a diff mode or explicit --changed-ranges.
// Filter keeps findings on changed lines or wholly changed files, plus unlocated findings in any listed file, and counts the rest as filtered.
package diff

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// ChangedLines describes the set of lines per file altered relative to a git base, a diff mode or explicit ranges.
//
// Filter, FileChanged and RangeChanged consult it to decide what counts as changed in a changed-lines scan.
// A file in WholeFiles matches every finding in it; a file in LinesByFile matches findings on its listed lines or with no line.
type ChangedLines struct {
	// Base labels the comparison source, such as a Git revision, a diff mode like working-tree, a stdin patch or explicit ranges.
	Base string
	// LinesByFile maps file paths to the set of line numbers that changed; git input gives paths relative to the root git ran in.
	// A file with an empty set still counts for FileChanged and keeps findings that carry no line.
	LinesByFile map[string]map[int]struct{}
	// WholeFiles marks files where every current finding should be considered changed, such as new and untracked files.
	WholeFiles map[string]struct{}
	// ChangedFiles is the sorted union of file paths in LinesByFile and WholeFiles.
	ChangedFiles []string
}

// FilterResult is the outcome of filtering findings against a ChangedLines set.
//
// Every input finding lands either in Findings or in the FilteredFindings count, never both.
type FilterResult struct {
	// Findings holds the findings that overlap the changed-line set.
	Findings []finding.Finding
	// FilteredFindings is the count of findings dropped because they do not overlap the diff.
	FilteredFindings int
}

// hunkPattern matches the unified-diff hunk header used to recover added line ranges.
// It captures the new-side start and optional count, so @@ -4,2 +3,0 @@ yields start 3 and count 0.
var hunkPattern = regexp.MustCompile(`@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// patchParseState carries state while streaming a unified diff.
// currentFile stays empty until a +++ header names a destination, and newFile marks that destination as added by this diff.
type patchParseState struct {
	currentFile string
	newFile     bool
}

// FromGit runs git diff against base and returns the changed lines under paths, with file paths relative to root.
//
// ctx cancels the git subprocess so a hung git does not outlive an aborted scan.
// root is the directory git runs in, and with no paths the whole of root is diffed; a clean diff gives empty LinesByFile and WholeFiles maps.
// Untracked files are not included; FromMode adds them only for working-tree and base-revision modes.
//
// It fails when base is empty, when git exits non-zero, with git's trimmed stderr in the error, or when git cannot be started.
func FromGit(ctx context.Context, root string, base string, paths []string) (ChangedLines, error) {
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
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		// A missing repository or an unknown base, such as a mistyped branch, stops the changed-lines scan; the error carries git's message.
		if exitErr, ok := err.(*exec.ExitError); ok {
			return ChangedLines{}, fmt.Errorf("git diff failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		// If git is not installed or root does not exist, this startup error stops the changed-lines scan.
		return ChangedLines{}, err
	}
	return Parse(base, output), nil
}

// FromMode resolves gruff's CLI diff modes into changed-line data, and ctx cancels the git subprocesses it spawns.
//
// An empty mode or working-tree merges staged and unstaged diffs, staged or unstaged gives only that diff, and other modes name a base revision.
// Untracked files under paths, or all of root when paths is empty, join the working-tree and base-revision results as wholly changed.
//
// It returns ChangedLines whose Base is mode, or working-tree when mode is empty. It fails with the first error from a git command run in root.
func FromMode(ctx context.Context, root string, mode string, paths []string) (ChangedLines, error) {
	switch mode {
	case "", "working-tree":
		staged, err := gitDiff(ctx, root, "working-tree", []string{"diff", "--cached", "--unified=0", "--no-ext-diff", "--relative", "--"}, paths)
		if err != nil {
			return ChangedLines{}, err
		}
		unstaged, err := gitDiff(ctx, root, "working-tree", []string{"diff", "--unified=0", "--no-ext-diff", "--relative", "--"}, paths)
		if err != nil {
			return ChangedLines{}, err
		}
		untracked, err := untrackedFiles(ctx, root, paths)
		if err != nil {
			return ChangedLines{}, err
		}
		return Merge("working-tree", staged, unstaged, WholeFiles("working-tree", untracked)), nil
	case "staged":
		return gitDiff(ctx, root, mode, []string{"diff", "--cached", "--unified=0", "--no-ext-diff", "--relative", "--"}, paths)
	case "unstaged":
		return gitDiff(ctx, root, mode, []string{"diff", "--unified=0", "--no-ext-diff", "--relative", "--"}, paths)
	default:
		// Any other mode is taken as a revision, so a mistyped mode such as stagd reaches git as a revision name and fails there.
		revisionLines, err := FromGit(ctx, root, mode, paths)
		if err != nil {
			return ChangedLines{}, err
		}
		untracked, err := untrackedFiles(ctx, root, paths)
		if err != nil {
			return ChangedLines{}, err
		}
		return Merge(mode, revisionLines, WholeFiles(mode, untracked)), nil
	}
}

// ExplicitRanges applies one --changed-ranges string, such as 3-3,8-10, to every already-discovered path.
//
// It returns ChangedLines with base as Base and each of files mapped to its own copy of the parsed line set; WholeFiles stays empty.
// It fails with the parseRangeSet error when ranges is malformed or covers no line. With no files, LinesByFile stays empty.
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
//
// It returns ChangedLines with base as Base and every path in files, slash-normalised, marked in WholeFiles; LinesByFile stays empty.
// With no files, both maps and ChangedFiles are empty.
func WholeFiles(base string, files []string) ChangedLines {
	changed := ChangedLines{Base: base, LinesByFile: map[string]map[int]struct{}{}, WholeFiles: map[string]struct{}{}}
	for _, file := range files {
		changed.WholeFiles[filepath.ToSlash(file)] = struct{}{}
	}
	changed.refreshChangedFiles()
	return changed
}

// Merge combines multiple changed-line sets while preserving whole-file scope.
//
// It returns a new ChangedLines with base as Base holding the union of sets; a file whole in any set stays whole and drops its line hunks.
// With no sets, both maps and ChangedFiles are empty.
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
//
// It returns ChangedLines with base as Base: new files are marked whole, and other files collect their added-side hunk lines.
// A pure-deletion hunk records its anchor line instead. Deleted files are skipped, and an empty patch gives empty maps.
func Parse(base string, patch []byte) ChangedLines {
	result := ChangedLines{
		Base:        base,
		LinesByFile: map[string]map[int]struct{}{},
		WholeFiles:  map[string]struct{}{},
	}
	state := patchParseState{}
	for _, raw := range bytes.Split(patch, []byte("\n")) {
		parsePatchLine(&result, &state, string(raw))
	}
	result.refreshChangedFiles()
	return result
}

// parsePatchLine updates result and state from one unified-diff line.
// A diff --git header resets state, a new-file header marks the next file as added, +++ names it and @@ records hunk lines for it.
func parsePatchLine(result *ChangedLines, state *patchParseState, line string) {
	switch {
	case strings.HasPrefix(line, "diff --git "):
		state.currentFile = ""
		state.newFile = false
	// A file added by this diff is marked whole, so every finding in it survives the changed-lines filter.
	case strings.HasPrefix(line, "new file mode ") || line == "--- /dev/null":
		state.newFile = true
	case strings.HasPrefix(line, "+++ "):
		state.currentFile = parseNewFile(line)
		markParsedFile(result, state.currentFile, state.newFile)
	case state.currentFile != "" && strings.HasPrefix(line, "@@ "):
		addHunkLines(result, state.currentFile, line)
	}
}

// markParsedFile records whether a parsed destination file should be tracked by line hunks or treated as wholly changed.
// When newFile is true, file joins the WholeFiles of result, else result gets an empty LinesByFile entry if absent; an empty file name is ignored.
func markParsedFile(result *ChangedLines, file string, newFile bool) {
	if file == "" {
		return
	}
	if newFile {
		result.WholeFiles[file] = struct{}{}
		return
	}
	if _, ok := result.LinesByFile[file]; !ok {
		result.LinesByFile[file] = map[int]struct{}{}
	}
}

// addHunkLines records the added-side line range from a unified-diff hunk.
//
// line is the hunk header; its added-side lines go into the LinesByFile entry for file in result, and a file already marked whole is skipped.
// A pure-deletion hunk records its new-side start, using line 1 when that start is 0.
// A header that does not match hunkPattern changes nothing.
func addHunkLines(result *ChangedLines, file string, line string) {
	if _, whole := result.WholeFiles[file]; whole {
		return
	}
	matches := hunkPattern.FindStringSubmatch(line)
	if len(matches) == 0 {
		return
	}
	start, _ := strconv.Atoi(matches[1])
	count := 1
	if matches[2] != "" {
		count, _ = strconv.Atoi(matches[2])
	}
	if count == 0 {
		// A pure-deletion hunk such as @@ -4,2 +3,0 @@ has no added side; its new-side start names the line just before the removed block.
		//
		// Anchoring that line keeps any finding whose reported range covers it, such as one spanning the edited function.
		// Without it, a removal-only edit records no changed line, and a --diff or --since scan silently drops findings in the edited function.
		anchor := start
		// Removing the first lines of a file gives a new-side start of 0, so line 1 stands in.
		if anchor < 1 {
			anchor = 1
		}
		result.LinesByFile[file][anchor] = struct{}{}
		return
	}
	for offset := 0; offset < count; offset++ {
		result.LinesByFile[file][start+offset] = struct{}{}
	}
}

// Filter keeps findings overlapping changed, including all findings in wholly changed files and unlocated findings in any listed file.
// A nil Location or line 0 counts as unlocated, and an empty changed-line set for the file still retains such findings.
//
// It returns a FilterResult with the kept findings in input order and the dropped count in FilteredFindings, zero when every finding overlaps.
// When nothing overlaps, Findings is an empty, non-nil slice.
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
//
// item matches when changed marks its file whole, or lists the file and either item has no line or a line from Line to EndLine is changed.
// An EndLine of zero or below Line counts as Line, and a file absent from both maps reports false.
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
// changed is the set to consult; a file listed in LinesByFile counts even when its line set is empty.
func FileChanged(changed ChangedLines, file string) bool {
	if _, ok := changed.WholeFiles[file]; ok {
		return true
	}
	_, ok := changed.LinesByFile[file]
	return ok
}

// RangeChanged reports whether lines start through end of file overlap the changed set.
// A file in WholeFiles always reports true; an end of zero or below start checks start alone, and a file absent from changed reports false.
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
// It returns line without its +++ marker and surrounding space, minus a leading b/ prefix, or an empty string when the path is /dev/null.
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

// gitDiff runs git with the prepared diff args in root, scoped to paths or the whole tree, and parses stdout into ChangedLines.
//
// ctx cancels the git subprocess so a hung git does not outlive an aborted scan.
// It returns the ChangedLines parsed from git's stdout, with base only as its Base label and never passed to git; empty output gives empty maps.
//
// It fails with an error holding git's trimmed stderr when git exits non-zero, so the caller can report why the diff could not be computed.
// It also fails with the exec error when git cannot be started.
func gitDiff(ctx context.Context, root string, base string, args []string, paths []string) (ChangedLines, error) {
	if len(paths) == 0 {
		args = append(args, ".")
	} else {
		args = append(args, paths...)
	}
	// #nosec G204 -- arguments are passed directly to git without shell expansion.
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		// Running gruff-go outside a git repository makes git exit non-zero and lands here, and the error carries git's own message.
		if exitErr, ok := err.(*exec.ExitError); ok {
			return ChangedLines{}, fmt.Errorf("git diff failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return ChangedLines{}, err
	}
	return Parse(base, output), nil
}

// untrackedFiles lists untracked, non-ignored files so FromMode can treat brand-new files as wholly changed rather than miss them.
//
// ctx cancels the lookup, which runs git ls-files --others --exclude-standard, so ignored untracked files are left out of its result.
// It returns the slash-separated paths git ls-files prints when run in root, limited to paths or the whole of root when paths is empty.
//
// With no untracked files the slice is empty, not nil.
// It fails with an error holding git's trimmed stderr when git exits non-zero, or with the exec error when git cannot be started.
func untrackedFiles(ctx context.Context, root string, paths []string) ([]string, error) {
	args := []string{"ls-files", "--others", "--exclude-standard", "--"}
	if len(paths) == 0 {
		args = append(args, ".")
	} else {
		args = append(args, paths...)
	}
	// #nosec G204 -- arguments are passed directly to git without shell expansion.
	command := exec.CommandContext(ctx, "git", args...)
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

// parseRangeSet parses a --changed-ranges string such as 3-3,8-10 into the set of 1-based line numbers it covers.
//
// Malformed or empty input fails loudly instead of silently scanning nothing.
// raw lists single lines or start-end pairs separated by commas, with blank entries skipped; it returns the non-empty set of covered lines.
//
// It fails with a nil set when an entry has more than one dash, a non-integer or sub-1 start, or a non-integer end or one below its start.
// It also fails when raw holds no entry at all.
func parseRangeSet(raw string) (map[int]struct{}, error) {
	out := map[int]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		bounds := strings.Split(trimmed, "-")
		// A stray dash, as in 3--5, lands here, and the error names the entry.
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid --changed-ranges entry: %s", trimmed)
		}
		start, err := strconv.Atoi(bounds[0])
		// Line numbers start at 1, so an entry such as 0-5 or a typo like a-5 fails here.
		if err != nil || start < 1 {
			return nil, fmt.Errorf("invalid --changed-ranges entry: %s", trimmed)
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.Atoi(bounds[1])
			// A reversed range such as 10-8 fails here instead of silently covering no lines.
			if err != nil || end < start {
				return nil, fmt.Errorf("invalid --changed-ranges entry: %s", trimmed)
			}
		}
		for line := start; line <= end; line++ {
			out[line] = struct{}{}
		}
	}
	// A value made only of commas or spaces selects no lines, so it is rejected with an error.
	if len(out) == 0 {
		return nil, fmt.Errorf("--changed-ranges must include at least one range")
	}
	return out, nil
}

// copyLineSet returns an independent copy of a line set so a caller can store or mutate it without aliasing the source map.
// lines is that source; a nil or empty lines gives an empty, non-nil map.
func copyLineSet(lines map[int]struct{}) map[int]struct{} {
	out := map[int]struct{}{}
	for line := range lines {
		out[line] = struct{}{}
	}
	return out
}

// refreshChangedFiles rebuilds ChangedFiles as the sorted, deduplicated union of the LinesByFile and WholeFiles keys.
// Every constructor in this file calls it last, so ChangedFiles stays consistent after the line maps are filled.
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
