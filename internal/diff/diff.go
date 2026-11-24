// Package diff computes changed-line filters from git diffs.
//
// It powers the changed-lines-only scan mode used by CI integrations, built from a git base, a diff mode or explicit --changed-ranges.
// Filter keeps findings on changed lines or wholly changed files, plus unlocated findings in any listed file, and counts the rest as filtered.
package diff

import (
	"bytes"
	"context"
	"fmt"
	"math"
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

// hunkPattern matches the unified-diff hunk header used to recover old and new line ranges.
// It captures optional old count, new-side start, and optional new count, so @@ -4,2 +3,0 @@ yields oldCount=2, start=3, newCount=0.
var hunkPattern = regexp.MustCompile(`@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// patchParseState carries state while streaming a unified diff, including active hunk line counters.
// Tracking hunk line counts keeps unchanged context lines out of ChangedLines and prevents added "++ " content from hijacking file headers.
type patchParseState struct {
	currentFile    string
	newFile        bool
	inHunk         bool
	oldRemaining   int
	newRemaining   int
	newLine        int
	hunkStart      int
	hunkNewCount   int
	hunkSawBody    bool
	hunkSawAdd     bool
	deletionAnchor int
}

// FromGit runs git diff against base and returns the changed lines under paths, with file paths relative to root.
//
// ctx cancels the git subprocess so a hung git does not outlive an aborted scan.
// base must be a non-empty revision that does not start with '-', preventing git option injection via flags such as --output=.
//
// root is the directory git runs in, and with no paths the whole of root is diffed; a clean diff gives empty LinesByFile and WholeFiles maps.
// Untracked files are not included; FromMode adds them only for working-tree and base-revision modes.
//
// It fails when base is empty or starts with '-', when git exits non-zero, with git's trimmed stderr in the error, or when git cannot be started.
func FromGit(ctx context.Context, root string, base string, paths []string) (ChangedLines, error) {
	if base == "" {
		return ChangedLines{}, fmt.Errorf("diff base must not be empty")
	}
	if strings.HasPrefix(base, "-") {
		return ChangedLines{}, fmt.Errorf("diff base %q must not start with '-'", base)
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
// An empty mode or working-tree diffs HEAD against the working tree when HEAD exists (so staged and unstaged edits share live disk line numbers),
// falling back to staged plus unstaged diffs in an unborn repository. Staged or unstaged gives only that diff, and other modes name a base revision.
// Untracked files under paths, or all of root when paths is empty, join the working-tree and base-revision results as wholly changed.
//
// It returns ChangedLines whose Base is mode, or working-tree when mode is empty. It fails with the first error from a git command run in root.
func FromMode(ctx context.Context, root string, mode string, paths []string) (ChangedLines, error) {
	switch mode {
	case "", "working-tree":
		untracked, err := untrackedFiles(ctx, root, paths)
		if err != nil {
			return ChangedLines{}, err
		}
		// When HEAD exists, diffing HEAD directly against the working tree keeps staged and unstaged line numbers aligned with files on disk.
		if gitHasHead(ctx, root) {
			working, err := gitDiff(ctx, root, "working-tree", []string{"diff", "HEAD", "--unified=0", "--no-ext-diff", "--relative", "--"}, paths)
			if err != nil {
				return ChangedLines{}, err
			}
			return Merge("working-tree", working, WholeFiles("working-tree", untracked)), nil
		}
		staged, err := gitDiff(ctx, root, "working-tree", []string{"diff", "--cached", "--unified=0", "--no-ext-diff", "--relative", "--"}, paths)
		if err != nil {
			return ChangedLines{}, err
		}
		unstaged, err := gitDiff(ctx, root, "working-tree", []string{"diff", "--unified=0", "--no-ext-diff", "--relative", "--"}, paths)
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
	// Strip a single trailing newline so EOF does not emit a phantom empty line into an active hunk.
	trimmedPatch := bytes.TrimSuffix(patch, []byte("\n"))
	for _, raw := range bytes.Split(trimmedPatch, []byte("\n")) {
		parsePatchLine(&result, &state, strings.TrimSuffix(string(raw), "\r"))
	}
	finishHunk(&result, &state)
	result.refreshChangedFiles()
	return result
}

// ParseStdin reads the patch a developer pipes to --diff=- and returns its changed lines without running Git.
//
// An empty patch means there is no change to check. Unrecognized input or a bad hunk header returns an error instead of an empty successful scan.
func ParseStdin(patch []byte) (ChangedLines, error) {
	// A clean git diff produces no bytes, so an empty pipe is a valid comparison.
	if len(bytes.TrimSpace(patch)) == 0 {
		return Parse("stdin", patch), nil
	}

	lines := bytes.Split(patch, []byte("\n"))
	hasChangeRecord, hasGitHeader, hasDestination := false, false, false
	previousLine := ""
	// A patch can contain several files, including metadata-only changes with no source lines for Gruff to check.
	for lineIndex, raw := range lines {
		line := strings.TrimSuffix(string(raw), "\r")
		switch {
		case strings.HasPrefix(line, "diff --git "):
			hasGitHeader, hasDestination = true, false
		case strings.HasPrefix(line, "+++ ") && strings.HasPrefix(previousLine, "--- "):
			hasDestination = strings.TrimSpace(line[4:]) != "" && strings.TrimSpace(previousLine[4:]) != ""
		case strings.HasPrefix(line, "@@"):
			// A truncated or unrelated input may contain a hunk marker with no usable file location.
			if !hasDestination || !validStdinHunk(line, len(lines)) {
				return ChangedLines{}, fmt.Errorf("stdin patch has an invalid hunk at line %d", lineIndex+1)
			}
			hasChangeRecord = true
		case hasGitHeader && isGitMetadataChange(line):
			hasChangeRecord = true
		}
		previousLine = line
	}
	// A log or compiler message accidentally piped in contains no recognizable patch record.
	if !hasChangeRecord {
		return ChangedLines{}, fmt.Errorf("stdin did not contain a unified diff")
	}
	return Parse("stdin", patch), nil
}

// validStdinHunk reports whether line gives a usable new-side range for --diff=-.
// The declared number of lines must fit within patchLineCount, so a bad header cannot expand beyond the supplied patch.
func validStdinHunk(line string, patchLineCount int) bool {
	bounds := hunkPattern.FindStringSubmatch(line)
	// A combined or truncated hunk uses a header this changed-line scan cannot interpret.
	if bounds == nil || !strings.HasPrefix(line, bounds[0]) {
		return false
	}
	start, startErr := strconv.Atoi(bounds[2])
	count := 1
	var countErr error
	// A user piping a one-line diff gets a header that usually omits the count.
	if bounds[3] != "" {
		count, countErr = strconv.Atoi(bounds[3])
	}
	return startErr == nil && countErr == nil && count <= patchLineCount && start <= math.MaxInt-count
}

// isGitMetadataChange reports whether line identifies a valid kind of Git change that can appear without text hunks.
// It lets an ordinary empty-file, rename, permission, or binary change produce an empty changed-line scope.
func isGitMetadataChange(line string) bool {
	return strings.HasPrefix(line, "new file mode ") || strings.HasPrefix(line, "deleted file mode ") ||
		strings.HasPrefix(line, "new mode ") || strings.HasPrefix(line, "rename to ") || strings.HasPrefix(line, "copy to ") ||
		strings.HasPrefix(line, "Binary files ") || line == "GIT binary patch"
}

// parsePatchLine updates result and state from one unified-diff line.
// While inside an active hunk body it consumes +, -, context, and no-newline lines so unchanged context and "++ " content cannot hijack headers.
func parsePatchLine(result *ChangedLines, state *patchParseState, line string) {
	if state.inHunk && (state.oldRemaining > 0 || state.newRemaining > 0) {
		if consumeHunkLine(result, state, line) {
			return
		}
		finishHunk(result, state)
	}
	switch {
	case strings.HasPrefix(line, "diff --git "):
		finishHunk(result, state)
		state.currentFile = ""
		state.newFile = false
	// A file added by this diff is marked whole, so every finding in it survives the changed-lines filter.
	case strings.HasPrefix(line, "new file mode "):
		state.newFile = true
	case strings.HasPrefix(line, "--- "):
		finishHunk(result, state)
		// Plain diff -u patches omit "diff --git " headers, so refresh newFile from each source header (stripping optional tab timestamps).
		sourcePath, _, _ := strings.Cut(strings.TrimPrefix(line, "--- "), "\t")
		state.newFile = strings.TrimSpace(sourcePath) == "/dev/null"
	case strings.HasPrefix(line, "+++ "):
		finishHunk(result, state)
		state.currentFile = parseNewFile(line)
		markParsedFile(result, state.currentFile, state.newFile)
	case state.currentFile != "" && strings.HasPrefix(line, "@@ "):
		finishHunk(result, state)
		beginHunk(state, line)
	}
}

// consumeHunkLine updates result and state for one line inside an active unified-diff hunk and reports whether line belonged to that hunk.
//
// Added ('+') lines enter result.LinesByFile, context (' ') lines advance state.newLine without marking changes, and '-' sets a delete anchor.
// Returns false when line is not a hunk body marker so parsePatchLine closes the hunk and parses line as the next diff header.
func consumeHunkLine(result *ChangedLines, state *patchParseState, line string) bool {
	switch {
	case strings.HasPrefix(line, "+") && state.newRemaining > 0:
		state.hunkSawBody = true
		state.hunkSawAdd = true
		// Wholly new files already retain every finding, so line-level entries are recorded only for modified files.
		if _, whole := result.WholeFiles[state.currentFile]; !whole && state.currentFile != "" {
			result.LinesByFile[state.currentFile][state.newLine] = struct{}{}
		}
		state.newLine++
		state.newRemaining--
	case strings.HasPrefix(line, "-") && state.oldRemaining > 0:
		state.hunkSawBody = true
		// Keep the first deletion point so a pure-deletion hunk still anchors nearby findings when no lines are added.
		if state.deletionAnchor == 0 {
			state.deletionAnchor = max(1, state.newLine)
		}
		state.oldRemaining--
	// Treat bare empty lines as context only once body lines have started, so header-only patches never lose their fallback line range.
	case (strings.HasPrefix(line, " ") || (line == "" && state.hunkSawBody)) && state.oldRemaining > 0 && state.newRemaining > 0:
		state.hunkSawBody = true
		state.newLine++
		state.oldRemaining--
		state.newRemaining--
	case strings.HasPrefix(line, "\\"):
		// "\ No newline at end of file" is hunk metadata and consumes neither old nor new line counts.
		return true
	default:
		return false
	}
	// Close the hunk immediately once all expected old and new lines have been read so the next diff header parses cleanly.
	if state.oldRemaining == 0 && state.newRemaining == 0 {
		finishHunk(result, state)
	}
	return true
}

// beginHunk initializes active hunk tracking in state from a unified-diff @@ header line.
// A header that does not match hunkPattern leaves state outside any hunk.
func beginHunk(state *patchParseState, line string) {
	matches := hunkPattern.FindStringSubmatch(line)
	if len(matches) == 0 {
		return
	}
	oldCount := 1
	if matches[1] != "" {
		oldCount, _ = strconv.Atoi(matches[1])
	}
	start, _ := strconv.Atoi(matches[2])
	newCount := 1
	if matches[3] != "" {
		newCount, _ = strconv.Atoi(matches[3])
	}
	state.inHunk = true
	state.oldRemaining = oldCount
	state.newRemaining = newCount
	state.newLine = start
	state.hunkStart = start
	state.hunkNewCount = newCount
	state.hunkSawBody = false
	state.hunkSawAdd = false
	state.deletionAnchor = 0
}

// finishHunk closes the active hunk in state and records fallback or deletion-anchor lines into result when needed.
//
// When no hunk body lines appeared (such as synthetic -U0 header-only patches), it marks the header's new-line range in result.
// When body lines held only deletions, it records the deletion anchor line so deletions still trigger overlapping findings; inactive hunks no-op.
func finishHunk(result *ChangedLines, state *patchParseState) {
	if !state.inHunk {
		return
	}
	state.inHunk = false
	file := state.currentFile
	// Skip recording when no destination file was established or the entire file is already marked whole.
	if file == "" {
		return
	}
	if _, whole := result.WholeFiles[file]; whole {
		return
	}
	// Header-only hunks without body lines fall back to the header's declared new range (or line 1 for a zero-line deletion).
	if !state.hunkSawBody {
		if state.hunkNewCount == 0 {
			result.LinesByFile[file][max(1, state.hunkStart)] = struct{}{}
			return
		}
		for offset := 0; offset < state.hunkNewCount; offset++ {
			result.LinesByFile[file][state.hunkStart+offset] = struct{}{}
		}
		return
	}
	// A hunk with only deletions and context gets one anchor line so deleting a guard or comment keeps findings at that spot in scope.
	if !state.hunkSawAdd {
		anchor := state.deletionAnchor
		if anchor < 1 {
			anchor = max(1, state.hunkStart)
		}
		result.LinesByFile[file][anchor] = struct{}{}
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

// Filter keeps findings overlapping changed, including all findings in wholly changed files and unlocated findings in any listed file.
// A nil Location or line 0 counts as unlocated, and an empty changed-line set for the file still retains such findings.
//
// It returns a FilterResult with the kept findings in input order and the dropped count in FilteredFindings, zero when every finding overlaps.
// When nothing overlaps, Findings is an empty, non-nil slice.
func Filter(findings []finding.Finding, changed ChangedLines) FilterResult {
	kept := make([]finding.Finding, 0, len(findings))
	filtered := 0
	for _, item := range findings {
		// Only findings overlapping the requested change belong in this patch report.
		if MatchesFinding(item, changed) {
			kept = append(kept, item)
			continue
		}
		filtered++
	}
	return FilterResult{Findings: kept, FilteredFindings: filtered}
}

// MatchesFinding reports whether a finding overlaps the changed-line set.
//
// item matches when changed marks its file whole, or lists the file and either item has no line or a line from Line to EndLine is changed.
// An EndLine of zero or below Line counts as Line, and a file absent from both maps reports false.
func MatchesFinding(item finding.Finding, changed ChangedLines) bool {
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
	// A developer can touch a later member of a test group while the finding still points at its first member.
	for _, line := range item.GroupMemberLines() {
		// Any edited member is enough to keep its duplicate group in scope.
		if _, changed := lines[line]; changed {
			return true
		}
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

// parseNewFile extracts the destination file path from a unified-diff "+++ " header line.
//
// It strips optional diff -u tab-separated timestamps and any leading b/ prefix.
// Returns an empty string for deleted files ("/dev/null") or an empty header so callers skip tracking them.
func parseNewFile(line string) string {
	headerPath, _, _ := strings.Cut(strings.TrimPrefix(line, "+++ "), "\t")
	cleanPath := strings.TrimSpace(headerPath)
	// Deleted files use /dev/null as their destination and carry no post-change lines to filter.
	if cleanPath == "/dev/null" {
		return ""
	}
	if strings.HasPrefix(cleanPath, "b/") {
		return strings.TrimPrefix(cleanPath, "b/")
	}
	return cleanPath
}

// gitHasHead reports whether the git repository at root has a resolvable HEAD commit.
// ctx cancels the probe; unborn repositories without an initial commit report false so FromMode falls back to staged plus unstaged diffs.
func gitHasHead(ctx context.Context, root string) bool {
	// #nosec G204 -- fixed git subcommand with no user-controlled arguments.
	command := exec.CommandContext(ctx, "git", "rev-parse", "--verify", "--quiet", "HEAD")
	command.Dir = root
	return command.Run() == nil
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
