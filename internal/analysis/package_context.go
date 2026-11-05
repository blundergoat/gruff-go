package analysis

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// projectContextFiles adds the same-directory Go siblings of each named Go file inside root, so project rules can read package evidence.
//
// Reached on a scan such as gruff-go analyse internal/cli/hook.go; findings in those context-only siblings stay out of the report.
//
// root is the analysis root; opts supplies the explicit scan paths and the context, ignore patterns and include-ignored setting for discovery.
//
// It returns primary, the report targets, unchanged when no explicit path inside root names one of its Go files.
// Otherwise the result merges primary with the discovered .go siblings.
// It fails with a nil slice and the error when a sibling directory cannot be read or source discovery fails.
func projectContextFiles(root string, opts Options, primary []source.File) ([]source.File, error) {
	dirs := explicitGoFileDirs(root, opts.Paths, primary)
	// A directory operand, or a scan naming no Go file, gets no sibling context, and the discovered targets are used as they are.
	if len(dirs) == 0 {
		return primary, nil
	}
	paths := []string{}
	for dir := range dirs {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		// A package directory deleted or made unreadable during the run lands here, and no partial context set is returned.
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			paths = append(paths, filepath.ToSlash(filepath.Join(dir, entry.Name())))
		}
	}
	slices.Sort(paths)
	// Siblings are rediscovered with the scan's ignore patterns and include-ignored setting, so ignore config also applies to context files.
	discovery, err := source.Discover(source.Options{
		Context:        opts.Context,
		Root:           root,
		Paths:          paths,
		IgnorePatterns: opts.IgnorePaths,
		IncludeIgnored: opts.IncludeIgnored,
	})
	if err != nil {
		return nil, err
	}
	return mergeSourceFiles(primary, discovery.Files), nil
}

// explicitGoFileDirs returns the package directories of the named files inside root that discovery kept as Go source.
//
// root resolves each relative entry of paths, the user's scan operands, and primary is the discovery set whose Go files qualify.
// Directory operands, paths that fail to stat, files outside root and files outside primary are skipped; the result is nil when none qualifies.
// Keys are slash-separated directories relative to root, with an empty key for a file directly under it.
func explicitGoFileDirs(root string, paths []string, primary []source.File) map[string]struct{} {
	if len(paths) == 0 || len(primary) == 0 {
		return nil
	}
	primaryGo := map[string]struct{}{}
	for _, file := range primary {
		if file.Type == source.FileTypeGo {
			primaryGo[file.Path] = struct{}{}
		}
	}
	dirs := map[string]struct{}{}
	for _, operand := range paths {
		abs := operand
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(root, operand)
		}
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() {
			continue
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(filepath.Clean(rel))
		// A named file that discovery ignored, or one that is not Go source such as README.md, pulls in no siblings.
		if _, ok := primaryGo[rel]; !ok {
			continue
		}
		dirs[slashDir(rel)] = struct{}{}
	}
	if len(dirs) == 0 {
		return nil
	}
	return dirs
}

// slashDir returns the slash-separated parent directory of path, using an empty string for a file directly under the analysis root.
// path is a project-relative file path; for internal/cli/hook.go the result is internal/cli.
func slashDir(path string) string {
	dir := filepath.ToSlash(filepath.Dir(path))
	if dir == "." {
		return ""
	}
	return dir
}

// mergeSourceFiles joins primary, the report targets, with context, the sibling files read only for package evidence, by stable display path.
//
// It returns one file per display path in ascending path order, and a context entry replaces a primary entry with the same path.
// The result is an empty, non-nil slice when primary and context are both empty.
func mergeSourceFiles(primary []source.File, context []source.File) []source.File {
	byPath := map[string]source.File{}
	for _, file := range primary {
		byPath[file.Path] = file
	}
	for _, file := range context {
		byPath[file.Path] = file
	}
	merged := make([]source.File, 0, len(byPath))
	for _, file := range byPath {
		merged = append(merged, file)
	}
	slices.SortFunc(merged, func(left, right source.File) int {
		return strings.Compare(left.Path, right.Path)
	})
	return merged
}

// sameSourceFileSet reports whether two already-sorted discovery results cover the same display paths.
// left and right are compared position by position, so the same paths in a different order report false.
func sameSourceFileSet(left []source.File, right []source.File) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Path != right[index].Path {
			return false
		}
	}
	return true
}

// contextOnlyParseDiagnostics keeps the parser diagnostics for sibling files pulled in only for package context.
//
// Primary-file diagnostics come from the primary parse, so re-reporting them here would double-count them.
// The rest explain a sibling that failed to parse, so a project rule misfiring on a primary file because of it has a visible cause.
//
// projectDiagnostics holds the parser diagnostics to filter, and primary is the report target set whose file paths are dropped.
// It returns the remaining diagnostics in their original order, or nil when projectDiagnostics is empty.
// When every entry names a primary file the result is an empty, non-nil slice.
func contextOnlyParseDiagnostics(projectDiagnostics []parser.Diagnostic, primary []source.File) []parser.Diagnostic {
	if len(projectDiagnostics) == 0 {
		return nil
	}
	primaryPaths := make(map[string]struct{}, len(primary))
	for _, file := range primary {
		primaryPaths[file.Path] = struct{}{}
	}
	contextOnly := make([]parser.Diagnostic, 0, len(projectDiagnostics))
	for _, item := range projectDiagnostics {
		if _, ok := primaryPaths[item.File]; ok {
			continue
		}
		contextOnly = append(contextOnly, item)
	}
	return contextOnly
}

// reportableFileSet builds the allowlist of primary files whose findings stay visible in the final report.
// It returns a set keyed by the display path of each entry in files; the set is empty, not nil, when files is empty.
func reportableFileSet(files []source.File) map[string]struct{} {
	allowed := map[string]struct{}{}
	for _, file := range files {
		allowed[file.Path] = struct{}{}
	}
	return allowed
}

// filterFindingsToFiles removes findings that were produced only because a sibling file was parsed for package-level context.
//
// findings is filtered in place, overwriting its backing array, and allowed holds the display paths whose findings are kept.
// It returns findings unchanged when allowed is empty; otherwise the result holds, in order, findings with no file or an allowed file.
func filterFindingsToFiles(findings []finding.Finding, allowed map[string]struct{}) []finding.Finding {
	// An empty allowlist keeps every finding rather than blanking the report.
	if len(allowed) == 0 {
		return findings
	}
	filtered := findings[:0]
	for _, item := range findings {
		// A finding with no file cannot come from a sibling, so it stays in the report.
		if item.File == "" {
			filtered = append(filtered, item)
			continue
		}
		if _, ok := allowed[item.File]; ok {
			filtered = append(filtered, item)
		}
	}
	return filtered
}
