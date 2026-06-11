package analysis

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/source"
)

// projectContextFiles loads same-directory Go siblings for explicit file scans
// so project rules can reason about package-level evidence without reporting
// findings from those context-only files.
func projectContextFiles(root string, opts Options, primary []source.File) ([]source.File, error) {
	dirs := explicitGoFileDirs(root, opts.Paths, primary)
	if len(dirs) == 0 {
		return primary, nil
	}
	paths := []string{}
	for dir := range dirs {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
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

// explicitGoFileDirs returns package directories for user-supplied file paths
// that resolved to Go source in the primary discovery set.
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
	for _, input := range paths {
		abs := input
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(root, input)
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

// slashDir returns the slash-separated parent directory, using an empty string
// for files directly under the analysis root.
func slashDir(path string) string {
	dir := filepath.ToSlash(filepath.Dir(path))
	if dir == "." {
		return ""
	}
	return dir
}

// mergeSourceFiles joins primary report targets with context-only files by
// stable display path.
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

// sameSourceFileSet reports whether two already-sorted discovery results cover
// the same display paths.
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

// reportableFileSet builds the allowlist of primary files whose findings should
// remain visible in the final report.
func reportableFileSet(files []source.File) map[string]struct{} {
	allowed := map[string]struct{}{}
	for _, file := range files {
		allowed[file.Path] = struct{}{}
	}
	return allowed
}

// filterFindingsToFiles removes findings that were produced only because a
// sibling file was parsed for package-level context.
func filterFindingsToFiles(findings []finding.Finding, allowed map[string]struct{}) []finding.Finding {
	if len(allowed) == 0 {
		return findings
	}
	filtered := findings[:0]
	for _, item := range findings {
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
