// Package source discovers analyzable Go and text/config source files.
// It applies .gitignore filtering, fallback dependency skips, and project ignore patterns.
package source

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/pathfilter"
)

// FileType labels discovered files as Go source or generic text/config content.
type FileType string

// FileTypeGo and FileTypeText are the supported source classifications emitted by Discover.
const (
	FileTypeGo   FileType = "go"
	FileTypeText FileType = "text"
)

// File represents a discovered source file with its repo-relative and absolute paths.
type File struct {
	// Path is the slash-normalised path relative to the discovery root.
	Path string `json:"path"`
	// AbsPath is the absolute filesystem path used for file IO; not serialised to JSON.
	AbsPath string `json:"-"`
	// Type classifies the file as Go source or generic text/config content.
	Type FileType `json:"type"`
}

// SkippedPath records a discovered path that was filtered out, with the reason code.
type SkippedPath struct {
	// Path is the slash-normalised path relative to the discovery root.
	Path string `json:"path"`
	// Reason is the short identifier explaining why the path was skipped (e.g. "gitignored", "generated").
	Reason string `json:"reason"`
}

// Result is the discovery output containing files, missing inputs, and skipped paths.
type Result struct {
	// Files is the sorted, deduped list of accepted source files.
	Files []File `json:"files"`
	// Missing lists user-provided input paths that did not exist on disk.
	Missing []string `json:"missing"`
	// Skipped lists paths excluded from analysis with their reasons.
	Skipped []SkippedPath `json:"skipped"`
}

// Options configures a single Discover invocation.
type Options struct {
	// Context cancels discovery; nil defaults to context.Background.
	Context context.Context
	// Root is the directory walked for discovery; empty means current working directory.
	Root string
	// Paths limits discovery to these explicit roots under Root; empty means scan everything under Root.
	Paths []string
	// IncludeIgnored disables gitignore and metadata pruning when true.
	IncludeIgnored bool
	// IgnorePatterns are config-supplied path patterns merged on top of gitignore handling.
	IgnorePatterns []string
}

// Discover walks the configured paths and returns classified source files and skips.
func Discover(options Options) (Result, error) {
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	root := options.Root
	if root == "" {
		root = "."
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return Result{}, err
	}
	paths := options.Paths
	if len(paths) == 0 {
		paths = []string{"."}
	}

	walker := newDiscoveryWalker(ctx, rootAbs, options)
	for _, input := range paths {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if err := walker.visitInput(input); err != nil {
			return Result{}, err
		}
	}
	walker.flushParseErrors()
	walker.normalize()
	return walker.result, nil
}

// discoveryWalker holds the state used by Discover while traversing the filesystem.
type discoveryWalker struct {
	ctx             context.Context
	rootAbs         string
	options         Options
	matcher         *Matcher
	gitignoreActive bool
	result          Result
}

// newDiscoveryWalker constructs a walker rooted at rootAbs with gitignore handling enabled.
func newDiscoveryWalker(ctx context.Context, rootAbs string, options Options) *discoveryWalker {
	return &discoveryWalker{
		ctx:             ctx,
		rootAbs:         rootAbs,
		options:         options,
		matcher:         NewMatcher(rootAbs),
		gitignoreActive: !options.IncludeIgnored,
	}
}

// fallbackAppliesAt reports whether the hardcoded dependency-skip fallback
// (vendor/node_modules/dist/...) should apply at rel. The fallback is a zero-
// configuration default for repositories that ship no .gitignore at all; once
// any .gitignore appears in the ancestor chain the project has expressed its
// own intent, so the fallback steps aside instead of overriding it.
func (w *discoveryWalker) fallbackAppliesAt(rel string) bool {
	parent := parentSlashDir(rel)
	return !w.matcher.HasGitignoreInChain(parent)
}

// parentSlashDir returns the slash-separated parent directory of rel, or "" if
// rel has no parent. Mirrors path.Dir but returns "" instead of "." for the
// top level so it lines up with the Matcher's "" root convention.
func parentSlashDir(rel string) string {
	if rel == "" || rel == "." {
		return ""
	}
	idx := strings.LastIndex(rel, "/")
	if idx <= 0 {
		return ""
	}
	return rel[:idx]
}

// visitInput processes a single user-provided input path, file or directory.
func (w *discoveryWalker) visitInput(input string) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	path := input
	if !filepath.IsAbs(path) {
		path = filepath.Join(w.rootAbs, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			w.result.Missing = append(w.result.Missing, slashClean(input))
			return nil
		}
		return err
	}
	if !info.IsDir() {
		w.visitFile(path)
		return nil
	}
	path = filepath.Clean(path)
	if path != filepath.Clean(w.rootAbs) {
		if err := w.visitDir(path); err != nil {
			if err == filepath.SkipDir {
				return nil
			}
			return err
		}
	}
	return filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if current == path {
				return nil
			}
			return w.visitDir(current)
		}
		w.visitFile(current)
		return nil
	})
}

// visitDir decides whether to prune or descend into a directory.
func (w *discoveryWalker) visitDir(current string) error {
	rel := displayPath(w.rootAbs, current)
	if w.gitignoreActive && pathUnderRoot(w.rootAbs, current) {
		if ignored, _ := w.matcher.Match(rel, true); ignored {
			w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: rel, Reason: "gitignored"})
			return filepath.SkipDir
		}
	}
	if reason, ignored := w.ignoredDir(rel); ignored {
		w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: rel, Reason: reason})
		return filepath.SkipDir
	}
	return nil
}

// visitFile classifies a discovered file and records it as scanned or skipped.
func (w *discoveryWalker) visitFile(path string) {
	if w.gitignoreActive && pathUnderRoot(w.rootAbs, path) {
		rel := displayPath(w.rootAbs, path)
		if ignored, _ := w.matcher.Match(rel, false); ignored {
			w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: rel, Reason: "gitignored"})
			return
		}
	}
	w.addFile(path)
}

// flushParseErrors records gitignore parse errors as skipped entries.
func (w *discoveryWalker) flushParseErrors() {
	for _, badPath := range w.matcher.ParseErrors() {
		w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: badPath, Reason: "gitignore-parse-error"})
	}
}

// normalize sorts and dedupes the discovery Result fields for determinism.
func (w *discoveryWalker) normalize() {
	slices.SortFunc(w.result.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	slices.Sort(w.result.Missing)
	slices.SortFunc(w.result.Skipped, func(a, b SkippedPath) int {
		if a.Path == b.Path {
			return strings.Compare(a.Reason, b.Reason)
		}
		return strings.Compare(a.Path, b.Path)
	})
	w.result.Files = dedupeFiles(w.result.Files)
	w.result.Missing = slices.Compact(w.result.Missing)
	w.result.Skipped = dedupeSkipped(w.result.Skipped)
}

// ignoredDir returns the skip reason and true when the directory should be pruned.
func (w *discoveryWalker) ignoredDir(rel string) (string, bool) {
	if pathfilter.MatchesAny(w.options.IgnorePatterns, rel) {
		return "config-ignore", true
	}
	if w.options.IncludeIgnored {
		return "", false
	}
	if reason, ignored := alwaysIgnoredDir(rel); ignored {
		return reason, true
	}
	if w.fallbackAppliesAt(rel) {
		return fallbackIgnoredDir(rel)
	}
	return "", false
}

// addFile applies file-level filters and appends accepted files to the Result.
func (w *discoveryWalker) addFile(path string) {
	rel := displayPath(w.rootAbs, path)
	if pathfilter.MatchesAny(w.options.IgnorePatterns, rel) {
		w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: rel, Reason: "config-ignore"})
		return
	}
	if !w.options.IncludeIgnored {
		if reason, ignored := alwaysIgnoredFile(rel); ignored {
			w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: rel, Reason: reason})
			return
		}
		if w.fallbackAppliesAt(rel) {
			if reason, ignored := fallbackIgnoredFile(rel); ignored {
				w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: rel, Reason: reason})
				return
			}
		}
	}
	fileType, ok := classify(path)
	if !ok {
		return
	}
	if fileType == FileTypeGo && !w.options.IncludeIgnored && isGeneratedGo(path) {
		w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: rel, Reason: "generated"})
		return
	}
	w.result.Files = append(w.result.Files, File{Path: rel, AbsPath: path, Type: fileType})
}

// pathUnderRoot reports whether path lives inside rootAbs. Used to gate the
// repository .gitignore matcher so explicit inputs outside the discovery root
// (for example an absolute /tmp path passed alongside an in-repo target) are
// not silently dropped by unrelated rules from the project's .gitignore.
func pathUnderRoot(rootAbs, path string) bool {
	rel, err := filepath.Rel(rootAbs, path)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// classify returns the FileType for a path based on its extension or name.
func classify(path string) (FileType, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".go" {
		return FileTypeGo, true
	}
	switch ext {
	case ".json", ".yaml", ".yml", ".toml", ".ini", ".xml", ".env", ".txt":
		return FileTypeText, true
	default:
		if strings.HasPrefix(filepath.Base(path), ".env") {
			return FileTypeText, true
		}
		return "", false
	}
}

// alwaysIgnoredDir reports VCS and tool-metadata directories that are unconditionally skipped.
func alwaysIgnoredDir(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	for _, part := range parts {
		switch part {
		case ".git", ".hg", ".svn":
			return "vcs", true
		case ".agents", ".claude", ".codex", ".github", ".goat-flow":
			return "non-application-metadata", true
		}
	}
	return "", false
}

// alwaysIgnoredFile reports files that live inside unconditionally skipped metadata directories.
func alwaysIgnoredFile(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	for _, part := range parts[:len(parts)-1] {
		switch part {
		case ".agents", ".claude", ".codex", ".github", ".goat-flow":
			return "non-application-metadata", true
		}
	}
	return "", false
}

// fallbackIgnoredDir reports directories skipped when no project .gitignore exists.
func fallbackIgnoredDir(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	for _, part := range parts {
		switch part {
		case "vendor", "node_modules":
			return "dependency", true
		case "dist", "build", "coverage":
			return "build-output", true
		case ".idea", ".vscode":
			return "local-tooling", true
		}
	}
	return "", false
}

// fallbackIgnoredFile is a placeholder for future filename-based fallback skips.
func fallbackIgnoredFile(_ string) (string, bool) {
	return "", false
}

// isGeneratedGo reports whether a Go file carries the generated-file marker comment.
func isGeneratedGo(path string) bool {
	// #nosec G304 -- scanner intentionally opens files selected by discovery.
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "package ") {
			return false
		}
		if !strings.HasPrefix(line, "//") && !strings.HasPrefix(line, "/*") && !strings.HasPrefix(line, "*") {
			return false
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "code generated") && strings.Contains(lower, "do not edit") {
			return true
		}
	}
	return false
}

// displayPath converts an absolute filesystem path into a repo-relative display form.
func displayPath(rootAbs, path string) string {
	rel, err := filepath.Rel(rootAbs, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

// slashClean normalises a path to slash-separated, cleaned form.
func slashClean(path string) string {
	return filepath.ToSlash(filepath.Clean(path))
}

// dedupeFiles removes adjacent duplicate entries from a sorted file slice.
func dedupeFiles(files []File) []File {
	if len(files) < 2 {
		return files
	}
	out := files[:0]
	var previous string
	for i, file := range files {
		if i > 0 && file.Path == previous {
			continue
		}
		out = append(out, file)
		previous = file.Path
	}
	return out
}

// dedupeSkipped removes adjacent duplicate entries from a sorted skipped-paths slice.
func dedupeSkipped(skipped []SkippedPath) []SkippedPath {
	if len(skipped) < 2 {
		return skipped
	}
	out := skipped[:0]
	var previous SkippedPath
	for i, item := range skipped {
		if i > 0 && item == previous {
			continue
		}
		out = append(out, item)
		previous = item
	}
	return out
}
