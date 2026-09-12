// Package source discovers analyzable Go and text/config source files.
// It applies .gitignore filtering, fallback dependency skips, and project ignore patterns.
package source

import (
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

// Ignore-origin classifications reported in SkippedPath.Source and by
// CheckIgnore. They name the layer that excluded a path so a coding-agent hook
// can tell config-driven scope (which the agent must respect) from incidental
// VCS/build defaults: a config paths.ignore glob, a repository .gitignore, a
// built-in default (VCS, tool metadata, dependency fallback), or generated-file
// detection. Named Origin* rather than Source* so the exported identifiers do
// not stutter against the package name in `source.SourceConfig` form.
const (
	OriginConfig    = "config"
	OriginGitignore = "gitignore"
	OriginDefault   = "default"
	OriginGenerated = "generated"
)

// SkippedPath records a discovered path that was filtered out, with the reason code.
type SkippedPath struct {
	// Path is the slash-normalised path relative to the discovery root.
	Path string `json:"path"`
	// Reason is the short identifier explaining why the path was skipped (e.g. "gitignored", "generated").
	Reason string `json:"reason"`
	// Source classifies the deciding layer: config | gitignore | default | generated.
	// Additive field; omitted from JSON when empty so existing {path,reason} consumers are unaffected.
	Source string `json:"source,omitempty"`
	// Pattern is the exact config paths.ignore glob that matched; set only when Source is config.
	Pattern string `json:"pattern,omitempty"`
}

// IgnoreDecision is the result of the shared ignore engine for a single path.
// It backs both discovery's skip records and the check-ignore command, so the
// two can never disagree about whether - or why - a path is ignored.
type IgnoreDecision struct {
	// Ignored is true when the path would be excluded from analysis.
	Ignored bool
	// Reason is the stable short code retained for backward compatibility.
	Reason string
	// Source classifies the deciding layer: config | gitignore | default | generated.
	Source string
	// Pattern is the exact config glob that matched, populated only for Source config.
	Pattern string
}

// skippedPath projects an ignore decision onto the discovery SkippedPath shape.
func (d IgnoreDecision) skippedPath(rel string) SkippedPath {
	return SkippedPath{Path: rel, Reason: d.Reason, Source: d.Source, Pattern: d.Pattern}
}

// CheckIgnore reports whether the repository-relative path rel would be excluded
// from analysis under options, using the exact same engine Discover applies -
// there is no second ignore implementation. isDir selects directory-pattern
// semantics. It reads no file contents and runs no analysis, so it is O(1) per
// path; generated-file detection (which must read the file) is therefore never
// reported here. rootAbs anchors the repository .gitignore matcher.
func CheckIgnore(rootAbs, rel string, isDir bool, options Options) IgnoreDecision {
	walker := newDiscoveryWalker(context.Background(), rootAbs, options)
	return walker.decideIgnore(rel, isDir, !isDir)
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
	// IncludeIgnored disables gitignore, fallback, and generated-file pruning when true.
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
		w.visitFile(path, true)
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
		w.visitFile(current, false)
		return nil
	})
}

// visitDir decides whether to prune or descend into a directory.
func (w *discoveryWalker) visitDir(current string) error {
	rel := displayPath(w.rootAbs, current)
	if decision := w.decideIgnore(rel, true, false); decision.Ignored {
		w.result.Skipped = append(w.result.Skipped, decision.skippedPath(rel))
		return filepath.SkipDir
	}
	return nil
}

// visitFile classifies a discovered or explicitly requested file and records it as scanned or skipped.
func (w *discoveryWalker) visitFile(path string, explicit bool) {
	rel := displayPath(w.rootAbs, path)
	if decision := w.decideIgnore(rel, false, explicit); decision.Ignored {
		w.result.Skipped = append(w.result.Skipped, decision.skippedPath(rel))
		return
	}
	w.addFile(path)
}

// flushParseErrors records gitignore parse errors as skipped entries.
func (w *discoveryWalker) flushParseErrors() {
	for _, badPath := range w.matcher.ParseErrors() {
		w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: badPath, Reason: "gitignore-parse-error", Source: OriginGitignore})
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

// decideIgnore is the single ignore engine shared by discovery and the
// check-ignore command. Precedence, highest first: config paths.ignore
// (authoritative in every invocation mode), VCS internals (always blocked),
// repository .gitignore, then the no-gitignore fallback. Explicit files bypass
// gitignore and fallback decisions. Generated-file detection lives in addFile, not here,
// because it must read the file - keeping this engine O(1) and path-only so
// check-ignore can reuse it verbatim.
func (w *discoveryWalker) decideIgnore(rel string, isDir bool, explicit bool) IgnoreDecision {
	if matched, pattern := pathfilter.FirstMatch(w.options.IgnorePatterns, rel); matched {
		return IgnoreDecision{Ignored: true, Reason: "config-ignore", Source: OriginConfig, Pattern: pattern}
	}
	if isDir {
		if reason, ignored := alwaysIgnoredDir(rel); ignored {
			return IgnoreDecision{Ignored: true, Reason: reason, Source: OriginDefault}
		}
	} else if reason, ignored := alwaysIgnoredFile(rel); ignored {
		return IgnoreDecision{Ignored: true, Reason: reason, Source: OriginDefault}
	}
	if w.options.IncludeIgnored || explicit {
		return IgnoreDecision{}
	}
	if w.gitignoreActive && repoRelative(rel) {
		if ignored, _ := w.matcher.Match(rel, isDir); ignored {
			return IgnoreDecision{Ignored: true, Reason: "gitignored", Source: OriginGitignore}
		}
	}
	if isDir {
		if w.fallbackAppliesAt(rel) {
			if reason, ignored := fallbackIgnoredDir(rel); ignored {
				return IgnoreDecision{Ignored: true, Reason: reason, Source: OriginDefault}
			}
		}
		return IgnoreDecision{}
	}
	if w.fallbackAppliesAt(rel) {
		if reason, ignored := fallbackIgnoredFile(rel); ignored {
			return IgnoreDecision{Ignored: true, Reason: reason, Source: OriginDefault}
		}
	}
	return IgnoreDecision{}
}

// addFile appends a non-ignored file to the Result. The ignore decision is made
// by decideIgnore before this is called, so the only exclusion left here is
// generated-file detection - which reads the file and therefore cannot live in
// the path-only ignore engine that check-ignore shares.
func (w *discoveryWalker) addFile(path string) {
	rel := displayPath(w.rootAbs, path)
	fileType, ok := classify(path)
	if !ok {
		return
	}
	if fileType == FileTypeGo && !w.options.IncludeIgnored && isGeneratedGo(path) {
		w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: rel, Reason: "generated", Source: OriginGenerated})
		return
	}
	w.result.Files = append(w.result.Files, File{Path: rel, AbsPath: path, Type: fileType})
}

// repoRelative reports whether rel is a clean repository-relative path. displayPath
// yields an absolute slash path for inputs outside the discovery root, so a
// leading "/" or ".." means "not under root" and the repository .gitignore
// matcher must not apply - mirroring the pathUnderRoot gate the inline gitignore
// checks used before the engine was unified.
func repoRelative(rel string) bool {
	if rel == "" || rel == "." {
		return false
	}
	if strings.HasPrefix(rel, "/") || rel == ".." || strings.HasPrefix(rel, "../") {
		return false
	}
	return !hasWindowsDrivePrefix(rel)
}

// hasWindowsDrivePrefix reports whether path begins with a Windows drive qualifier
// such as "C:/" or "C:\". displayPath slash-normalises an out-of-root input to
// "C:/…", which carries no leading "/" or "../", so without this guard repoRelative
// would treat an explicitly requested out-of-root file as repo-relative and the
// repository .gitignore matcher could silently skip it.
func hasWindowsDrivePrefix(path string) bool {
	if len(path) < 3 {
		return false
	}
	letter := path[0]
	if !(('A' <= letter && letter <= 'Z') || ('a' <= letter && letter <= 'z')) {
		return false
	}
	return path[1] == ':' && (path[2] == '/' || path[2] == '\\')
}

// classify returns the FileType for a path based on its extension or name.
// go.mod and go.sum carry no recognised extension but are classified as text so
// the Go-module dependency-posture rules can scan them; they are matched by base
// name rather than by an extension switch.
func classify(path string) (FileType, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".go" {
		return FileTypeGo, true
	}
	switch ext {
	case ".json", ".yaml", ".yml", ".toml", ".ini", ".xml", ".env", ".txt":
		return FileTypeText, true
	default:
		base := filepath.Base(path)
		if base == "go.mod" || base == "go.sum" {
			return FileTypeText, true
		}
		if strings.HasPrefix(base, ".env") {
			return FileTypeText, true
		}
		return "", false
	}
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
