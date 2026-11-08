// Package source discovers the Go and text/config files gruff-go analyses under the requested paths.
//
// It applies config paths.ignore globs, the repository .gitignore, built-in default skips and generated-file detection.
// Skips are listed with a reason, but most files of an unsupported type, such as .md or .js, are dropped without a record.
//
// CheckIgnore applies the same path rules to a single path for the check-ignore command.
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

// File represents one discovered source file that gruff-go will analyse.
//
// Path and Type are serialised to JSON, while AbsPath stays out of JSON and is used for file IO.
type File struct {
	// Path is the slash-normalised display path, which may be absolute for inputs outside the discovery root.
	Path string `json:"path"`
	// AbsPath is the absolute filesystem path used for file IO; not serialised to JSON.
	AbsPath string `json:"-"`
	// Type classifies the file as Go source or generic text/config content.
	Type FileType `json:"type"`
}

// Ignore-origin classifications name the layer that excluded a path, so a coding-agent hook can tell config scope from incidental defaults.
//
//   - OriginConfig: a config paths.ignore glob matched, a scope the agent must respect.
//   - OriginGitignore: the repository .gitignore matched.
//   - OriginDefault: a built-in default such as VCS internals, tool metadata, third-party or minified files, or the dependency fallback.
//   - OriginGenerated: generated-file detection, which only discovery reports, never CheckIgnore.
//
// They appear in SkippedPath.Source and CheckIgnore results, and are named Origin so they do not stutter as source.SourceConfig.
const (
	OriginConfig    = "config"
	OriginGitignore = "gitignore"
	OriginDefault   = "default"
	OriginGenerated = "generated"
)

// SkippedPath records a discovered path that was filtered out, with the reason code.
//
// Discover lists these in Result.Skipped, but most files of an unsupported type, such as .md or .js, are dropped without one.
type SkippedPath struct {
	// Path is the slash-normalised display path, which may be absolute for inputs outside the discovery root.
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
//
// Discovery skip records and the check-ignore command both come from this engine, but their outcomes can differ.
// check-ignore judges a file as if the user named it directly, so only config globs and VCS internals can exclude it.
// Discovery also skips generated Go files, which check-ignore never reports.
type IgnoreDecision struct {
	// Ignored is true when the path would be excluded from analysis.
	Ignored bool
	// Reason is the stable short code retained for backward compatibility.
	Reason string
	// Source names the deciding layer, config, gitignore or default, when Ignored is true, and is empty otherwise.
	Source string
	// Pattern is the exact config glob that matched, populated only for Source config.
	Pattern string
}

// skippedPath projects an ignore decision onto the discovery SkippedPath shape.
//
// It returns a SkippedPath with Path set to rel, the slash-separated display path, and Reason, Source and Pattern copied from the decision.
// Pattern is empty unless Source is config.
func (d IgnoreDecision) skippedPath(rel string) SkippedPath {
	return SkippedPath{Path: rel, Reason: d.Reason, Source: d.Source, Pattern: d.Pattern}
}

// CheckIgnore reports whether the repository-relative path rel would be excluded from analysis under options, for the check-ignore command.
//
// It uses the same decideIgnore engine as Discover; isDir selects directory-pattern semantics and rootAbs anchors the .gitignore matcher.
// A file is judged as if the user had named it as an input, so only config globs and VCS internals can exclude it.
//
// It may read repository .gitignore files but never the candidate file, so generated-file detection is never reported here.
// The result carries Reason, Source and, for a config glob, Pattern; a zero IgnoreDecision means no ignore rule excludes the path.
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
	// Paths lists the input files and directories, relative ones joined to Root; empty means scan everything under Root.
	Paths []string
	// IncludeIgnored, when true, disables every skip except config globs and VCS internals, including generated-file detection.
	IncludeIgnored bool
	// IgnorePatterns are the config paths.ignore globs; they win over every other layer, even for files the user names directly.
	IgnorePatterns []string
}

// Discover walks the configured paths and returns classified source files and skips.
//
// options sets the context, root (default the working directory), input paths (default the whole root), ignore patterns and IncludeIgnored.
// On success it returns sorted files, missing inputs and skipped paths, and an absent input is recorded as missing.
// The error is non-nil, with an empty Result, when the context is done, the root cannot be made absolute, or a stat or directory walk fails.
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
	// If the root cannot be made absolute, for example after the working directory is deleted mid-run, discovery returns that error.
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

// newDiscoveryWalker constructs a walker rooted at rootAbs, with gitignore handling enabled unless options.IncludeIgnored is set.
//
// options is kept for ignore patterns and IncludeIgnored, ctx is checked during walks, and a .gitignore matcher is always built for rootAbs.
// It returns a non-nil walker with an empty Result.
func newDiscoveryWalker(ctx context.Context, rootAbs string, options Options) *discoveryWalker {
	return &discoveryWalker{
		ctx:             ctx,
		rootAbs:         rootAbs,
		options:         options,
		matcher:         NewMatcher(rootAbs),
		gitignoreActive: !options.IncludeIgnored,
	}
}

// fallbackAppliesAt reports whether the no-gitignore fallback skips, such as node_modules, build and coverage, apply at rel.
//
// The fallback steps aside once any readable .gitignore, even one with no rules, exists from the discovery root through rel's parent.
// Third-party and minified skips run earlier in decideIgnore and do not defer to a .gitignore.
func (w *discoveryWalker) fallbackAppliesAt(rel string) bool {
	parent := parentSlashDir(rel)
	return !w.matcher.HasGitignoreInChain(parent)
}

// parentSlashDir returns the slash-separated parent directory of rel, or an empty string when rel has no parent.
//
// It mirrors path.Dir but gives an empty string instead of a dot at the top level, matching the Matcher's empty-string root convention.
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
//
// A relative input is joined to rootAbs; a missing one is recorded in Missing, and a file is visited as explicit.
// An ignored non-root directory is recorded in Skipped and returns nil without walking; other directories are walked.
// The error is non-nil when the context is done, os.Stat fails with anything but not-exist, or the directory walk fails.
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
		// A mistyped path argument lands here: it is listed in Missing and the other inputs are still scanned.
		if os.IsNotExist(err) {
			w.result.Missing = append(w.result.Missing, slashClean(input))
			return nil
		}
		// Any other stat failure, such as permission denied on a parent directory, aborts discovery with that error.
		return err
	}
	// A file the user names directly bypasses .gitignore, third-party, minified and fallback skips; config globs and VCS internals still apply.
	if !info.IsDir() {
		w.visitFile(path, true)
		return nil
	}
	path = filepath.Clean(path)
	// A directory input other than the root is checked like any walked directory, so naming a gitignored directory still skips it.
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
		// An unreadable subdirectory, such as one without read permission, aborts the whole discovery instead of being skipped.
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
//
// current is the absolute directory path, converted to a display path for the ignore decision.
// It returns the filepath.SkipDir sentinel error when the directory is ignored, after recording the skip, and nil otherwise.
func (w *discoveryWalker) visitDir(current string) error {
	rel := displayPath(w.rootAbs, current)
	if decision := w.decideIgnore(rel, true, false); decision.Ignored {
		w.result.Skipped = append(w.result.Skipped, decision.skippedPath(rel))
		return filepath.SkipDir
	}
	return nil
}

// visitFile records supported files and reportable skips for a discovered or named file, leaving other unsupported files unreported.
//
// path is the absolute file path; explicit marks a directly named input, exempt from path ignores after VCS internals but not generated-Go checks.
// A default minified-name skip is recorded only when classify accepts the file, so unsupported minified assets stay silent.
// Any other unsupported file, such as notes.md, is listed in Skipped only if an ignore rule excludes it; otherwise addFile drops it silently.
func (w *discoveryWalker) visitFile(path string, explicit bool) {
	rel := displayPath(w.rootAbs, path)
	if decision := w.decideIgnore(rel, false, explicit); decision.Ignored {
		// Only the default minified-name skip needs a supported file; config, .gitignore and other default skips are recorded for any file.
		if _, eligible := classify(path); eligible || decision.Source != OriginDefault || decision.Reason != minifiedReason {
			w.result.Skipped = append(w.result.Skipped, decision.skippedPath(rel))
		}
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

// normalize sorts the discovery Result fields, deduplicates files and missing inputs, and removes adjacent identical skipped records.
//
// Files and Missing are sorted by path, and Skipped by path then reason, so the lists keep one order between runs.
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

// decideIgnore is the single path-only ignore engine shared by discovery and check-ignore; generated-file detection stays in addFile.
//
// Order: config globs, VCS internals, in-root .gitignore, third-party, build-output and minified names, then the no-gitignore fallback.
// Explicit files and IncludeIgnored stop after VCS internals, and only the fallback defers to a governing .gitignore.
//
// rel is the slash-separated display path, isDir selects directory rules, and explicit marks a file the user named directly.
// It returns a zero IgnoreDecision when the path is kept; otherwise Ignored is true with the deciding Reason and Source, and Pattern for config.
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
	// A directory input outside the root is walked without this repository's .gitignore, since its paths stay absolute.
	if w.gitignoreActive && repoRelative(rel) {
		if ignored, _ := w.matcher.Match(rel, isDir); ignored {
			return IgnoreDecision{Ignored: true, Reason: "gitignored", Source: OriginGitignore}
		}
	}
	// A committed copy is still someone else's code, so these classes skip whatever the .gitignore says (section 7).
	if reason, ignored := thirdPartyDir(rel, isDir); ignored {
		return IgnoreDecision{Ignored: true, Reason: reason, Source: OriginDefault}
	}
	if !isDir {
		if reason, ignored := minifiedFile(rel); ignored {
			return IgnoreDecision{Ignored: true, Reason: reason, Source: OriginDefault}
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

// addFile adds a file that passed decideIgnore to Result.Files, unless its type is unsupported or it is a generated Go file.
//
// path is the absolute file path, and its display form becomes File.Path.
// An unsupported file is dropped without a record; a generated Go file is recorded in Skipped as generated unless IncludeIgnored is set.
// Generated-file detection reads the file outside check-ignore's path-only engine; a read failure leaves the Go file in Result.Files.
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

// repoRelative reports whether rel is a clean repository-relative path that the repository .gitignore may judge.
//
// displayPath keeps inputs outside the discovery root absolute, so a leading slash, a .. segment or a Windows drive letter means not under root.
// An empty rel or a dot denotes the root itself and also gives false.
func repoRelative(rel string) bool {
	if rel == "" || rel == "." {
		return false
	}
	if strings.HasPrefix(rel, "/") || rel == ".." || strings.HasPrefix(rel, "../") {
		return false
	}
	return !hasWindowsDrivePrefix(rel)
}

// hasWindowsDrivePrefix reports whether path begins with a Windows drive qualifier, a letter and a colon followed by a slash or backslash.
//
// displayPath slash-normalises an out-of-root input to a C:/ path, which has no leading slash or ../ prefix.
// Without this guard repoRelative would accept files under an out-of-root directory input, and the repository .gitignore could skip them.
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

// classify returns the FileType for a path from its extension or base name, with true when gruff-go analyses that type.
//
// Ignoring extension case, .go is Go; .json, .yaml, .yml, .toml, .ini, .xml, .env and .txt are text, as are remaining names starting with .env.
// go.mod and go.sum are matched by base name as text, so the dependency-posture rules can read go.mod.
// Any other file, such as README.md or app.js, gives an empty type and false and is never analysed.
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

// displayPath converts an absolute filesystem path into the repo-relative form shown in File.Path and SkippedPath.Path.
//
// rootAbs is the absolute discovery root; the result is path made relative to it, in slash form.
// When that relative form starts with .. or cannot be computed, the result is path itself in slash form, so out-of-root inputs stay absolute.
func displayPath(rootAbs, path string) string {
	rel, err := filepath.Rel(rootAbs, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

// slashClean normalises a path to slash-separated, cleaned form.
// It returns filepath.Clean of path with separators turned into slashes, so an empty path gives a single dot.
func slashClean(path string) string {
	return filepath.ToSlash(filepath.Clean(path))
}

// dedupeFiles removes adjacent duplicate entries from a sorted file slice, so a file reached through two overlapping inputs is listed once.
//
// files must already be sorted by Path; entries are compared by Path only and the first of each run is kept, reusing the backing array of files.
// It returns the compacted slice, or files unchanged when it holds fewer than two entries.
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
//
// It returns the compacted slice, which reuses the backing array of skipped and drops only entries equal in every field to the one before.
// Fewer than two entries are returned unchanged.
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
