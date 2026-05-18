// Package source discovers analyzable Go and text/config source files.
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

type FileType string

const (
	FileTypeGo   FileType = "go"
	FileTypeText FileType = "text"
)

type File struct {
	Path    string   `json:"path"`
	AbsPath string   `json:"-"`
	Type    FileType `json:"type"`
}

type SkippedPath struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type Result struct {
	Files   []File        `json:"files"`
	Missing []string      `json:"missing"`
	Skipped []SkippedPath `json:"skipped"`
}

type Options struct {
	Context        context.Context
	Root           string
	Paths          []string
	IncludeIgnored bool
	IgnorePatterns []string
}

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

type discoveryWalker struct {
	ctx             context.Context
	rootAbs         string
	options         Options
	matcher         *Matcher
	gitignoreActive bool
	fallbackActive  bool
	result          Result
}

func newDiscoveryWalker(ctx context.Context, rootAbs string, options Options) *discoveryWalker {
	fallbackActive := !rootHasGitignore(rootAbs)
	return &discoveryWalker{
		ctx:             ctx,
		rootAbs:         rootAbs,
		options:         options,
		matcher:         NewMatcher(rootAbs),
		gitignoreActive: !options.IncludeIgnored,
		fallbackActive:  fallbackActive,
	}
}

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

func (w *discoveryWalker) visitDir(current string) error {
	rel := displayPath(w.rootAbs, current)
	if w.gitignoreActive {
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

func (w *discoveryWalker) visitFile(path string) {
	if w.gitignoreActive {
		rel := displayPath(w.rootAbs, path)
		if ignored, _ := w.matcher.Match(rel, false); ignored {
			w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: rel, Reason: "gitignored"})
			return
		}
	}
	w.addFile(path)
}

func (w *discoveryWalker) flushParseErrors() {
	for _, badPath := range w.matcher.ParseErrors() {
		w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: badPath, Reason: "gitignore-parse-error"})
	}
}

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
	if w.fallbackActive {
		return fallbackIgnoredDir(rel)
	}
	return "", false
}

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
		if w.fallbackActive {
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

func rootHasGitignore(rootAbs string) bool {
	info, err := os.Stat(filepath.Join(rootAbs, ".gitignore"))
	return err == nil && !info.IsDir()
}

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

func fallbackIgnoredFile(_ string) (string, bool) {
	return "", false
}

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

func displayPath(rootAbs, path string) string {
	rel, err := filepath.Rel(rootAbs, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func slashClean(path string) string {
	return filepath.ToSlash(filepath.Clean(path))
}

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
