// Package source discovers analyzable Go and text/config source files.
package source

import (
	"bufio"
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
	Root           string
	Paths          []string
	IncludeIgnored bool
	IgnorePatterns []string
}

func Discover(options Options) (Result, error) {
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

	walker := newDiscoveryWalker(rootAbs, options)
	for _, input := range paths {
		if err := walker.visitInput(input); err != nil {
			return Result{}, err
		}
	}
	walker.flushParseErrors()
	walker.normalize()
	return walker.result, nil
}

type discoveryWalker struct {
	rootAbs         string
	options         Options
	matcher         *Matcher
	gitignoreActive bool
	result          Result
}

func newDiscoveryWalker(rootAbs string, options Options) *discoveryWalker {
	return &discoveryWalker{
		rootAbs:         rootAbs,
		options:         options,
		matcher:         NewMatcher(rootAbs),
		gitignoreActive: !options.IncludeIgnored,
	}
}

func (w *discoveryWalker) visitInput(input string) error {
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
	return filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
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
	if !w.options.IncludeIgnored {
		if reason, ignored := ignoredDir(w.rootAbs, current, w.options.IgnorePatterns); ignored {
			w.result.Skipped = append(w.result.Skipped, SkippedPath{Path: rel, Reason: reason})
			return filepath.SkipDir
		}
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
	addFile(w.rootAbs, path, w.options.IncludeIgnored, w.options.IgnorePatterns, &w.result)
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

func addFile(rootAbs, path string, includeIgnored bool, ignorePatterns []string, result *Result) {
	rel := displayPath(rootAbs, path)
	if !includeIgnored {
		if reason, ignored := ignoredFile(rel, ignorePatterns); ignored {
			result.Skipped = append(result.Skipped, SkippedPath{Path: rel, Reason: reason})
			return
		}
	}
	fileType, ok := classify(path)
	if !ok {
		return
	}
	if fileType == FileTypeGo && !includeIgnored && isGeneratedGo(path) {
		result.Skipped = append(result.Skipped, SkippedPath{Path: rel, Reason: "generated"})
		return
	}
	result.Files = append(result.Files, File{Path: rel, AbsPath: path, Type: fileType})
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

func ignoredDir(rootAbs, path string, ignorePatterns []string) (string, bool) {
	rel := displayPath(rootAbs, path)
	if pathfilter.MatchesAny(ignorePatterns, rel) {
		return "config-ignore", true
	}
	parts := strings.Split(rel, "/")
	for _, part := range parts {
		switch part {
		case ".git", ".hg", ".svn":
			return "vcs", true
		case "vendor", "node_modules":
			return "dependency", true
		case "dist", "build", "coverage":
			return "build-output", true
		case ".idea", ".vscode":
			return "local-tooling", true
		}
	}
	if rel == ".goat-flow/tasks" || strings.HasPrefix(rel, ".goat-flow/tasks/") {
		return "goat-flow-local-task-state", true
	}
	if rel == ".goat-flow/logs" || strings.HasPrefix(rel, ".goat-flow/logs/") {
		return "goat-flow-local-logs", true
	}
	if rel == ".goat-flow/scratchpad" || strings.HasPrefix(rel, ".goat-flow/scratchpad/") {
		return "goat-flow-local-scratchpad", true
	}
	return "", false
}

func ignoredFile(rel string, ignorePatterns []string) (string, bool) {
	if pathfilter.MatchesAny(ignorePatterns, rel) {
		return "config-ignore", true
	}
	if strings.HasPrefix(rel, ".goat-flow/tasks/") {
		return "goat-flow-local-task-state", true
	}
	if strings.HasPrefix(rel, ".goat-flow/logs/") {
		return "goat-flow-local-logs", true
	}
	if strings.HasPrefix(rel, ".goat-flow/scratchpad/") {
		return "goat-flow-local-scratchpad", true
	}
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
