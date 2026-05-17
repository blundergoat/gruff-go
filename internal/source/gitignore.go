package source

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Matcher decides whether a slash-separated path inside the discovery root is
// ignored by the working tree's .gitignore files. It is constructed per
// Discover invocation, consults only .gitignore files inside the root, and
// never reads the user's global gitignore, .git/info/exclude, or any external
// Git state. See `.goat-flow/decisions/ADR-004-gitignore-respecting-discovery.md`
// and `.goat-flow/decisions/ADR-005-gitignore-matcher-implementation.md`.
type Matcher struct {
	rootAbs string
	cache   map[string]*ignoreFile
}

// NewMatcher builds a Matcher rooted at rootAbs. .gitignore files are loaded
// lazily on Match calls.
func NewMatcher(rootAbs string) *Matcher {
	return &Matcher{rootAbs: rootAbs, cache: map[string]*ignoreFile{}}
}

// Match reports whether rel is ignored. rel is slash-separated and relative to
// the matcher root with no leading slash. isDir indicates whether rel itself is
// a directory; directory-only patterns (trailing /) only match the path itself
// when isDir is true, but they still match any descendant of a matched
// ancestor directory. source identifies the relative path of the .gitignore
// whose rule decided the outcome.
func (m *Matcher) Match(rel string, isDir bool) (matched bool, source string) {
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" || rel == "." {
		return false, ""
	}
	matched, source = m.matchPath(rel, isDir)
	if matched {
		return matched, source
	}
	parts := strings.Split(rel, "/")
	for i := len(parts) - 1; i >= 1; i-- {
		ancestor := strings.Join(parts[:i], "/")
		if ok, src := m.matchPath(ancestor, true); ok {
			return true, src
		}
	}
	return false, source
}

// ParseErrors returns the relative paths of .gitignore files that failed to
// parse during loading. The matcher silently skips a malformed file's rules;
// callers can surface ParseErrors as discovery diagnostics.
func (m *Matcher) ParseErrors() []string {
	var out []string
	for dir, file := range m.cache {
		if file != nil && file.err != nil {
			out = append(out, joinIgnorePath(dir, ".gitignore"))
		}
	}
	return out
}

func (m *Matcher) matchPath(rel string, isDir bool) (bool, string) {
	chain := ancestorChain(rel)
	matched := false
	source := ""
	for _, dir := range chain {
		file := m.load(dir)
		if file == nil || file.err != nil {
			continue
		}
		rels := relPathFrom(dir, rel)
		for _, rule := range file.rules {
			if rule.dirOnly && !isDir {
				continue
			}
			if rule.match(rels) {
				matched = !rule.negation
				source = joinIgnorePath(dir, ".gitignore")
			}
		}
	}
	return matched, source
}

func (m *Matcher) load(dir string) *ignoreFile {
	if existing, ok := m.cache[dir]; ok {
		return existing
	}
	full := filepath.Join(m.rootAbs, filepath.FromSlash(dir), ".gitignore")
	data, err := os.ReadFile(full)
	if err != nil {
		m.cache[dir] = nil
		return nil
	}
	file := parseIgnoreFile(dir, string(data))
	m.cache[dir] = file
	return file
}

type ignoreFile struct {
	dir   string
	rules []ignoreRule
	err   error
}

type ignoreRule struct {
	raw      string
	negation bool
	dirOnly  bool
	anchored bool
	parts    []string
}

func parseIgnoreFile(dir, text string) *ignoreFile {
	file := &ignoreFile{dir: dir}
	for _, raw := range strings.Split(text, "\n") {
		line := raw
		if strings.HasSuffix(line, "\r") {
			line = line[:len(line)-1]
		}
		line = trimUnescapedTrailingWhitespace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, err := parseIgnoreRule(line)
		if err != nil {
			file.err = err
			file.rules = nil
			return file
		}
		file.rules = append(file.rules, rule)
	}
	return file
}

func parseIgnoreRule(raw string) (ignoreRule, error) {
	rule := ignoreRule{raw: raw}
	line := raw
	switch {
	case strings.HasPrefix(line, `\!`):
		line = line[1:]
	case strings.HasPrefix(line, `\#`):
		line = line[1:]
	case strings.HasPrefix(line, "!"):
		rule.negation = true
		line = line[1:]
	}
	if strings.HasPrefix(line, "/") {
		rule.anchored = true
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		rule.dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}
	if line == "" {
		return ignoreRule{}, fmt.Errorf("empty pattern in %q", raw)
	}
	if strings.Contains(line, "/") {
		rule.anchored = true
	}
	parts := strings.Split(line, "/")
	for _, segment := range parts {
		if segment == "**" {
			continue
		}
		if _, err := path.Match(segment, ""); err != nil {
			return ignoreRule{}, fmt.Errorf("invalid pattern %q: %w", raw, err)
		}
	}
	rule.parts = parts
	return rule, nil
}

func (r ignoreRule) match(rel string) bool {
	if rel == "" {
		return false
	}
	segments := strings.Split(rel, "/")
	if r.anchored {
		return matchSegmentsAt(r.parts, 0, segments, 0)
	}
	for i := 0; i < len(segments); i++ {
		if matchSegmentsAt(r.parts, 0, segments, i) {
			return true
		}
	}
	return false
}

func matchSegmentsAt(pat []string, pi int, seg []string, si int) bool {
	for pi < len(pat) {
		if pat[pi] == "**" {
			if pi == len(pat)-1 {
				return true
			}
			for k := si; k <= len(seg); k++ {
				if matchSegmentsAt(pat, pi+1, seg, k) {
					return true
				}
			}
			return false
		}
		if si >= len(seg) {
			return false
		}
		ok, _ := path.Match(pat[pi], seg[si])
		if !ok {
			return false
		}
		pi++
		si++
	}
	return si == len(seg)
}

func trimUnescapedTrailingWhitespace(line string) string {
	end := len(line)
	for end > 0 {
		switch line[end-1] {
		case ' ', '\t':
			if escaped(line, end-1) {
				return line[:end]
			}
			end--
		default:
			return line[:end]
		}
	}
	return line[:end]
}

func escaped(line string, index int) bool {
	backslashes := 0
	for i := index - 1; i >= 0 && line[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func ancestorChain(rel string) []string {
	parts := strings.Split(rel, "/")
	out := []string{""}
	for i := 1; i < len(parts); i++ {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

func relPathFrom(dir, rel string) string {
	if dir == "" {
		return rel
	}
	return strings.TrimPrefix(rel, dir+"/")
}

func joinIgnorePath(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}
