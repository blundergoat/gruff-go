// Package source gitignore matcher applies repository-local .gitignore rules.
//
// It is consumed by Discover to skip files Git would normally ignore, so those files are left out of the scan.
// A malformed .gitignore line is dropped and its file is listed by ParseErrors, while the file's valid rules still apply.
package source

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Matcher decides whether a slash-separated path inside the discovery root is ignored by the working tree's .gitignore files.
//
// It is constructed per Discover invocation and consults only .gitignore files inside the root.
// It never reads the user's global gitignore, .git/info/exclude, or any external Git state; other discovery exclusions still apply.
//
// ADR-004 records the gitignore-respecting discovery decision and ADR-005 the matcher implementation.
// Both live under .goat-flow/learning-loop/decisions.
type Matcher struct {
	rootAbs        string
	cache          map[string]*ignoreFile
	ruleChainCache map[string]bool
}

// NewMatcher builds a Matcher rooted at rootAbs, the discovery root that each directory's .gitignore path is joined onto.
//
// .gitignore files are loaded lazily on Match and HasGitignoreInChain calls.
// It returns a non-nil Matcher with empty caches and reads nothing from disk itself.
func NewMatcher(rootAbs string) *Matcher {
	return &Matcher{
		rootAbs:        rootAbs,
		cache:          map[string]*ignoreFile{},
		ruleChainCache: map[string]bool{},
	}
}

// Match reports whether rel is ignored by the .gitignore files from the matcher root down to rel's parent directory.
//
// rel is slash-separated and relative to the matcher root; one leading slash is trimmed, and an empty rel or "." reports false.
// isDir says whether rel itself is a directory: directory-only patterns (trailing /) match rel only when isDir is true.
// They still match any descendant of a matched ancestor directory, so a file under an ignored build/ is ignored too.
//
// It returns matched true when rel or an ancestor directory is ignored, and source as the root-relative path of the deciding .gitignore.
// When matched is false, source names the .gitignore whose negation rule re-included rel, or is empty when no rule matched.
func (m *Matcher) Match(rel string, isDir bool) (matched bool, source string) {
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" || rel == "." {
		return false, ""
	}
	if !m.hasRulesInChain(parentDir(rel)) {
		return false, ""
	}
	matched, source = m.matchPath(rel, isDir)
	if matched {
		return matched, source
	}
	// An ignored ancestor directory beats a negation for rel, as in Git: !build/keep.go cannot re-include a file under an ignored build/.
	parts := strings.Split(rel, "/")
	for i := len(parts) - 1; i >= 1; i-- {
		ancestor := strings.Join(parts[:i], "/")
		if ok, src := m.matchPath(ancestor, true); ok {
			return true, src
		}
	}
	return false, source
}

// hasRulesInChain reports whether any .gitignore from root through dir exists with usable rules.
//
// dir is a root-relative slash directory, empty for the root, and each answer is cached for the life of the Matcher.
// It still loads malformed files so ParseErrors can surface them, while preserving any valid rules from the same file.
// A false result means Match ignores nothing directly inside dir, because no .gitignore on the way there has a valid rule.
func (m *Matcher) hasRulesInChain(dir string) bool {
	if value, ok := m.ruleChainCache[dir]; ok {
		return value
	}
	for _, ancestor := range dirChain(dir) {
		file := m.load(ancestor)
		if file != nil && len(file.rules) > 0 {
			m.ruleChainCache[dir] = true
			return true
		}
	}
	m.ruleChainCache[dir] = false
	return false
}

// HasGitignoreInChain reports whether any directory from the matcher root through dir has a .gitignore file.
//
// Discovery uses this to gate the hardcoded dependency-skip fallback per subtree.
// A monorepo subtree with its own .gitignore then keeps its own rules instead of the dependency-skip fallback inherited from the rootless parent.
//
// dir is root-relative and slash-separated; a .gitignore with no valid rule still counts, while an unreadable one does not.
func (m *Matcher) HasGitignoreInChain(dir string) bool {
	for _, ancestor := range dirChain(dir) {
		if m.load(ancestor) != nil {
			return true
		}
	}
	return false
}

// ParseErrors returns the relative paths of .gitignore files that failed to parse during loading.
//
// Only malformed lines are skipped; valid rules in the same file remain active.
// A lone ! or / line, or a pattern with an unclosed character class, makes a line malformed.
//
// Callers can surface ParseErrors as discovery diagnostics; only files loaded so far are listed, in no fixed order.
// The result is nil when every loaded .gitignore parsed cleanly.
func (m *Matcher) ParseErrors() []string {
	var failedPaths []string
	for dir, file := range m.cache {
		if file != nil && file.err != nil {
			failedPaths = append(failedPaths, joinIgnorePath(dir, ".gitignore"))
		}
	}
	return failedPaths
}

// matchPath walks the ancestor chain and evaluates rules from each .gitignore.
//
// rel is a root-relative slash path; isDir lets directory-only rules apply, and the last matching rule, with deeper files read later, decides.
// It returns whether rel is ignored and the root-relative path of the deciding .gitignore, which stays set when a negation rule wins.
// The results are false and an empty string when no loaded rule matches.
func (m *Matcher) matchPath(rel string, isDir bool) (bool, string) {
	chain := ancestorChain(rel)
	matched := false
	source := ""
	for _, dir := range chain {
		file := m.load(dir)
		if file == nil {
			continue
		}
		relFromDir := relPathFrom(dir, rel)
		for _, rule := range file.rules {
			// A trailing-slash pattern such as build/ skips files here; Match still ignores files under build through its ancestor check.
			if rule.dirOnly && !isDir {
				continue
			}
			if rule.match(relFromDir) {
				matched = !rule.negation
				source = joinIgnorePath(dir, ".gitignore")
			}
		}
	}
	return matched, source
}

// load reads and caches the .gitignore file at the given directory.
//
// dir is slash-separated and relative to the matcher root, with an empty string for the root itself.
// It returns the parsed file, which may carry a parse error, or nil when the file is missing or unreadable; both outcomes are cached per dir.
func (m *Matcher) load(dir string) *ignoreFile {
	if existing, ok := m.cache[dir]; ok {
		return existing
	}
	ignoreFilePath := filepath.Join(m.rootAbs, filepath.FromSlash(dir), ".gitignore")
	data, err := os.ReadFile(ignoreFilePath)
	// A .gitignore gruff-go cannot read, such as one with mode 000, is treated as absent: its rules do not apply and ParseErrors does not list it.
	if err != nil {
		m.cache[dir] = nil
		return nil
	}
	file := parseIgnoreFile(dir, string(data))
	m.cache[dir] = file
	return file
}

// ignoreFile holds the parsed rules from a single .gitignore file.
type ignoreFile struct {
	dir   string
	rules []ignoreRule
	err   error
}

// ignoreRule represents one .gitignore pattern with parsed flags.
type ignoreRule struct {
	raw      string
	negation bool
	dirOnly  bool
	anchored bool
	parts    []string
}

// parseIgnoreFile parses .gitignore text into rules attached to the given directory.
//
// dir is the root-relative directory recorded on the result.
// text is split on newlines; each line drops a trailing carriage return and unescaped trailing whitespace, and blank or # lines are skipped.
// It returns a non-nil ignoreFile with the valid rules in file order; an unparsable line is dropped and the last such error is kept in err.
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
		// A malformed line is dropped while later lines still load, and ParseErrors then lists this file.
		if err != nil {
			file.err = err
			continue
		}
		file.rules = append(file.rules, rule)
	}
	return file
}

// parseIgnoreRule converts a single .gitignore line into a structured ignoreRule.
//
// raw is one trimmed, non-comment line from parseIgnoreFile; a leading backslash escapes ! or #, and an unescaped leading ! sets negation.
// A leading slash or any inner slash sets anchored, and a trailing slash sets dirOnly; the remaining pattern is split into parts on slashes.
//
// It returns the parsed rule, with raw kept verbatim, and a nil error on success.
// It fails with a zero ignoreRule when the pattern is empty after stripping or a segment other than ** is a malformed path.Match pattern.
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
	// A line of only !, /, or !/ has no pattern left and is reported as malformed.
	if line == "" {
		return ignoreRule{}, fmt.Errorf("empty pattern in %q", raw)
	}
	// A pattern with an inner slash, such as docs/build, matches only from this .gitignore's directory, not at any depth.
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

// match reports whether the rule applies to the given relative path.
//
// rel is slash-separated and relative to the rule's .gitignore directory; an empty rel reports false.
// Anchored rules must match from the first segment and unanchored ones from any segment, in both cases through the last segment.
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

// matchSegmentsAt recursively matches pattern segments against path segments.
//
// A terminal ** requires at least one remaining path segment, so foo/** targets descendants of foo rather than foo itself.
// Without that, foo itself would be ignored, and as an ignored ancestor it would block a later !foo/a from re-including foo/a.
//
// pat and seg are the rule parts and path segments, compared from pi and si; an inner ** spans zero or more segments, others use path.Match.
// It reports true when every part matches and seg is fully consumed, or when a terminal ** is reached with a segment left, and false otherwise.
func matchSegmentsAt(pat []string, pi int, seg []string, si int) bool {
	for pi < len(pat) {
		if pat[pi] == "**" {
			if pi == len(pat)-1 {
				return si < len(seg)
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

// trimUnescapedTrailingWhitespace strips trailing whitespace that is not backslash-escaped.
//
// line is one .gitignore line without its line ending; only trailing spaces and tabs are removed, and an escaping backslash is kept.
// It returns the trimmed line, which stops at the first escaped space or tab from the end and is empty when line holds only spaces and tabs.
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

// escaped reports whether the character at index is preceded by an odd number of backslashes.
// line is the text being scanned and index is a byte offset into it; backslashes are counted backwards from the byte before index.
func escaped(line string, index int) bool {
	backslashes := 0
	for i := index - 1; i >= 0 && line[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 1
}

// ancestorChain returns the directory ancestors of rel, from root down to its parent.
// The root is the empty string, so a top-level rel such as main.go gives a one-entry chain holding only the root.
func ancestorChain(rel string) []string {
	parts := strings.Split(rel, "/")
	out := []string{""}
	for i := 1; i < len(parts); i++ {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

// dirChain returns dir plus each of its ancestors, from root downward.
// The root is the empty string, and an empty dir or "." gives a chain holding only the root.
func dirChain(dir string) []string {
	if dir == "" || dir == "." {
		return []string{""}
	}
	parts := strings.Split(dir, "/")
	out := make([]string, 0, len(parts)+1)
	out = append(out, "")
	for i := 1; i <= len(parts); i++ {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

// parentDir returns the slash-separated directory containing rel.
// The result is empty when rel has no slash, meaning rel sits directly in the matcher root.
func parentDir(rel string) string {
	index := strings.LastIndex(rel, "/")
	if index < 0 {
		return ""
	}
	return rel[:index]
}

// relPathFrom returns rel rewritten relative to dir.
// rel comes back unchanged when dir is empty, meaning the root, or when rel does not start with dir and a slash.
func relPathFrom(dir, rel string) string {
	if dir == "" {
		return rel
	}
	return strings.TrimPrefix(rel, dir+"/")
}

// joinIgnorePath joins a directory and ignore file name with a slash separator.
//
// dir is a root-relative directory, empty for the root, and name is the file name, such as .gitignore.
// It returns name alone when dir is empty, and dir, a slash, and name otherwise.
func joinIgnorePath(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}
