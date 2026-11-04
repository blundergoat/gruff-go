// Package pathfilter validates and matches slash-separated repository paths.
//
// It supports glob-style patterns and a restricted trailing /** recursive suffix.
// Users reach it through paths.ignore or ignorePaths in .gruff-go.yaml, where Validate rejects a bad pattern when the config is parsed.
//
// Discovery uses the match helpers to decide which files a run skips, and FirstMatch also names the glob that skipped each one.
package pathfilter

import (
	"fmt"
	"path"
	"strings"
)

// Validate ensures a user-provided path pattern is well-formed and repo-relative.
//
// It returns an error when pattern is empty, starts with a slash, contains a backslash, or cleans to a drive-qualified path, the root or above.
// It also fails for more than one ** or one not used as a trailing /** suffix, or a pattern path.Match rejects; otherwise it returns nil.
func Validate(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("path pattern must not be empty")
	}
	if strings.HasPrefix(pattern, "/") {
		return fmt.Errorf("path pattern %q must be relative", pattern)
	}
	cleaned := path.Clean(pattern)
	// A pattern that still starts with a drive letter after cleaning, such as C:/src/**, is rejected on every platform, so its config cannot load.
	if len(cleaned) >= 2 && ((cleaned[0] >= 'A' && cleaned[0] <= 'Z') || (cleaned[0] >= 'a' && cleaned[0] <= 'z')) && cleaned[1] == ':' {
		return fmt.Errorf("path pattern %q must not use a Windows drive qualifier", pattern)
	}
	if strings.Contains(pattern, `\`) {
		return fmt.Errorf("path pattern %q must use slash separators", pattern)
	}
	// Checked after cleaning, so src/../../x is refused like ../x, and a pattern that cleans to the root, such as src/.., is refused too.
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("path pattern %q must stay inside the repository", pattern)
	}
	// Matches gives ** meaning only as a trailing /** suffix; anywhere else path.Match would read it as a plain *, so pkg/**/gen.go is refused.
	recursiveGlobs := strings.Count(pattern, "**")
	if recursiveGlobs > 1 || (recursiveGlobs == 1 && !strings.HasSuffix(pattern, "/**")) {
		return fmt.Errorf("path pattern %q may only use one ** as a trailing recursive suffix", pattern)
	}
	probe := pattern
	if strings.HasSuffix(pattern, "/**") {
		probe = strings.TrimSuffix(pattern, "/**") + "/*"
	}
	// A malformed glob in an ignore path, such as an unclosed character class, fails here and Validate wraps path.Match's error.
	if _, err := path.Match(probe, "probe"); err != nil {
		return fmt.Errorf("invalid path pattern %q: %w", pattern, err)
	}
	return nil
}

// MatchesAny reports whether any of the supplied patterns matches the relative path.
// Patterns are tried in order with Matches against rel until one matches; a nil or empty patterns slice reports false.
func MatchesAny(patterns []string, rel string) bool {
	matched, _ := FirstMatch(patterns, rel)
	return matched
}

// FirstMatch reports whether any pattern matches rel and returns the first matching pattern verbatim.
//
// Callers such as discovery and check-ignore use it to tell a consumer which configured glob excluded a path, not merely that one did.
// Patterns are tried in order, so the result is the earliest match; no match, or nil patterns, returns false and an empty pattern.
func FirstMatch(patterns []string, rel string) (matched bool, pattern string) {
	for _, candidate := range patterns {
		if Matches(candidate, rel) {
			return true, candidate
		}
	}
	return false, ""
}

// Matches reports whether the pattern matches the relative path.
//
// Both rel and pattern drop a leading ./ and rel is path-cleaned before matching.
// A pattern ending in / or /** matches rel equal to its prefix or below it; other patterns match via path.Match or an exact cleaned equality.
//
// path.Match never lets * cross a slash, so *.go matches only root-level files; a whole subtree needs a trailing / or /**.
func Matches(pattern string, rel string) bool {
	rel = path.Clean(strings.TrimPrefix(rel, "./"))
	pattern = strings.TrimPrefix(pattern, "./")
	if strings.HasSuffix(pattern, "/") {
		pattern += "**"
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return rel == prefix || strings.HasPrefix(rel, prefix+"/")
	}
	// path.Match's error is dropped: a malformed pattern that skipped Validate fails to match here and falls back to exact equality.
	if ok, _ := path.Match(pattern, rel); ok {
		return true
	}
	return rel == path.Clean(pattern)
}
