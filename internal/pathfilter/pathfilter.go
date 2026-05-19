// Package pathfilter validates and matches slash-separated repository paths.
// It supports glob-style patterns and a restricted trailing /** recursive suffix.
package pathfilter

import (
	"fmt"
	"path"
	"strings"
)

// Validate ensures a user-provided path pattern is well-formed and repo-relative.
func Validate(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("path pattern must not be empty")
	}
	if strings.HasPrefix(pattern, "/") {
		return fmt.Errorf("path pattern %q must be relative", pattern)
	}
	cleaned := path.Clean(pattern)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("path pattern %q must stay inside the repository", pattern)
	}
	if strings.Contains(pattern, "**") && !strings.HasSuffix(pattern, "/**") {
		return fmt.Errorf("path pattern %q may only use ** as a trailing recursive suffix", pattern)
	}
	probe := pattern
	if strings.HasSuffix(pattern, "/**") {
		probe = strings.TrimSuffix(pattern, "/**") + "/*"
	}
	if _, err := path.Match(probe, "probe"); err != nil {
		return fmt.Errorf("invalid path pattern %q: %w", pattern, err)
	}
	return nil
}

// MatchesAny reports whether any of the supplied patterns matches the relative path.
func MatchesAny(patterns []string, rel string) bool {
	for _, pattern := range patterns {
		if Matches(pattern, rel) {
			return true
		}
	}
	return false
}

// Matches reports whether the pattern matches the relative path.
func Matches(pattern string, rel string) bool {
	rel = path.Clean(strings.TrimPrefix(rel, "./"))
	pattern = strings.TrimPrefix(pattern, "./")
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return rel == prefix || strings.HasPrefix(rel, prefix+"/")
	}
	if ok, _ := path.Match(pattern, rel); ok {
		return true
	}
	return rel == path.Clean(pattern)
}
