// Package source discovers analyzable Go and text/config source files.
// This file classifies which directories and files are ignored by default,
// separate from .gitignore matching and config paths.ignore patterns.
package source

import "strings"

// alwaysIgnoredDir reports VCS internals that are unconditionally skipped.
func alwaysIgnoredDir(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	for _, part := range parts {
		if part == ".git" || part == ".hg" || part == ".svn" {
			return "vcs", true
		}
	}
	return "", false
}

// alwaysIgnoredFile reports files that live inside unconditionally skipped VCS internals.
func alwaysIgnoredFile(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	for _, part := range parts[:len(parts)-1] {
		if part == ".git" || part == ".hg" || part == ".svn" {
			return "vcs", true
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
		case ".fleet", ".idea", ".vscode":
			return "local-tooling", true
		}
	}
	return "", false
}

// fallbackIgnoredFile is a placeholder for future filename-based fallback skips.
func fallbackIgnoredFile(_ string) (string, bool) {
	return "", false
}
