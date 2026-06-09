// Package source discovers analyzable Go and text/config source files.
// This file classifies which directories and files are ignored by default,
// separate from .gitignore matching and config paths.ignore patterns.
package source

import "strings"

// alwaysIgnoredDir reports VCS and tool-metadata directories that are unconditionally skipped.
func alwaysIgnoredDir(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	for _, part := range parts {
		switch part {
		case ".git", ".hg", ".svn":
			return "vcs", true
		case ".agents", ".claude", ".codex", ".goat-flow":
			return "non-application-metadata", true
		}
	}
	return githubMetadataDecision(rel)
}

// alwaysIgnoredFile reports files that live inside unconditionally skipped metadata directories.
func alwaysIgnoredFile(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	for _, part := range parts[:len(parts)-1] {
		switch part {
		case ".agents", ".claude", ".codex", ".goat-flow":
			return "non-application-metadata", true
		}
	}
	return githubMetadataDecision(rel)
}

// githubMetadataDecision classifies .github paths. The .github tree is tool
// metadata and is skipped by default, with one carve-out: the workflows subtree
// is analysable so the CI/workflow security rules can inspect GitHub Actions
// YAML. The .github directory itself is kept (so the walk can descend to reach
// workflows), .github/workflows and everything beneath it are kept, and every
// other .github path is reported as non-application metadata. Paths without a
// .github component fall through to the caller's other checks.
func githubMetadataDecision(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		if part != ".github" {
			continue
		}
		if i == len(parts)-1 {
			return "", false
		}
		if parts[i+1] == "workflows" {
			return "", false
		}
		return "non-application-metadata", true
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
