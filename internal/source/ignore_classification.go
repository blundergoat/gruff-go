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
		case "node_modules":
			return "dependency", true
		case "build", "coverage":
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

// minifiedReason is the reason a minified file such as `config.min.json` is skipped with.
const minifiedReason = "generated"

// thirdPartyDir reports the skip reason of the outermost directory on rel named for third-party copies or `dist`, which
// is skipped at any depth even under a governing .gitignore (FAMILY-CONTRACT.md section 7, amended by precision-floor
// M04). `build` and `coverage` stay in the fallback above, which still defers to a .gitignore.
//
// Names compare over ASCII case, so `Vendor/` matches as it does in every port. A file's own name is not a
// directory, so a file named `dist` never matches.
func thirdPartyDir(rel string, isDir bool) (string, bool) {
	parts := strings.Split(rel, "/")
	if !isDir {
		parts = parts[:len(parts)-1]
	}
	for _, part := range parts {
		switch asciiLower(part) {
		case "vendor", "vendors", "third_party", "third-party", "bower_components":
			return "dependency", true
		case "dist":
			return "build-output", true
		}
	}
	return "", false
}

// minifiedFile reports the generated reason for a base name with `.min.` directly before its final extension, such as
// `config.min.json`;
// `app.min.js.map` and `admin.mini.json` do not match.
func minifiedFile(rel string) (string, bool) {
	name := asciiLower(rel[strings.LastIndex(rel, "/")+1:])
	dot := strings.LastIndex(name, ".")
	if dot <= 0 || dot == len(name)-1 || !strings.HasSuffix(name[:dot], ".min") {
		return "", false
	}
	return minifiedReason, true
}

// asciiLower lowercases A-Z only, so `thİrd_party` (U+0130), which strings.ToLower folds to `third_party`, stays
// unmatched, as it does in every port.
func asciiLower(value string) string {
	return strings.Map(func(character rune) rune {
		if character >= 'A' && character <= 'Z' {
			return character + ('a' - 'A')
		}
		return character
	}, value)
}
