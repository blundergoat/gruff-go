// Package source discovers analyzable Go and text/config source files.
//
// This file classifies which directories and files are ignored by default, separate from .gitignore matching and config paths.ignore patterns.
// Each classifier returns a short reason, such as "vcs", "dependency" or "generated", with true when it ignores the path.
package source

import "strings"

// alwaysIgnoredDir reports VCS internals that are unconditionally skipped.
//
// rel is a slash-separated path, possibly absolute; every segment, the last included, is matched exactly against .git, .hg and .svn.
// It returns the reason "vcs" and true on a match, or an empty reason and false when no segment names a VCS directory.
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
//
// rel is a slash-separated file path, possibly absolute; every segment but the file name is matched exactly against .git, .hg and .svn.
// It returns the reason "vcs" and true on a match, or an empty reason and false when no directory segment names a VCS directory.
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
//
// rel is a slash-separated path, possibly absolute; its segments are compared with exact case, and the first match decides the reason.
// It returns true with "dependency" for node_modules, "build-output" for build or coverage, and "local-tooling" for .fleet, .idea or .vscode.
// When no segment matches, the result is an empty reason and false.
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
// It always returns an empty reason and false, whatever the name, so it never marks a file as skipped.
func fallbackIgnoredFile(_ string) (string, bool) {
	return "", false
}

// minifiedReason is the reason a minified file such as `config.min.json` is skipped with.
const minifiedReason = "generated"

// thirdPartyDir reports the skip reason of the outermost directory on rel named for third-party copies or dist.
//
// These names are skipped at any depth, even under a governing .gitignore (FAMILY-CONTRACT.md section 7, amended by precision-floor M04).
// The build and coverage names stay in fallbackIgnoredDir, which still defers to a .gitignore.
//
// Names compare over ASCII case, so Vendor/ matches as it does in every port; a file named dist never matches, since a file is not a directory.
// isDir is true when rel names a directory, whose own name is then checked too; when false, the last segment is dropped as a file name.
//
// The reason is "dependency" for vendor, vendors, third_party, third-party or bower_components, and "build-output" for dist, each with true.
// It returns an empty reason and false when no checked segment matches.
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

// minifiedFile reports the "generated" reason for a base name with .min. directly before its final extension, such as config.min.json.
//
// Names such as app.min.js.map and admin.mini.json do not match.
// rel is a slash-separated path whose base name, after the last slash, is matched with ASCII letters lowered, so APP.MIN.JS matches too.
// It returns an empty reason and false for any other base name, including one ending in a dot or with no dot after its first character.
func minifiedFile(rel string) (string, bool) {
	name := asciiLower(rel[strings.LastIndex(rel, "/")+1:])
	dot := strings.LastIndex(name, ".")
	if dot <= 0 || dot == len(name)-1 || !strings.HasSuffix(name[:dot], ".min") {
		return "", false
	}
	return minifiedReason, true
}

// asciiLower lowercases A-Z only, so thİrd_party (U+0130), which strings.ToLower folds to third_party, stays unmatched, as it does in every port.
//
// value may hold any text; only A to Z become lowercase and other runes pass through, but strings.Map turns invalid UTF-8 bytes into U+FFFD.
// It returns the lowered string, which is empty when value is empty.
func asciiLower(value string) string {
	return strings.Map(func(character rune) rune {
		if character >= 'A' && character <= 'Z' {
			return character + ('a' - 'A')
		}
		return character
	}, value)
}
