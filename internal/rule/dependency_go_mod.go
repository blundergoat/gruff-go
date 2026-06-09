// Package rule defines gruff-go's rule registry and analysers.
// This file implements parser-only Go-module dependency-posture checks that scan
// go.mod replace directives as text (no go list, no proxy queries).
package rule

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// goModReplace records one parsed `replace … => …` directive: the 1-indexed line,
// the replacement target (right-hand side), and whether that target is a local
// filesystem path rather than a module path.
type goModReplace struct {
	line        int
	replacement string
	local       bool
}

// GoModLocalReplaceRule flags go.mod replace directives that redirect a module to
// a local filesystem path, which does not reproduce outside the author's machine.
type GoModLocalReplaceRule struct{}

// Definition declares the dependency.go-mod-local-replace rule for go.mod
// replace directives that redirect a module to a local filesystem path.
func (GoModLocalReplaceRule) Definition() Definition {
	return Definition{
		ID:             "dependency.go-mod-local-replace",
		Title:          "Local go.mod replace directive",
		Description:    "Flags go.mod replace directives that redirect a dependency to a local filesystem path (./…, ../…, or an absolute path). Local replacements do not reproduce for other clones or CI and usually indicate in-progress local development that should not ship.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"dependency", "security", "supply-chain"},
		Remediation:    "Remove the local replace before shipping and depend on a published module version, or vendor the dependency explicitly.",
	}
}

// AnalyzeUnit emits findings for local replace directives in go.mod.
func (GoModLocalReplaceRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if !isGoModFile(unit.File.Path) {
		return nil
	}
	findings := []finding.Finding{}
	for _, directive := range goModReplaceDirectives(unit.Source) {
		if !directive.local {
			continue
		}
		findings = append(findings, finding.Finding{
			Message:  "go.mod replaces a module with a local filesystem path",
			File:     unit.File.Path,
			Location: &finding.Location{Line: directive.line},
			Metadata: map[string]any{"replacement": directive.replacement},
		})
	}
	return findings
}

// GoModRemoteReplaceRule flags go.mod replace directives that redirect a module
// to a different remote module, which silently swaps a dependency's source.
type GoModRemoteReplaceRule struct{}

// Definition declares the dependency.go-mod-remote-replace rule for go.mod
// replace directives that swap a module for a different remote module.
func (GoModRemoteReplaceRule) Definition() Definition {
	return Definition{
		ID:             "dependency.go-mod-remote-replace",
		Title:          "Remote go.mod replace directive",
		Description:    "Flags go.mod replace directives that redirect a dependency to a different remote module path or version. Remote replacements silently swap a dependency's source and should be reviewed as a supply-chain decision.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"dependency", "security", "supply-chain"},
		Remediation:    "Confirm the replacement module and version are trusted and intentional, and prefer pinning the original module to a vetted release where possible.",
	}
}

// AnalyzeUnit emits findings for remote replace directives in go.mod.
func (GoModRemoteReplaceRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if !isGoModFile(unit.File.Path) {
		return nil
	}
	findings := []finding.Finding{}
	for _, directive := range goModReplaceDirectives(unit.Source) {
		if directive.local {
			continue
		}
		findings = append(findings, finding.Finding{
			Message:  "go.mod replaces a module with a remote module",
			File:     unit.File.Path,
			Location: &finding.Location{Line: directive.line},
			Metadata: map[string]any{"replacement": directive.replacement},
		})
	}
	return findings
}

// isGoModFile reports whether the path is a go.mod module file.
func isGoModFile(path string) bool {
	return filepath.Base(strings.ReplaceAll(path, "\\", "/")) == "go.mod"
}

// goModReplaceDirectives parses the replace directives in go.mod source. It scans
// for `=>` lines, which only replace directives use, and classifies the
// replacement target as a local path or a remote module. Both the single-line and
// block (`replace ( … )`) forms produce one `=>` line per directive. The `//`
// comment is stripped from each line first, so a commented-out replace or an
// arrow that appears inside a trailing comment does not produce a finding.
func goModReplaceDirectives(source string) []goModReplace {
	out := []goModReplace{}
	for index, line := range strings.Split(source, "\n") {
		code := line
		if comment := strings.Index(code, "//"); comment >= 0 {
			code = code[:comment]
		}
		arrow := strings.Index(code, "=>")
		if arrow < 0 {
			continue
		}
		fields := strings.Fields(code[arrow+2:])
		if len(fields) == 0 {
			continue
		}
		target := unquoteGoModField(fields[0])
		out = append(out, goModReplace{
			line:        index + 1,
			replacement: target,
			local:       isLocalReplacePath(target),
		})
	}
	return out
}

// unquoteGoModField removes the optional double quotes go.mod allows around a
// path or module field, so a quoted local replace target such as "../lib" is
// classified by its real path rather than the leading quote (which would
// otherwise misroute it to the remote-replace rule and remediation).
func unquoteGoModField(field string) string {
	if unquoted, err := strconv.Unquote(field); err == nil {
		return unquoted
	}
	return field
}

// isLocalReplacePath reports whether a replace target is a local filesystem path
// (relative, rooted, or a Windows drive path) rather than a module path.
func isLocalReplacePath(target string) bool {
	switch {
	case target == ".",
		strings.HasPrefix(target, "./"),
		strings.HasPrefix(target, "../"),
		strings.HasPrefix(target, "/"):
		return true
	}
	if len(target) >= 3 && target[1] == ':' && (target[2] == '\\' || target[2] == '/') {
		return true
	}
	return false
}
