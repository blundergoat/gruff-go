// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds the parser-only go.mod checks: it reads replace directives as text and never runs go list or queries a module proxy.
// They report through dependency.go-mod-local-replace, which is opt-in, and dependency.go-mod-remote-replace, which default scans run.
package rule

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// goModReplace records one replace directive as goModReplaceDirectives parsed it from a go.mod line.
//
// It holds the 1-indexed line number and the replacement target, which is the first field after the arrow.
// The local flag is isLocalReplacePath's verdict on that target; false routes the directive to the remote-replace rule.
type goModReplace struct {
	line        int
	replacement string
	local       bool
}

// GoModLocalReplaceRule is the opt-in dependency.go-mod-local-replace rule for go.mod replace directives that point at a local path.
//
// A local path may be missing in other clones or CI, though a relative path to a module committed in the same repository still resolves.
// The rule flags the directive either way, because it reads only the go.mod text and never checks where the path leads.
type GoModLocalReplaceRule struct{}

// Definition declares the dependency.go-mod-local-replace rule for go.mod replace directives that point a module at a local filesystem path.
// It returns the fixed definition: advisory severity, high confidence, the security pillar, and DefaultEnabled false, so the rule is opt-in.
func (GoModLocalReplaceRule) Definition() Definition {
	return Definition{
		ID:             "dependency.go-mod-local-replace",
		Title:          "Local go.mod replace directive",
		Description:    "Flags go.mod replace directives that redirect a dependency to a local filesystem path (./…, ../…, or an absolute path). Local replacements do not reproduce for other clones or CI and usually indicate in-progress local development that should not ship.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: false,
		Tags:           []string{"dependency", "security", "supply-chain"},
		Remediation:    "Remove the local replace before shipping and depend on a published module version, or vendor the dependency explicitly.",
	}
}

// AnalyzeUnit emits findings for local replace directives in go.mod.
//
// It returns nil unless the unit file is named go.mod; otherwise it returns one finding per directive whose target isLocalReplacePath accepts.
// Each finding records the directive's 1-indexed line and its replacement target; the slice is empty when no target is classified local.
func (GoModLocalReplaceRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if !isGoModFile(unit.File.Path) {
		return nil
	}
	findings := []finding.Finding{}
	for _, directive := range goModReplaceDirectives(unit.Source) {
		// Non-local targets belong to dependency.go-mod-remote-replace, so with both rules on each directive is reported exactly once.
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

// GoModRemoteReplaceRule is the default-on dependency.go-mod-remote-replace rule for targets isLocalReplacePath does not call local.
//
// That includes a different module path or another version of the same module, and either one silently swaps a dependency's source.
// Every target isLocalReplacePath rejects lands here, including a bare dot-dot target, so some local paths surface as remote replaces.
type GoModRemoteReplaceRule struct{}

// Definition declares the dependency.go-mod-remote-replace rule for replace targets that isLocalReplacePath does not recognise as local.
// It returns the fixed definition: advisory severity, high confidence, the security pillar, and DefaultEnabled true, so default scans run it.
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
//
// It returns nil unless the unit file is named go.mod; otherwise it returns one finding per directive whose target isLocalReplacePath rejects.
// Each finding records the directive's 1-indexed line and its replacement target; the slice is empty when every target is classified local.
func (GoModRemoteReplaceRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if !isGoModFile(unit.File.Path) {
		return nil
	}
	findings := []finding.Finding{}
	for _, directive := range goModReplaceDirectives(unit.Source) {
		// Local targets belong to the opt-in dependency.go-mod-local-replace, so they stay silent here even when that rule is off.
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

// isGoModFile reports whether path names a file called go.mod, with backslashes treated as separators.
// False makes both replace rules skip the unit, so a renamed copy such as go.mod.bak is never checked.
func isGoModFile(path string) bool {
	return filepath.Base(strings.ReplaceAll(path, "\\", "/")) == "go.mod"
}

// goModReplaceDirectives parses the replace directives in go.mod source by finding the lines that contain =>, which only replace uses.
//
// Both the single-line and the block replace form put one => on each directive's line, so each directive yields one entry.
// A commented-out replace, or an arrow inside a trailing comment, produces no finding because each line is cut at its first double slash.
//
// It returns one entry per comment-stripped line with a field after =>, in source order, holding the 1-indexed line and that first field.
// Each entry also records whether isLocalReplacePath classifies the target as local; the slice is empty, not nil, when no line qualifies.
//
// The field is unquoted only when it is a valid quoted literal, so a quoted path containing spaces is kept as its truncated first piece.
// That piece keeps its opening quote, so a quoted local path with spaces is classified remote and reported by the remote-replace rule.
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
		// A half-typed replace that ends at => has no target, so neither replace rule reports it.
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

// unquoteGoModField removes the optional quotes go.mod allows around a path or module field.
//
// That lets a quoted target such as "../lib" count as local; with its leading quote kept it would be reported as a remote replace.
// It returns the unquoted text when field is a valid Go quoted literal, such as a double-quoted or backquoted string, and field unchanged otherwise.
func unquoteGoModField(field string) string {
	if unquoted, err := strconv.Unquote(field); err == nil {
		return unquoted
	}
	return field
}

// isLocalReplacePath reports whether a replace target takes one of the local filesystem path forms it recognises, rather than a module path.
//
// It reports true only for these forms.
//   - the single-dot target on its own.
//   - a ./ or ../ prefix.
//   - a leading slash, as in an absolute Unix path.
//   - one byte, then a colon and a slash or backslash, as in the Windows path C:\lib.
//
// Anything else reports false and goes to the remote-replace rule, including a bare dot-dot target and backslash forms such as ..\lib.
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
