// Package rule defines the checks users see in gruff-go scan results.
//
// This file keeps Go initialisms consistent in names such as userID and parseURL.
// It reports declaration drift in hand-authored files, and in generated files only when Context.IncludeIgnored is set.
package rule

import (
	"fmt"
	"go/ast"
	"strings"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// defaultAcronymNames lists the Go initialisms enforced by default.
//
// A non-empty Acronyms list on AcronymCaseRule replaces it rather than adding to it.
// Definition publishes it as the default of the acronyms option.
var defaultAcronymNames = []string{
	"HTTP",
	"URL",
	"JSON",
	"ID",
	"XML",
	"API",
	"JWT",
	"AWS",
	"OAUTH",
	"CSS",
	"HTML",
	"YAML",
	"SARIF",
	"ASCII",
	"SQL",
	"CLI",
	"TCP",
	"UDP",
	"TLS",
	"SSL",
	"DNS",
	"IP",
	"GPU",
	"CPU",
	"OS",
}

// acronymSpec pairs a lowercased lookup form of an acronym with its canonical all-caps spelling.
type acronymSpec struct {
	lower     string
	canonical string
}

// acronymIssue records a token from an identifier that mis-cases a configured acronym.
type acronymIssue struct {
	token     string
	canonical string
}

// AcronymCaseRule finds mixed-case initialisms in Go declarations for the naming.acronym-case rule.
//
// Users enable it when a codebase wants names such as userID and parseURL; it is off by default.
// Generated files are skipped unless Context.IncludeIgnored is set, while exact names in Allow stay exempt.
type AcronymCaseRule struct {
	// Acronyms overrides the default initialism list (HTTP, URL, ID, ...) the rule enforces.
	Acronyms []string
	// Allow lists identifiers that are exempt from acronym-case checking by exact name match.
	Allow []string
	// AcceptedAbbreviations exempts identifier tokens that match an entry, ignoring case and surrounding whitespace, from acronym-case findings.
	AcceptedAbbreviations []string
}

// Definition declares the naming.acronym-case rule that enforces consistent casing for HTTP, URL, ID, JSON, and the rest of the Go initialism set.
// It returns the rule's metadata: off by default, advisory at medium confidence, with defaultAcronymNames and an empty allow list as options.
func (r AcronymCaseRule) Definition() Definition {
	return Definition{
		ID:             "naming.acronym-case",
		Title:          "Acronym case",
		Description:    "Flags identifiers that spell configured Go initialisms with mixed casing.",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Tags:           []string{"go-style", "naming"},
		Options:        map[string]any{"acronyms": defaultAcronymNames, "allow": []string{}},
		Remediation:    "Use Go's canonical all-caps initialism spelling within identifiers, such as userID and parseURL.",
		FalsePositiveShapes: []FalsePositiveShape{{
			Shape:      "A hand-written binding, framework hook, or external API may require a declaration whose name uses non-Go initialism casing.",
			Mitigation: "Add the exact required identifier to rules.naming.acronym-case.options.allow, or keep generated bindings marked as generated code.",
		}},
	}
}

// AnalyzeUnit walks the unit and emits findings for identifiers that mis-case configured initialisms.
//
// It returns nil when unit has no AST or FileSet, when shouldSkipGeneratedUnit skips it under ctx, or when no acronym spec remains.
// Otherwise it checks declared type, func, var, const, field and parameter names, skipping _ and exact Allow entries.
// It returns one finding per mis-cased name with the token and canonical acronym in its metadata, or an empty non-nil slice when none match.
func (r AcronymCaseRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || shouldSkipGeneratedUnit(unit, ctx) {
		return nil
	}
	specs := r.acronymSpecs()
	// A list of only blank acronyms leaves no spec, so the rule reports nothing rather than falling back to the defaults.
	if len(specs) == 0 {
		return nil
	}
	allow := exactStringSet(r.Allow)
	accepted := lowerStringSet(r.AcceptedAbbreviations)
	findings := []finding.Finding{}
	check := func(ident *ast.Ident) {
		if ident == nil || ident.Name == "_" || allow[ident.Name] {
			return
		}
		issue, ok := firstAcronymIssue(ident.Name, specs, accepted)
		if !ok {
			return
		}
		position := unit.FileSet.Position(ident.NamePos)
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("identifier %q uses mixed-case acronym %q; prefer %q", ident.Name, issue.token, issue.canonical),
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Symbol:   ident.Name,
			Metadata: map[string]any{
				"identifier": ident.Name,
				"token":      issue.token,
				"acronym":    issue.canonical,
			},
		})
	}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		// Only declarations are checked, so code that merely calls or references a mis-cased name declared elsewhere gets no finding.
		switch item := node.(type) {
		case *ast.TypeSpec:
			check(item.Name)
		case *ast.FuncDecl:
			check(item.Name)
		case *ast.ValueSpec:
			for _, ident := range item.Names {
				check(ident)
			}
		// Mis-cased names of struct fields, interface methods, receivers, type parameters, parameters and named results can produce findings.
		case *ast.Field:
			for _, ident := range item.Names {
				check(ident)
			}
		}
		return true
	})
	return findings
}

// acronymSpecs returns the deduplicated, canonicalised acronym specs the rule will enforce.
// It uses defaultAcronymNames when Acronyms is empty, trims and uppercases each entry, and gives an empty slice when every entry is blank.
func (r AcronymCaseRule) acronymSpecs() []acronymSpec {
	acronymNames := r.Acronyms
	if len(acronymNames) == 0 {
		acronymNames = defaultAcronymNames
	}
	seen := map[string]bool{}
	specs := make([]acronymSpec, 0, len(acronymNames))
	for _, item := range acronymNames {
		canonical := strings.ToUpper(strings.TrimSpace(item))
		if canonical == "" {
			continue
		}
		lower := strings.ToLower(canonical)
		if seen[lower] {
			continue
		}
		seen[lower] = true
		specs = append(specs, acronymSpec{lower: lower, canonical: canonical})
	}
	return specs
}

// firstAcronymIssue returns the first token in name that mis-cases a configured acronym, if any.
//
// A token in name counts when its lowercase form matches a spec in specs and is not a key in accepted,
// and the token itself is neither that spec's canonical spelling nor all-lowercase.
// When no token qualifies it returns a zero acronymIssue and false.
func firstAcronymIssue(name string, specs []acronymSpec, accepted map[string]bool) (acronymIssue, bool) {
	for _, token := range splitIdentifierTokens(name) {
		lower := strings.ToLower(token)
		for _, spec := range specs {
			if lower != spec.lower || accepted[lower] {
				continue
			}
			// An all-lowercase token passes, so httpClient and user_id give no finding; only mixed spellings such as Http or Id are reported.
			if token == spec.canonical || token == lower {
				continue
			}
			return acronymIssue{token: token, canonical: spec.canonical}, true
		}
	}
	return acronymIssue{}, false
}

// splitIdentifierTokens breaks an identifier into camel-case or snake-case sub-tokens.
//
// It splits name at underscores, which are dropped, at each lowercase-to-uppercase or letter-digit change,
// and before the last capital of an uppercase run followed by lowercase, so HTTPServer gives HTTP and Server.
// It returns the tokens in order, or an empty non-nil slice when name is empty or only underscores.
func splitIdentifierTokens(name string) []string {
	runes := []rune(name)
	tokens := []string{}
	start := 0
	flush := func(end int) {
		if start < end {
			tokens = append(tokens, string(runes[start:end]))
		}
	}
	for index, current := range runes {
		if current == '_' {
			flush(index)
			start = index + 1
			continue
		}
		if index == start {
			continue
		}
		previous := runes[index-1]
		boundary := (unicode.IsLower(previous) || unicode.IsDigit(previous)) && unicode.IsUpper(current)
		boundary = boundary || (unicode.IsLetter(previous) && unicode.IsDigit(current))
		boundary = boundary || (unicode.IsDigit(previous) && unicode.IsLetter(current))
		if !boundary && unicode.IsUpper(previous) && unicode.IsUpper(current) && index+1 < len(runes) && unicode.IsLower(runes[index+1]) {
			boundary = true
		}
		if boundary {
			flush(index)
			start = index
		}
	}
	flush(len(runes))
	return tokens
}

// exactStringSet returns a set keyed by the unmodified, non-empty entries of values.
func exactStringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		if value != "" {
			out[value] = true
		}
	}
	return out
}

// lowerStringSet returns a set keyed by trimmed, lowercased entries of values.
func lowerStringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			out[strings.ToLower(trimmed)] = true
		}
	}
	return out
}
