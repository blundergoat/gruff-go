package rule

import (
	"bufio"
	"fmt"
	"go/ast"
	"strings"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

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

type acronymSpec struct {
	lower     string
	canonical string
}

type acronymIssue struct {
	token     string
	canonical string
}

// AcronymCaseRule flags mixed-case Go initialisms such as HttpClient.
type AcronymCaseRule struct {
	Acronyms              []string
	Allow                 []string
	AcceptedAbbreviations []string
}

func (r AcronymCaseRule) Definition() Definition {
	return Definition{
		ID:             "naming.acronym-case",
		Title:          "Acronym case",
		Description:    "Flags identifiers that spell configured Go initialisms with mixed casing.",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Tags:           []string{"go-style", "naming", "opt-in"},
		Options:        map[string]any{"acronyms": defaultAcronymNames, "allow": []string{}},
		Remediation:    "Use all-caps initialisms in exported names and consistently cased initialisms in unexported names.",
	}
}

func (r AcronymCaseRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || hasGeneratedHeader(unit.Source) {
		return nil
	}
	specs := r.acronymSpecs()
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
		switch item := node.(type) {
		case *ast.TypeSpec:
			check(item.Name)
		case *ast.FuncDecl:
			check(item.Name)
		case *ast.ValueSpec:
			for _, ident := range item.Names {
				check(ident)
			}
		case *ast.Field:
			for _, ident := range item.Names {
				check(ident)
			}
		}
		return true
	})
	return findings
}

func (r AcronymCaseRule) acronymSpecs() []acronymSpec {
	source := r.Acronyms
	if len(source) == 0 {
		source = defaultAcronymNames
	}
	seen := map[string]bool{}
	specs := make([]acronymSpec, 0, len(source))
	for _, item := range source {
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

func firstAcronymIssue(name string, specs []acronymSpec, accepted map[string]bool) (acronymIssue, bool) {
	for _, token := range splitIdentifierTokens(name) {
		lower := strings.ToLower(token)
		for _, spec := range specs {
			if lower != spec.lower || accepted[lower] {
				continue
			}
			if token == spec.canonical || token == lower {
				continue
			}
			return acronymIssue{token: token, canonical: spec.canonical}, true
		}
	}
	return acronymIssue{}, false
}

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

func hasGeneratedHeader(source string) bool {
	scanner := bufio.NewScanner(strings.NewReader(source))
	for index := 0; index < 10 && scanner.Scan(); index++ {
		line := scanner.Text()
		if strings.Contains(line, "Code generated") || strings.Contains(line, "DO NOT EDIT") {
			return true
		}
	}
	return false
}

func exactStringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		if value != "" {
			out[value] = true
		}
	}
	return out
}

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
