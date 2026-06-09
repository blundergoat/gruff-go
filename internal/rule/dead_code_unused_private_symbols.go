// Package rule defines gruff-go's rule registry and analysers.
// This file implements opt-in parser-only private type, var, and const dead-code candidates.
package rule

import (
	"fmt"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// UnusedPrivateTypeRule flags private named types that have no parser-visible references.
type UnusedPrivateTypeRule struct{}

// Definition declares the dead-code.unused-private-type candidate rule.
func (UnusedPrivateTypeRule) Definition() Definition {
	return Definition{
		ID:             "dead-code.unused-private-type",
		Title:          "Unused private type",
		Description:    "Flags package-private top-level types whose names are not referenced anywhere else in the same parsed package. Generated, test, vendor, and reflection-heavy packages are excluded so the parser-only candidate stays precision-first.",
		Pillar:         finding.PillarDeadCode,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Tags:           []string{"candidate", "cross-file", "dead-code"},
		Remediation:    "Delete the type if it is abandoned, or enable the rule only after confirming generated, reflective, and build-tagged references are not part of the package contract.",
	}
}

// AnalyzeProject emits candidate findings for unreferenced package-private types.
func (UnusedPrivateTypeRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	return unusedPrivateSymbolFindings(newPackageReferenceIndex(units), "type")
}

// UnusedPrivateVarRule flags private package variables that have no parser-visible references.
type UnusedPrivateVarRule struct{}

// Definition declares the dead-code.unused-private-var candidate rule.
func (UnusedPrivateVarRule) Definition() Definition {
	return Definition{
		ID:             "dead-code.unused-private-var",
		Title:          "Unused private var",
		Description:    "Flags package-private top-level variables whose names are not referenced anywhere else in the same parsed package. Test files, generated files, registration tables, blank identifiers, vendor paths, and reflection-heavy packages are excluded.",
		Pillar:         finding.PillarDeadCode,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Tags:           []string{"candidate", "cross-file", "dead-code"},
		Remediation:    "Delete the variable if it is abandoned, or keep the rule opt-in until parser-only evidence can prove indirect registration use is not involved.",
	}
}

// AnalyzeProject emits candidate findings for unreferenced package-private vars.
func (UnusedPrivateVarRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	return unusedPrivateSymbolFindings(newPackageReferenceIndex(units), "var")
}

// UnusedPrivateConstRule flags private package constants that have no parser-visible references.
type UnusedPrivateConstRule struct{}

// Definition declares the dead-code.unused-private-const candidate rule.
func (UnusedPrivateConstRule) Definition() Definition {
	return Definition{
		ID:             "dead-code.unused-private-const",
		Title:          "Unused private const",
		Description:    "Flags package-private top-level constants whose names are not referenced anywhere else in the same parsed package. Iota groups, multi-name const specs, test files, generated files, vendor paths, and reflection-heavy packages are excluded.",
		Pillar:         finding.PillarDeadCode,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Tags:           []string{"candidate", "cross-file", "dead-code"},
		Remediation:    "Delete the constant if it is abandoned, or leave the candidate rule opt-in where grouped constants or build tags make parser-only certainty too weak.",
	}
}

// AnalyzeProject emits candidate findings for unreferenced package-private consts.
func (UnusedPrivateConstRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	return unusedPrivateSymbolFindings(newPackageReferenceIndex(units), "const")
}

// unusedPrivateSymbolFindings emits findings for the selected declaration kind in deterministic package order.
func unusedPrivateSymbolFindings(index packageReferenceIndex, kind string) []finding.Finding {
	findings := []finding.Finding{}
	for _, group := range index.ordered {
		if group.skipForPrecision {
			continue
		}
		for _, decl := range privateSymbolDeclsByKind(group, kind) {
			if !group.unreferenced(decl) {
				continue
			}
			position := decl.unit.FileSet.Position(decl.pos)
			findings = append(findings, finding.Finding{
				Message:  fmt.Sprintf("private %s %q is not referenced in package %q (candidate)", kind, decl.name, group.key.packageName),
				File:     decl.unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   decl.name,
				Metadata: map[string]any{"candidate": true, "kind": kind, "package": group.key.packageName},
			})
		}
	}
	return findings
}

// privateSymbolDeclsByKind selects the declaration list used by one candidate rule.
func privateSymbolDeclsByKind(group *packageReferenceGroup, kind string) []packageSymbolDecl {
	switch kind {
	case "type":
		return group.privateTypes
	case "var":
		return group.privateVars
	case "const":
		return group.privateConsts
	default:
		return nil
	}
}
