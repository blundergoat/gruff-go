// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements opt-in parser-only private type, var, and const dead-code candidates.
// Each rule is off by default; once enabled, a finding names a top-level declaration that nothing else in its package mentions.
package rule

import (
	"fmt"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// UnusedPrivateTypeRule flags private named types that have no parser-visible references.
//
// It backs dead-code.unused-private-type, off by default, and treats only names starting with a lowercase letter as private.
// Findings are marked (candidate) because a reference in a file excluded from the scan can still count in a real build.
type UnusedPrivateTypeRule struct{}

// Definition declares the dead-code.unused-private-type candidate rule.
// It returns a parser-capability Definition, disabled by default at advisory severity and medium confidence, tagged as a cross-file candidate.
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
		Remediation:    "Delete the type if nothing uses it. If it is referenced only from generated code, through reflection, or from a file behind a build tag, keep it and accept this finding in the baseline.",
	}
}

// AnalyzeProject emits candidate findings for unreferenced package-private types.
//
// It indexes units by package and returns a finding for each top-level type declared outside test files whose name
// starts with a lowercase letter and appears only once in its package; an unexported name starting with an underscore is skipped.
//
// A package contributes no findings when shouldSkipGeneratedUnit skips one of its units given ctx, or one is a vendor path or imports reflect.
// An empty result can also mean every candidate was excluded, not only that every private type is referenced.
func (UnusedPrivateTypeRule) AnalyzeProject(units []parser.Unit, ctx Context) []finding.Finding {
	return unusedPrivateSymbolFindings(newPackageReferenceIndex(units, ctx), "type")
}

// UnusedPrivateVarRule flags private package variables that have no parser-visible references.
//
// It backs dead-code.unused-private-var, off by default, and treats only names starting with a lowercase letter as private.
// Findings are marked (candidate) because a reference in a file excluded from the scan can still count in a real build.
type UnusedPrivateVarRule struct{}

// Definition declares the dead-code.unused-private-var candidate rule.
// It returns a parser-capability Definition, disabled by default at advisory severity and medium confidence, tagged as a cross-file candidate.
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
		Remediation:    "Delete the variable if nothing reads it. If it is used only through indirect registration, reflection, or a file behind a build tag, keep it and accept this finding in the baseline.",
	}
}

// AnalyzeProject emits candidate findings for unreferenced package-private vars.
//
// It indexes units by package and returns a finding for each top-level var declared outside test files whose name
// starts with a lowercase letter and appears only once in its package; an unexported name starting with an underscore is skipped.
//
// Blank names and var specs that isRegistrationValueSpec matches are never reported.
// A package contributes no findings when shouldSkipGeneratedUnit skips one of its units given ctx, or one is a vendor path or imports reflect.
// An empty result can also mean every candidate was excluded, not only that every private var is referenced.
func (UnusedPrivateVarRule) AnalyzeProject(units []parser.Unit, ctx Context) []finding.Finding {
	return unusedPrivateSymbolFindings(newPackageReferenceIndex(units, ctx), "var")
}

// UnusedPrivateConstRule flags private package constants that have no parser-visible references.
//
// It backs dead-code.unused-private-const, off by default, and treats only names starting with a lowercase letter as private.
// Findings are marked (candidate) because a reference in a file excluded from the scan can still count in a real build.
type UnusedPrivateConstRule struct{}

// Definition declares the dead-code.unused-private-const candidate rule.
// It returns a parser-capability Definition, disabled by default at advisory severity and medium confidence, tagged as a cross-file candidate.
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
		Remediation:    "Delete the constant if nothing uses it. If it is used from a file behind a build tag, or kept on purpose as part of a constant group, keep it and accept this finding in the baseline.",
	}
}

// AnalyzeProject emits candidate findings for unreferenced package-private consts.
//
// It indexes units by package and returns a finding for each top-level const declared outside test files whose name
// starts with a lowercase letter and appears only once in its package; an unexported name starting with an underscore is skipped.
//
// Const groups that use iota and specs declaring more than one name are never reported.
// A package contributes no findings when shouldSkipGeneratedUnit skips one of its units given ctx, or one is a vendor path or imports reflect.
// An empty result can also mean every candidate was excluded, not only that every private const is referenced.
func (UnusedPrivateConstRule) AnalyzeProject(units []parser.Unit, ctx Context) []finding.Finding {
	return unusedPrivateSymbolFindings(newPackageReferenceIndex(units, ctx), "const")
}

// unusedPrivateSymbolFindings emits findings for the selected declaration kind in deterministic package order.
//
// It walks index groups in order, skips any marked skipForPrecision, and returns one finding per kind declaration the group finds unreferenced.
// The result is an empty slice when no declaration qualifies or kind is not type, var or const.
//
// Each finding points at the declaration's line and column and names the symbol and its package, marked candidate.
func unusedPrivateSymbolFindings(index packageReferenceIndex, kind string) []finding.Finding {
	findings := []finding.Finding{}
	for _, group := range index.ordered {
		// Packages excluded for generated code, vendor paths or reflect imports land here, so even a truly unused symbol there stays silent.
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
// It returns the private types, vars or consts of group when kind is type, var or const, and nil for any other kind.
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
