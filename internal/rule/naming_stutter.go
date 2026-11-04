// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements the naming.package-stutter rule, which is disabled by default.
// Once enabled, it reports exported package-level names that stutter, skipping methods and allowStutter names, at advisory severity by default.
package rule

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// defaultPackageStutterAllow lists exported identifiers permitted to repeat their package name.
//
// It applies whenever AllowStutter is empty, so names such as config.Config and finding.Finding are not reported by default.
// A non-empty AllowStutter replaces this list, so Config and Finding must be listed there again to stay exempt.
// Definition also reports it as the allowStutter option default.
var defaultPackageStutterAllow = []string{"Config", "Finding"}

// PackageStutterRule flags exported identifiers whose names redundantly include the package name.
//
// It backs naming.package-stutter, which is disabled by default, so these findings appear only once the rule is enabled.
// A name stutters when its lower case starts with the lowercased package name.
// The original name must then end, or hold an ASCII capital, at that prefix's byte length, as in rule.RuleSet.
type PackageStutterRule struct {
	// AllowStutter lists exact exported names exempt from the stutter check; when it is empty, Config and Finding are exempt instead.
	AllowStutter []string
}

// Definition declares the naming.package-stutter rule, with default allowStutter exemptions for Config and Finding under the naming pillar.
//
// It returns a fully populated Definition: advisory severity, medium confidence, parser capability, disabled by default, with remediation text.
// The allowStutter option always reports the package defaults, whatever the receiver's AllowStutter holds.
func (r PackageStutterRule) Definition() Definition {
	return Definition{
		ID:             "naming.package-stutter",
		Title:          "Package stutter",
		Description:    "Flags exported identifiers whose lowercase form starts with their own package name (config.ConfigOptions, rule.RuleRegistry).",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Tags:           []string{"go-style", "naming"},
		Options: map[string]any{
			"allowStutter": defaultPackageStutterAllow,
		},
		Remediation: "Rename the identifier to remove the package-name prefix so call sites read `config.Options` instead of `config.ConfigOptions`. Use `allowStutter` for single-noun stutter the community accepts (Config, Finding).",
	}
}

// AnalyzeProject scans every file in units for exported declarations that stutter their package name.
//
// Units lacking a parsed AST, package name or file set are skipped; names in AllowStutter, or Config and Finding when it is empty, are exempt.
// It returns one finding per stuttering identifier, in the order of units and their declarations, or nil when none stutters.
//
// It panics when a checked name is shorter in bytes than the lowercased package name yet its own lower case starts with that package name.
// An exported Ⱥ in package ⱥ does this, because lowercase ⱥ takes three bytes and Ⱥ takes two.
func (r PackageStutterRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	allow := r.allowSet()
	var findings []finding.Finding
	for _, unit := range units {
		if unit.AST == nil || unit.AST.Name == nil || unit.FileSet == nil {
			continue
		}
		pkg := unit.AST.Name.Name
		if pkg == "" {
			continue
		}
		findings = append(findings, scanUnitForStutter(unit, strings.ToLower(pkg), allow)...)
	}
	return findings
}

// allowSet returns the configured allow list as a lookup set, defaulting to Config and Finding when AllowStutter is empty.
// Entries are trimmed and blank ones dropped, so an AllowStutter holding only blank strings gives an empty set that exempts nothing.
func (r PackageStutterRule) allowSet() map[string]bool {
	source := r.AllowStutter
	if len(source) == 0 {
		source = defaultPackageStutterAllow
	}
	exemptNames := make(map[string]bool, len(source))
	for _, name := range source {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			exemptNames[trimmed] = true
		}
	}
	return exemptNames
}

// scanUnitForStutter walks the declarations of a single unit looking for stuttered names.
//
// pkgLower is the package name of unit in lower case, and allow holds the exact identifier names exempt from the check.
// It returns the findings for every top-level declaration in source order, or nil when none stutters.
//
// It panics when a checked name is shorter in bytes than pkgLower yet its own lower case starts with pkgLower, as Unicode case mapping allows.
func scanUnitForStutter(unit parser.Unit, pkgLower string, allow map[string]bool) []finding.Finding {
	var findings []finding.Finding
	for _, decl := range unit.AST.Decls {
		findings = append(findings, stutterFindingsForDecl(unit, decl, pkgLower, allow)...)
	}
	return findings
}

// stutterFindingsForDecl dispatches a declaration to the appropriate stutter inspector.
//
// A function or general decl is checked for exported names that stutter pkgLower, the lowercase package name, unless allow exempts the exact name.
// unit supplies the file path and position each finding reports.
// It returns that inspector's findings, or nil for any other decl kind or when no name stutters.
//
// It panics when a checked name is shorter in bytes than pkgLower yet its own lower case starts with pkgLower, as Unicode case mapping allows.
func stutterFindingsForDecl(unit parser.Unit, decl ast.Decl, pkgLower string, allow map[string]bool) []finding.Finding {
	switch d := decl.(type) {
	case *ast.GenDecl:
		return stutterFindingsForGenDecl(unit, d, pkgLower, allow)
	case *ast.FuncDecl:
		return stutterFindingsForFuncDecl(unit, d, pkgLower, allow)
	}
	return nil
}

// stutterFindingsForGenDecl examines type and exported value specs for package stutter.
//
// Type, const and var names in decl are checked for the lowercase package prefix pkgLower unless allow exempts the exact name.
// Unexported names and import specs are skipped, and unit supplies the file path and position of each finding.
// It returns one finding per stuttering name in spec order, or nil when none stutters.
//
// It panics when a checked name is shorter in bytes than pkgLower yet its own lower case starts with pkgLower, as Unicode case mapping allows.
func stutterFindingsForGenDecl(unit parser.Unit, decl *ast.GenDecl, pkgLower string, allow map[string]bool) []finding.Finding {
	var findings []finding.Finding
	for _, spec := range decl.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			if f, ok := stutterCheck(unit, s.Name, pkgLower, allow); ok {
				findings = append(findings, f)
			}
		case *ast.ValueSpec:
			for _, name := range s.Names {
				if !ast.IsExported(name.Name) {
					continue
				}
				if f, ok := stutterCheck(unit, name, pkgLower, allow); ok {
					findings = append(findings, f)
				}
			}
		}
	}
	return findings
}

// stutterFindingsForFuncDecl checks top-level exported functions (skipping methods) for stutter.
//
// The function name in decl is checked for the lowercase package prefix pkgLower unless allow exempts it; unit supplies its finding location.
// It returns a one-element slice when the name stutters, or nil for a method, a missing or unexported name, or one that does not stutter.
//
// It panics when a checked name is shorter in bytes than pkgLower yet its own lower case starts with pkgLower, as Unicode case mapping allows.
func stutterFindingsForFuncDecl(unit parser.Unit, decl *ast.FuncDecl, pkgLower string, allow map[string]bool) []finding.Finding {
	if decl.Recv != nil || decl.Name == nil || !ast.IsExported(decl.Name.Name) {
		return nil
	}
	if f, ok := stutterCheck(unit, decl.Name, pkgLower, allow); ok {
		return []finding.Finding{f}
	}
	return nil
}

// stutterCheck evaluates a single identifier and returns a Finding when it stutters its package.
//
// pkgLower is the lowercased package name and allow holds exempt names; unit supplies the file path and position of the finding.
// The bool result is false, with a zero Finding, when ident is nil, unexported or allowed, or does not stutter.
//
// A name stutters when its lower case starts with pkgLower and the name is as long in bytes as pkgLower or has an ASCII capital at that offset.
// Unicode case mappings that change byte length can shift that offset, and a matching name shorter in bytes than pkgLower panics.
func stutterCheck(unit parser.Unit, ident *ast.Ident, pkgLower string, allow map[string]bool) (finding.Finding, bool) {
	if ident == nil {
		return finding.Finding{}, false
	}
	name := ident.Name
	// An allowStutter entry must match the whole name, so allowing Config still leaves ConfigOptions reportable.
	if !ast.IsExported(name) || allow[name] {
		return finding.Finding{}, false
	}
	if !isPackageStutter(name, pkgLower) {
		return finding.Finding{}, false
	}
	position := unit.FileSet.Position(ident.NamePos)
	return finding.Finding{
		Message:  fmt.Sprintf("identifier %q stutters package %q; rename so call sites read without repetition", name, pkgLower),
		File:     unit.File.Path,
		Location: &finding.Location{Line: position.Line, Column: position.Column},
		Symbol:   name,
		Metadata: map[string]any{"identifier": name, "package": pkgLower},
	}, true
}

// isPackageStutter reports whether identName begins with pkgLower followed by a word boundary.
//
// The prefix match ignores the case of identName, and the boundary is the end of identName or an ASCII capital at byte offset len(pkgLower).
// The result is false when either name is empty; rule.Rules does not stutter, while rule.RuleSet and config.Config do.
//
// It panics when identName is shorter in bytes than pkgLower yet its lower case starts with pkgLower, as for an exported Ⱥ in package ⱥ.
func isPackageStutter(identName, pkgLower string) bool {
	if pkgLower == "" || identName == "" {
		return false
	}
	if !strings.HasPrefix(strings.ToLower(identName), pkgLower) {
		return false
	}
	if len(identName) == len(pkgLower) {
		return true
	}
	// A name shorter in bytes than pkgLower, reachable only through Unicode case mapping, panics on this index.
	next := identName[len(pkgLower)]
	return next >= 'A' && next <= 'Z'
}
