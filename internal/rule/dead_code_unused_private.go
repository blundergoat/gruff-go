// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements dead-code.unused-private-function, which flags private top-level functions never named elsewhere in their package.
// The rule is parser-only: it counts how often each name appears across the package's units, without binding identifiers or reading types.
//
// That catches the common case, a private function nobody calls, but it favours false negatives over false positives.
// A name shared with a struct field, parameter or method anywhere in the package hides even a truly unused function.
// This precision-over-recall trade-off is deliberate: nobody wants a noisy dead-code rule they must suppress per finding to ship a release.
package rule

import (
	"fmt"
	"go/ast"
	"strconv"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// UnusedPrivateFunctionRule flags package-private top-level functions that are not syntactically referenced anywhere in their parsed package.
//
// It checks all parsed units together, so a call from another file of the same package keeps a function live.
// Methods, init, main, and packages that import reflect are left out; each finding names the function and its package.
type UnusedPrivateFunctionRule struct{}

// Definition declares the dead-code.unused-private-function rule.
// It returns the fixed rule metadata: advisory severity, medium confidence, parser capability, enabled by default, with no options.
func (UnusedPrivateFunctionRule) Definition() Definition {
	return Definition{
		ID:             "dead-code.unused-private-function",
		Title:          "Unused private function",
		Description:    "Flags package-private (lowercase-leading) top-level functions whose names are not referenced anywhere else in the same parsed package. Methods, init, main, and packages that import reflect are excluded so the rule stays precision-first.",
		Pillar:         finding.PillarDeadCode,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Tags:           []string{"dead-code", "cross-file"},
		Remediation:    "Delete the function, export it if other packages need it, or confirm it is only used through reflection or build-tag-gated code paths and suppress the finding locally.",
	}
}

// AnalyzeProject emits findings for unreferenced package-private functions.
//
// units supply the name counts per package; when ctx has IncludeIgnored set, generated Go files no longer mark their package skipForPrecision.
// Groups marked skipForPrecision are skipped whole, and a function is reported only when its name appears nowhere but its own declaration.
// It returns the findings in the index's group order, or an empty, non-nil slice when no private function is unreferenced.
func (UnusedPrivateFunctionRule) AnalyzeProject(units []parser.Unit, ctx Context) []finding.Finding {
	index := newPackageReferenceIndex(units, ctx)
	findings := []finding.Finding{}
	for _, group := range index.ordered {
		// A package gets no findings at all when any of its parsed files imports reflect, lives under a vendor path, or is treated as generated.
		if group.skipForPrecision {
			continue
		}
		for _, decl := range group.privateFuncs {
			// The declaration's own name counts once; any higher count means the name appears elsewhere and parser-only evidence cannot prove it unused.
			// A count of exactly one means nothing else in the package names the function, so the user gets a finding for it.
			if !group.unreferenced(decl) {
				continue
			}
			position := decl.unit.FileSet.Position(decl.pos)
			findings = append(findings, finding.Finding{
				Message:  fmt.Sprintf("private function %q is not referenced in package %q", decl.name, group.key.packageName),
				File:     decl.unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   decl.name,
				Metadata: map[string]any{"package": group.key.packageName},
			})
		}
	}
	return findings
}

// importsReflectPackage reports whether file imports the reflect package; false means no reflect import was found in file.
//
// A true result makes the rule skip the whole parsed package, even when every private function in it is unreferenced.
// That keeps the rule precision-first, as its description promises, at the cost of missing dead code in those packages.
func importsReflectPackage(file *ast.File) bool {
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		switch path {
		case "reflect":
			return true
		}
	}
	return false
}

// startsLowercase reports whether name begins with a lowercase rune; false covers an empty name and names led by a capital or underscore.
//
// Go uses leading case to gate package visibility; lowercase means package-private, which is the only scope this rule considers.
func startsLowercase(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		return unicode.IsLower(r)
	}
	return false
}

// isReservedFuncName protects Go's special function names, init and main, which produce no explicit caller reference.
//
// init runs automatically at package load and may be defined per file; main is the program entrypoint.
// init is live by spec in every package, main only in package main.
//
// It reports true only when name is exactly init or main, and false for every other name.
// It never sees the package, so it also reports true for a main declared outside package main.
func isReservedFuncName(name string) bool {
	return name == "init" || name == "main"
}
