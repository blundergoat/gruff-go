// Package rule defines gruff-go's rule registry and analysers.
// This file implements a project-level dead-code check that flags
// package-private top-level functions whose names never appear elsewhere
// in the same parsed package.
//
// The rule is parser-only: it does not resolve identifier bindings or
// reach into type information, it just counts how often each name
// appears across all units in the package. That is enough for the
// common case (a private function that nobody ever calls is a dead
// function), but it intentionally favours false-negatives over
// false-positives. Names that collide with struct fields, parameters,
// or method names anywhere in the package suppress the finding even
// when the function itself is genuinely unused. This is a deliberate
// precision-over-recall trade-off; nobody wants a noisy dead-code rule
// they have to suppress per-finding to ship a release.
package rule

import (
	"fmt"
	"go/ast"
	"path/filepath"
	"strconv"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// UnusedPrivateFunctionRule flags package-private top-level functions that
// are not syntactically referenced anywhere in their parsed package.
type UnusedPrivateFunctionRule struct{}

// Definition declares the dead-code.unused-private-function rule.
func (UnusedPrivateFunctionRule) Definition() Definition {
	return Definition{
		ID:             "dead-code.unused-private-function",
		Title:          "Unused private function",
		Description:    "Flags package-private (lowercase-leading) top-level functions whose names are not referenced anywhere else in the same parsed package. Methods, init, main, and packages that import reflect are excluded so the rule stays precision-first.",
		Pillar:         finding.PillarDeadCode,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Tags:           []string{"dead-code", "cross-file"},
		Remediation:    "Delete the function, export it if other packages need it, or confirm it is only used through reflection or build-tag-gated code paths and suppress the finding locally.",
	}
}

// AnalyzeProject emits findings for unreferenced package-private functions.
func (UnusedPrivateFunctionRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	groups := groupUnitsByPackage(units)
	findings := []finding.Finding{}
	for _, group := range groups {
		if group.skipForReflection {
			continue
		}
		identCounts := countAllIdentifiers(group.units)
		for _, decl := range group.privateFuncDecls {
			// Each FuncDecl's own Name ident contributes one occurrence to
			// the count. Anything greater means the name appears somewhere
			// else and we cannot prove the function is unused with parser-
			// only evidence. Equal-to-one means only the declaration carries
			// the name, so nothing in the package uses it.
			if identCounts[decl.fn.Name.Name] > 1 {
				continue
			}
			position := decl.unit.FileSet.Position(decl.fn.Pos())
			findings = append(findings, finding.Finding{
				Message:  fmt.Sprintf("private function %q is not referenced in package %q", decl.fn.Name.Name, group.packageName),
				File:     decl.unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   decl.fn.Name.Name,
				Metadata: map[string]any{"package": group.packageName},
			})
		}
	}
	return findings
}

// packageGroup carries one parsed package's worth of units plus the
// pre-filtered candidate declarations the rule will judge against.
type packageGroup struct {
	packageName       string
	units             []parser.Unit
	privateFuncDecls  []privateFuncDecl
	skipForReflection bool
}

// privateFuncDecl records a top-level private function declaration with the
// unit it came from. The unit reference is what lets the rule resolve
// FileSet positions when emitting findings.
type privateFuncDecl struct {
	unit parser.Unit
	fn   *ast.FuncDecl
}

// groupUnitsByPackage partitions parser units by (directory, packageName).
// Splitting on package name as well as directory matters because Go allows
// an external test package (e.g. `foo_test`) to live alongside the main
// package (`foo`) in the same directory; the two have different visibility
// rules and cannot reference each other's private symbols.
func groupUnitsByPackage(units []parser.Unit) []*packageGroup {
	byKey := map[string]*packageGroup{}
	for _, u := range units {
		if u.AST == nil || u.AST.Name == nil {
			continue
		}
		key := filepath.Dir(u.File.Path) + "\x00" + u.AST.Name.Name
		group, ok := byKey[key]
		if !ok {
			group = &packageGroup{packageName: u.AST.Name.Name}
			byKey[key] = group
		}
		group.units = append(group.units, u)
		if importsReflectPackage(u.AST) {
			group.skipForReflection = true
		}
		for _, decl := range u.AST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name == nil {
				continue
			}
			name := fn.Name.Name
			if !startsLowercase(name) || isReservedFuncName(name) {
				continue
			}
			group.privateFuncDecls = append(group.privateFuncDecls, privateFuncDecl{unit: u, fn: fn})
		}
	}
	groups := make([]*packageGroup, 0, len(byKey))
	for _, g := range byKey {
		groups = append(groups, g)
	}
	return groups
}

// countAllIdentifiers tallies every identifier across every unit in the
// package. Counting the FuncDecl.Name ident plus any in-body references
// uniformly is what lets the simple `count > 1` heuristic distinguish
// "declared and used" from "declared and abandoned".
func countAllIdentifiers(units []parser.Unit) map[string]int {
	counts := map[string]int{}
	for _, u := range units {
		if u.AST == nil {
			continue
		}
		ast.Inspect(u.AST, func(node ast.Node) bool {
			if id, ok := node.(*ast.Ident); ok {
				counts[id.Name]++
			}
			return true
		})
	}
	return counts
}

// importsReflectPackage reports whether the file imports a runtime-
// reflection package. Reflective dispatch can reference functions by name
// without ever producing a syntactic identifier reference, which would
// turn this rule into a noise factory; the safer call is to step aside
// for the whole package when reflection is in play.
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

// startsLowercase reports whether name begins with a lowercase rune.
// Go uses leading case to gate package visibility; lowercase means
// package-private, which is the only scope this rule considers.
func startsLowercase(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		return unicode.IsLower(r)
	}
	return false
}

// isReservedFuncName protects Go's special function names. `init` is
// invoked automatically at package load and may be defined per-file;
// `main` is the program entrypoint. Neither produces an explicit
// caller reference yet both are by-spec live.
func isReservedFuncName(name string) bool {
	return name == "init" || name == "main"
}
