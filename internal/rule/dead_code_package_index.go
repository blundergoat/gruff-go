// Package rule defines gruff-go's rule registry and analysers.
//
// This file builds a parser-only package reference index for private-symbol dead-code checks.
// It counts name spellings per directory and package; an eligible private declaration whose name occurs once becomes a dead-code candidate.
// A vendored file, a reflect import or a unit that shouldSkipGeneratedUnit skips marks the whole package skipForPrecision.
package rule

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blundergoat/gruff-go/internal/parser"
)

// packageReferenceKey identifies one parser-visible package boundary.
//
// Files share a group only with the same directory and package name, so an external _test package there forms its own group.
type packageReferenceKey struct {
	dir         string
	packageName string
}

// packageReferenceIndex stores package groups in both map and deterministic order.
type packageReferenceIndex struct {
	groups  map[packageReferenceKey]*packageReferenceGroup
	ordered []*packageReferenceGroup
}

// packageReferenceGroup carries declarations, references, and skip state for one package.
type packageReferenceGroup struct {
	key              packageReferenceKey
	units            []parser.Unit
	identifierCounts map[string]int
	privateFuncs     []packageSymbolDecl
	privateTypes     []packageSymbolDecl
	privateVars      []packageSymbolDecl
	privateConsts    []packageSymbolDecl
	skipForPrecision bool
}

// packageSymbolDecl records a private top-level declaration with stable source position evidence.
type packageSymbolDecl struct {
	unit parser.Unit
	name string
	pos  token.Pos
}

// newPackageReferenceIndex groups units by package and records parser-only declarations and references.
//
// units are the parsed files, and a unit without an AST or package name is ignored; ctx is passed to shouldSkipGeneratedUnit.
// A group is marked skipForPrecision when that check skips any of its units, or one of them is a vendor path or imports reflect.
// Returns the index with groups keyed by directory and package name, ordered by those two fields; it has no groups when every unit is ignored.
func newPackageReferenceIndex(units []parser.Unit, ctx Context) packageReferenceIndex {
	index := packageReferenceIndex{groups: map[packageReferenceKey]*packageReferenceGroup{}}
	for _, unit := range units {
		// A unit with no AST is left out, so a private name used only in that file can still look unreferenced to the dead-code checks.
		if unit.AST == nil || unit.AST.Name == nil {
			continue
		}
		key := packageReferenceKey{dir: filepath.Dir(unit.File.Path), packageName: unit.AST.Name.Name}
		group := index.group(key)
		group.units = append(group.units, unit)
		// A unit shouldSkipGeneratedUnit skips, a vendored file or a reflect import sets skipForPrecision for the whole package, not just that file.
		if shouldSkipGeneratedUnit(unit, ctx) || isVendorPath(unit.File.Path) || importsReflectPackage(unit.AST) {
			group.skipForPrecision = true
		}
		group.countIdentifiers(unit.AST)
		group.collectPrivateDeclarations(unit)
	}
	index.sortGroups()
	return index
}

// group returns the existing package group or creates one in deterministic map/order state.
// key is the directory and package name pair; a new group is stored in the map and appended to ordered, which sortGroups later sorts.
func (i *packageReferenceIndex) group(key packageReferenceKey) *packageReferenceGroup {
	group, ok := i.groups[key]
	if ok {
		return group
	}
	group = &packageReferenceGroup{key: key, identifierCounts: map[string]int{}}
	i.groups[key] = group
	i.ordered = append(i.ordered, group)
	return group
}

// sortGroups orders groups by directory, then package name, so project-rule findings come out in a stable order before callers emit them.
func (i *packageReferenceIndex) sortGroups() {
	sort.Slice(i.ordered, func(left, right int) bool {
		if i.ordered[left].key.dir != i.ordered[right].key.dir {
			return i.ordered[left].key.dir < i.ordered[right].key.dir
		}
		return i.ordered[left].key.packageName < i.ordered[right].key.packageName
	})
}

// countIdentifiers records every identifier spelling in the package syntax tree.
//
// file is one unit's syntax tree; each identifier node in it, declaration names included, adds one to identifierCounts for its spelling.
// Spelling alone counts, so a field, method or local variable sharing a private declaration's name makes that declaration look used.
func (g *packageReferenceGroup) countIdentifiers(file *ast.File) {
	ast.Inspect(file, func(node ast.Node) bool {
		if ident, ok := node.(*ast.Ident); ok {
			g.identifierCounts[ident.Name]++
		}
		return true
	})
}

// collectPrivateDeclarations records top-level private declarations that candidate rules may judge.
// unit is the parsed file whose top-level function and general declarations go to collectPrivateFunc and collectPrivateGenDecl.
func (g *packageReferenceGroup) collectPrivateDeclarations(unit parser.Unit) {
	for _, decl := range unit.AST.Decls {
		switch value := decl.(type) {
		case *ast.FuncDecl:
			g.collectPrivateFunc(unit, value)
		case *ast.GenDecl:
			g.collectPrivateGenDecl(unit, value)
		}
	}
}

// collectPrivateFunc records parser-visible package-private top-level functions.
//
// unit is the file holding fn and is stored with the record, and fn is skipped when it is a method, has no name, or does not start lowercase.
// A name that isReservedFuncName reserves is skipped as well.
// Unlike private types, vars and consts, functions declared in Go test files are recorded too.
func (g *packageReferenceGroup) collectPrivateFunc(unit parser.Unit, fn *ast.FuncDecl) {
	if fn.Recv != nil || fn.Name == nil || !startsLowercase(fn.Name.Name) || isReservedFuncName(fn.Name.Name) {
		return
	}
	g.privateFuncs = append(g.privateFuncs, packageSymbolDecl{unit: unit, name: fn.Name.Name, pos: fn.Pos()})
}

// collectPrivateGenDecl records top-level private type, var, and const declarations.
//
// unit is the file holding decl, and decl is routed by its token to collectPrivateTypes, collectPrivateVars or collectPrivateConsts.
// Import declarations match none of those tokens and are ignored.
func (g *packageReferenceGroup) collectPrivateGenDecl(unit parser.Unit, decl *ast.GenDecl) {
	switch decl.Tok {
	case token.TYPE:
		g.collectPrivateTypes(unit, decl)
	case token.VAR:
		g.collectPrivateVars(unit, decl)
	case token.CONST:
		g.collectPrivateConsts(unit, decl)
	}
}

// collectPrivateTypes records private named types from production files only.
//
// unit is the file holding decl, and nothing is recorded when its path is a Go test file.
// decl is a type group, and each spec whose name starts lowercase is recorded with its position.
func (g *packageReferenceGroup) collectPrivateTypes(unit parser.Unit, decl *ast.GenDecl) {
	if isGoTestFile(unit.File.Path) {
		return
	}
	for _, spec := range decl.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok || typeSpec.Name == nil || !startsLowercase(typeSpec.Name.Name) {
			continue
		}
		g.privateTypes = append(g.privateTypes, packageSymbolDecl{unit: unit, name: typeSpec.Name.Name, pos: typeSpec.Pos()})
	}
}

// collectPrivateVars records private package vars, excluding common registration and assertion shapes.
//
// unit is the file holding decl, and nothing is recorded when its path is a Go test file.
// decl is a var group whose specs are skipped when isRegistrationValueSpec matches; blank names and names not starting lowercase are skipped too.
func (g *packageReferenceGroup) collectPrivateVars(unit parser.Unit, decl *ast.GenDecl) {
	if isGoTestFile(unit.File.Path) {
		return
	}
	for _, spec := range decl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok || isRegistrationValueSpec(valueSpec) {
			continue
		}
		for _, name := range valueSpec.Names {
			if name == nil || name.Name == "_" || !startsLowercase(name.Name) {
				continue
			}
			g.privateVars = append(g.privateVars, packageSymbolDecl{unit: unit, name: name.Name, pos: name.Pos()})
		}
	}
}

// collectPrivateConsts records private package consts, excluding iota and multi-name specs.
//
// unit is the file holding decl, and nothing is recorded when its path is a Go test file.
// decl is a const group, skipped whole when any value uses iota; each single-name spec with a non-blank lowercase name is recorded.
func (g *packageReferenceGroup) collectPrivateConsts(unit parser.Unit, decl *ast.GenDecl) {
	// A whole iota group is skipped, so an unused member of an enum-style const block never becomes a dead-code candidate.
	if isGoTestFile(unit.File.Path) || genDeclUsesIota(decl) {
		return
	}
	for _, spec := range decl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok || len(valueSpec.Names) != 1 {
			continue
		}
		name := valueSpec.Names[0]
		if name == nil || name.Name == "_" || !startsLowercase(name.Name) {
			continue
		}
		g.privateConsts = append(g.privateConsts, packageSymbolDecl{unit: unit, name: name.Name, pos: name.Pos()})
	}
}

// unreferenced reports whether a declaration name appears only at its declaration site.
// decl supplies the name looked up in identifierCounts; the result is true when that spelling occurs at most once across the package files.
func (g *packageReferenceGroup) unreferenced(decl packageSymbolDecl) bool {
	return g.identifierCounts[decl.name] <= 1
}

// isRegistrationValueSpec excludes map/slice registration tables whose use is often declarative.
//
// spec is one var spec; the result is true when any name passes isRegistrationName or a composite literal spells out a map, slice or array type.
// It reports false for every other spec, such as one whose values are struct literals, named-type literals, pointers to literals, or calls.
// So collectPrivateVars skips a var whose literal spells out a map, slice or array type, even when nothing uses it.
func isRegistrationValueSpec(spec *ast.ValueSpec) bool {
	for _, name := range spec.Names {
		if name != nil && isRegistrationName(name.Name) {
			return true
		}
	}
	for _, value := range spec.Values {
		if literal, ok := value.(*ast.CompositeLit); ok {
			if _, ok := literal.Type.(*ast.MapType); ok {
				return true
			}
			if _, ok := literal.Type.(*ast.ArrayType); ok {
				return true
			}
		}
	}
	return false
}

// isRegistrationName recognises conventional top-level registries that may be consumed indirectly.
//
// Reports true when the lower-cased name contains register, registry, handlers, routes, checks or rules, and false otherwise.
// Matching is by substring, so a name such as checksumTable also counts as a registry.
func isRegistrationName(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "register") ||
		strings.Contains(lower, "registry") ||
		strings.Contains(lower, "handlers") ||
		strings.Contains(lower, "routes") ||
		strings.Contains(lower, "checks") ||
		strings.Contains(lower, "rules")
}

// genDeclUsesIota reports whether any value in a const group uses iota.
// decl is the const group whose value expressions are searched for an iota identifier; a spec with no values adds nothing.
func genDeclUsesIota(decl *ast.GenDecl) bool {
	for _, spec := range decl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, value := range valueSpec.Values {
			if exprUsesIdent(value, "iota") {
				return true
			}
		}
	}
	return false
}

// exprUsesIdent reports whether expr contains an identifier with the supplied name.
func exprUsesIdent(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		if ident, ok := node.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}
