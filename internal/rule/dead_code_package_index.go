// Package rule defines gruff-go's rule registry and analysers.
// This file builds a parser-only package reference index for private-symbol dead-code checks.
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
func newPackageReferenceIndex(units []parser.Unit, ctx Context) packageReferenceIndex {
	index := packageReferenceIndex{groups: map[packageReferenceKey]*packageReferenceGroup{}}
	for _, unit := range units {
		if unit.AST == nil || unit.AST.Name == nil {
			continue
		}
		key := packageReferenceKey{dir: filepath.Dir(unit.File.Path), packageName: unit.AST.Name.Name}
		group := index.group(key)
		group.units = append(group.units, unit)
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

// sortGroups stabilizes project-rule output before callers emit findings.
func (i *packageReferenceIndex) sortGroups() {
	sort.Slice(i.ordered, func(left, right int) bool {
		if i.ordered[left].key.dir != i.ordered[right].key.dir {
			return i.ordered[left].key.dir < i.ordered[right].key.dir
		}
		return i.ordered[left].key.packageName < i.ordered[right].key.packageName
	})
}

// countIdentifiers records every identifier spelling in the package syntax tree.
func (g *packageReferenceGroup) countIdentifiers(file *ast.File) {
	ast.Inspect(file, func(node ast.Node) bool {
		if ident, ok := node.(*ast.Ident); ok {
			g.identifierCounts[ident.Name]++
		}
		return true
	})
}

// collectPrivateDeclarations records top-level private declarations that candidate rules may judge.
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
func (g *packageReferenceGroup) collectPrivateFunc(unit parser.Unit, fn *ast.FuncDecl) {
	if fn.Recv != nil || fn.Name == nil || !startsLowercase(fn.Name.Name) || isReservedFuncName(fn.Name.Name) {
		return
	}
	g.privateFuncs = append(g.privateFuncs, packageSymbolDecl{unit: unit, name: fn.Name.Name, pos: fn.Pos()})
}

// collectPrivateGenDecl records top-level private type, var, and const declarations.
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
func (g *packageReferenceGroup) collectPrivateConsts(unit parser.Unit, decl *ast.GenDecl) {
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
func (g *packageReferenceGroup) unreferenced(decl packageSymbolDecl) bool {
	return g.identifierCounts[decl.name] <= 1
}

// isRegistrationValueSpec excludes map/slice registration tables whose use is often declarative.
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
