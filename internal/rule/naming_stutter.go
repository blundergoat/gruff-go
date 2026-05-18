package rule

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

var defaultPackageStutterAllow = []string{"Config", "Finding"}

type PackageStutterRule struct {
	AllowStutter []string
}

func (r PackageStutterRule) Definition() Definition {
	return Definition{
		ID:             "naming.package-stutter",
		Title:          "Package stutter",
		Description:    "Flags exported identifiers whose lowercase form starts with their own package name (config.ConfigOptions, rule.RuleRegistry).",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Tags:           []string{"go-style", "naming", "opt-in"},
		Options: map[string]any{
			"allowStutter": defaultPackageStutterAllow,
		},
		Remediation: "Rename the identifier to remove the package-name prefix so call sites read `config.Options` instead of `config.ConfigOptions`. Use `allowStutter` for single-noun stutter the community accepts (Config, Finding).",
	}
}

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

func (r PackageStutterRule) allowSet() map[string]bool {
	source := r.AllowStutter
	if len(source) == 0 {
		source = defaultPackageStutterAllow
	}
	out := make(map[string]bool, len(source))
	for _, name := range source {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			out[trimmed] = true
		}
	}
	return out
}

func scanUnitForStutter(unit parser.Unit, pkgLower string, allow map[string]bool) []finding.Finding {
	var findings []finding.Finding
	for _, decl := range unit.AST.Decls {
		findings = append(findings, stutterFindingsForDecl(unit, decl, pkgLower, allow)...)
	}
	return findings
}

func stutterFindingsForDecl(unit parser.Unit, decl ast.Decl, pkgLower string, allow map[string]bool) []finding.Finding {
	switch d := decl.(type) {
	case *ast.GenDecl:
		return stutterFindingsForGenDecl(unit, d, pkgLower, allow)
	case *ast.FuncDecl:
		return stutterFindingsForFuncDecl(unit, d, pkgLower, allow)
	}
	return nil
}

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

func stutterFindingsForFuncDecl(unit parser.Unit, decl *ast.FuncDecl, pkgLower string, allow map[string]bool) []finding.Finding {
	if decl.Recv != nil || decl.Name == nil || !ast.IsExported(decl.Name.Name) {
		return nil
	}
	if f, ok := stutterCheck(unit, decl.Name, pkgLower, allow); ok {
		return []finding.Finding{f}
	}
	return nil
}

func stutterCheck(unit parser.Unit, ident *ast.Ident, pkgLower string, allow map[string]bool) (finding.Finding, bool) {
	if ident == nil {
		return finding.Finding{}, false
	}
	name := ident.Name
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
	next := identName[len(pkgLower)]
	return next >= 'A' && next <= 'Z'
}
