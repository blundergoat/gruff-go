// Package rule defines gruff-go's rule registry and analysers.
// This file implements parser-only modernisation checks.
package rule

import (
	"go/ast"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// ioutilReplacements maps deprecated io/ioutil selectors to their modern package equivalents.
var ioutilReplacements = map[string]string{
	"Discard":   "io.Discard",
	"NopCloser": "io.NopCloser",
	"ReadAll":   "io.ReadAll",
	"ReadFile":  "os.ReadFile",
	"TempDir":   "os.MkdirTemp",
	"TempFile":  "os.CreateTemp",
	"WriteFile": "os.WriteFile",
}

// IoutilDeprecatedRule flags use of the deprecated io/ioutil package.
type IoutilDeprecatedRule struct{}

// Definition declares the modernisation.ioutil-deprecated rule for Go 1.16+ replacements.
func (IoutilDeprecatedRule) Definition() Definition {
	return Definition{
		ID:             "modernisation.ioutil-deprecated",
		Title:          "Deprecated ioutil API",
		Description:    "Flags calls to io/ioutil APIs that have direct io or os replacements in modern Go.",
		Pillar:         finding.PillarModernisation,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Options:        map[string]any{"minimumGoVersion": "1.16"},
		Tags:           []string{"go-style"},
		Remediation:    "Replace io/ioutil calls with the matching io or os package API.",
	}
}

// AnalyzeUnit emits findings for deprecated ioutil selector uses.
func (IoutilDeprecatedRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	ioutilPackages := packageImportNames(unit.AST, "io/ioutil", "ioutil")
	if len(ioutilPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || !ioutilPackages[receiver.Name] {
			return true
		}
		replacement, ok := ioutilReplacements[selector.Sel.Name]
		if !ok {
			return true
		}
		position := unit.FileSet.Position(selector.Pos())
		findings = append(findings, finding.Finding{
			Message:  "io/ioutil API has a modern replacement",
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Metadata: map[string]any{
				"api":         receiver.Name + "." + selector.Sel.Name,
				"replacement": replacement,
			},
		})
		return true
	})
	return findings
}
