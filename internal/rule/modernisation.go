// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements parser-only modernisation checks, which read one file's syntax tree and imports at a time.
// Its one rule, modernisation.ioutil-deprecated, is off by default, so gruff-go analyse reports io/ioutil calls only once the rule is enabled.
package rule

import (
	"go/ast"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// ioutilReplacements maps deprecated io/ioutil selectors to their modern package equivalents.
//
// Each value is the replacement API a finding carries in its metadata, telling the user what to use instead.
// An ioutil member with no entry here, such as ReadDir, is never reported, even in a file that imports io/ioutil.
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
//
// It backs the modernisation.ioutil-deprecated rule, which is off by default, so its advisory findings appear only once a user enables it.
// It judges each file alone from its imports and selectors; a file that never imports io/ioutil gets no finding.
type IoutilDeprecatedRule struct{}

// Definition declares the modernisation.ioutil-deprecated rule for Go 1.16+ replacements.
// It returns an advisory, high-confidence modernisation Definition that is off by default and carries a minimumGoVersion option of 1.16.
func (IoutilDeprecatedRule) Definition() Definition {
	return Definition{
		ID:             "modernisation.ioutil-deprecated",
		Title:          "Deprecated ioutil API",
		Description:    "Flags calls to io/ioutil APIs that have direct io or os replacements in modern Go.",
		Pillar:         finding.PillarModernisation,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: false,
		Options:        map[string]any{"minimumGoVersion": "1.16"},
		Tags:           []string{"go-style"},
		Remediation:    "Replace io/ioutil calls with the matching io or os package API.",
	}
}

// AnalyzeUnit emits findings for deprecated ioutil selector uses.
//
// The unit is skipped when its AST or FileSet is nil, or when packageImportNames finds no local name for the io/ioutil import.
// Only selectors on such a name whose member has an entry in ioutilReplacements are reported; other ioutil members are ignored.
//
// It returns one finding per matching selector, located at the selector's line and column with api and replacement metadata.
// The result is nil when the unit is skipped and an empty slice when no selector matches.
func (IoutilDeprecatedRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	ioutilImportNames := packageImportNames(unit.AST, "io/ioutil", "ioutil")
	if len(ioutilImportNames) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || !ioutilImportNames[receiver.Name] {
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
