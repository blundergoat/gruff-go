// Package rule defines gruff-go's rule registry and analysers.
// This file implements a parser-only test-quality check for time.Sleep
// usage in Go test files. Sleeps in tests are the dominant source of
// flakiness because real timing is non-deterministic across machines and CI.
package rule

import (
	"go/ast"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// SleepInTestRule flags time.Sleep call sites inside *_test.go files. The
// rule is scoped to test files because production code legitimately sleeps
// (rate limiting, retry backoff); inside tests the same call is almost
// always either a flake or a missing synchronisation primitive.
type SleepInTestRule struct{}

// Definition declares the test-quality.sleep-in-test rule, its severity,
// default-enabled state, flake-oriented tags, and remediation guidance
// pointing maintainers at channel- or fake-clock-based alternatives.
func (SleepInTestRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.sleep-in-test",
		Title:          "Sleep in test",
		Description:    "Flags time.Sleep calls in _test.go files. Sleeps are the dominant source of test flakiness; prefer explicit synchronisation primitives or fake clocks.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceHigh,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Tags:           []string{"tests", "flake"},
		Remediation:    "Replace time.Sleep with channel/WaitGroup synchronisation, polling against an observable condition, or a fake clock that advances deterministically.",
	}
}

// AnalyzeUnit emits findings for every time.Sleep call site in test files.
// The rule walks fn.Body per declaration so the finding's Symbol carries the
// enclosing test or helper function name, which makes triage in large suites
// considerably faster than a bare file:line pointer.
func (SleepInTestRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isGoTestFile(unit.File.Path) || hasGeneratedHeader(unit.Source) {
		return nil
	}
	timePackages := packageImportNames(unit.AST, "time", "time")
	if len(timePackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		symbol := functionName(fn)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !selectorCallMatches(call, timePackages, "Sleep") {
				return true
			}
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "test calls time.Sleep; replace with explicit synchronisation",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   symbol,
				Metadata: map[string]any{"call": "time.Sleep"},
			})
			return true
		})
	}
	return findings
}
