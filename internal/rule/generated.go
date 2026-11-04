// Package rule contains shared generated-source helpers for rule-level guards.
//
// Rules guarded this way skip a Go file whose header marks it generated, unless the run sets IncludeIgnored, which opts generated files back in.
package rule

import (
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// shouldSkipGeneratedUnit reports whether rule-level generated guards should suppress a parsed unit for this run.
//
// IncludeIgnored deliberately opts back into generated files after discovery, so rule guards must release them too.
// The header contract is Go-specific and discovery skips only generated Go files, so a non-Go unit with a Go-like banner stays in scope.
//
// It returns false when ctx has IncludeIgnored set or unit is not a Go file, otherwise whether source.HasGeneratedGoHeader is true for unit.Source.
func shouldSkipGeneratedUnit(unit parser.Unit, ctx Context) bool {
	if ctx.IncludeIgnored || unit.File.Type != source.FileTypeGo {
		return false
	}
	return source.HasGeneratedGoHeader(unit.Source)
}
