// Package rule contains shared generated-source helpers for rule-level guards.
package rule

import (
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// shouldSkipGeneratedUnit reports whether rule-level generated guards should
// suppress a parsed unit for this run. IncludeIgnored deliberately opts back
// into generated files after discovery, so rule guards must release them too.
func shouldSkipGeneratedUnit(unit parser.Unit, ctx Context) bool {
	return !ctx.IncludeIgnored && source.HasGeneratedGoHeader(unit.Source)
}
