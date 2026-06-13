// Package rule contains shared generated-source helpers for rule-level guards.
package rule

import (
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// shouldSkipGeneratedUnit reports whether rule-level generated guards should
// suppress a parsed unit for this run. IncludeIgnored deliberately opts back
// into generated files after discovery, so rule guards must release them too.
// The generated-header contract is Go-specific and discovery only skips
// generated Go files, so non-Go text units stay in scope here even when their
// leading comments happen to read like a Go generated banner.
func shouldSkipGeneratedUnit(unit parser.Unit, ctx Context) bool {
	if ctx.IncludeIgnored || unit.File.Type != source.FileTypeGo {
		return false
	}
	return source.HasGeneratedGoHeader(unit.Source)
}
