// Package rule defines gruff-go's rule registry and analysers.
// This file implements the naming.misspelling rule.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// defaultMisspellingDictionary maps common misspellings to their suggested corrections.
var defaultMisspellingDictionary = map[string]string{
	"accomodate":  "accommodate",
	"adress":      "address",
	"agressive":   "aggressive",
	"begining":    "beginning",
	"comparsion":  "comparison",
	"conatin":     "contain",
	"definately":  "definitely",
	"dervied":     "derived",
	"effecient":   "efficient",
	"enviroment":  "environment",
	"existance":   "existence",
	"independant": "independent",
	"intial":      "initial",
	"intialize":   "initialize",
	"intialized":  "initialized",
	"langauge":    "language",
	"lenght":      "length",
	"mantain":     "maintain",
	"occured":     "occurred",
	"occurence":   "occurrence",
	"paramater":   "parameter",
	"paramaters":  "parameters",
	"prefered":    "preferred",
	"priviledge":  "privilege",
	"recieve":     "receive",
	"recieved":    "received",
	"recieves":    "receives",
	"regsiter":    "register",
	"responce":    "response",
	"seperate":    "separate",
	"seperated":   "separated",
	"sucess":      "success",
	"succesful":   "successful",
	"thier":       "their",
	"untill":      "until",
	"useable":     "usable",
	"wether":      "whether",
	"wich":        "which",
	"wierd":       "weird",
}

// MisspellingRule flags identifiers, comments, and struct tags containing common programming misspellings.
type MisspellingRule struct {
	Extra  map[string]string
	Ignore []string
}

// Definition declares the naming.misspelling rule with a built-in dictionary of common programming typos plus an extensible `extra` map and `ignore` allowlist.
func (r MisspellingRule) Definition() Definition {
	return Definition{
		ID:             "naming.misspelling",
		Title:          "Misspelled identifier or comment",
		Description:    "Flags identifiers, doc comments, and struct tags containing common programming misspellings.",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Tags:           []string{"naming", "opt-in"},
		Options: map[string]any{
			"extra":  map[string]any{},
			"ignore": []string{},
		},
		Remediation: "Replace the misspelled token with the suggested correction. Use the `ignore` option for project-specific terms that look like misspellings but are intentional (proper nouns, vendor-specific terms).",
	}
}

// AnalyzeUnit scans the given unit for misspellings in identifiers, comments, and struct tags.
func (r MisspellingRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	ctx := r.buildContext(unit)
	if ctx == nil {
		return nil
	}
	ctx.checkComments(unit.AST.Doc)
	for _, decl := range unit.AST.Decls {
		ctx.walkDecl(decl)
	}
	return ctx.findings
}

// misspellingContext holds the per-unit state used while scanning for misspellings.
type misspellingContext struct {
	unit     parser.Unit
	dict     map[string]string
	ignore   map[string]bool
	seen     map[string]bool
	findings []finding.Finding
}

// buildContext returns a misspellingContext seeded with the rule's dictionary and ignore list.
func (r MisspellingRule) buildContext(unit parser.Unit) *misspellingContext {
	dict := r.dictionary()
	if len(dict) == 0 {
		return nil
	}
	return &misspellingContext{
		unit:   unit,
		dict:   dict,
		ignore: r.ignoreSet(),
		seen:   map[string]bool{},
	}
}

// emit records a misspelling finding for the given token unless it is ignored or already reported.
func (c *misspellingContext) emit(tok, suggestion string, pos token.Pos) {
	if c.ignore[tok] {
		return
	}
	position := c.unit.FileSet.Position(pos)
	key := fmt.Sprintf("%d:%d:%s", position.Line, position.Column, tok)
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.findings = append(c.findings, finding.Finding{
		Message:  fmt.Sprintf("%q looks like a misspelling of %q", tok, suggestion),
		File:     c.unit.File.Path,
		Location: &finding.Location{Line: position.Line, Column: position.Column},
		Metadata: map[string]any{"token": tok, "suggestion": suggestion},
	})
}

// checkText tokenises the given text and emits findings for any tokens in the dictionary.
func (c *misspellingContext) checkText(text string, pos token.Pos) {
	for _, tok := range tokenizeForMisspelling(text) {
		if suggestion, ok := c.dict[tok]; ok {
			c.emit(tok, suggestion, pos)
		}
	}
}

// checkComments scans each comment in the group for misspelled tokens.
func (c *misspellingContext) checkComments(group *ast.CommentGroup) {
	if group == nil {
		return
	}
	for _, comment := range group.List {
		c.checkText(comment.Text, comment.Slash)
	}
}

// walkDecl dispatches to the appropriate walker for general and function declarations.
func (c *misspellingContext) walkDecl(decl ast.Decl) {
	switch d := decl.(type) {
	case *ast.GenDecl:
		c.walkGenDecl(d)
	case *ast.FuncDecl:
		c.walkFuncDecl(d)
	}
}

// walkGenDecl inspects type, value, and import specs in the given general declaration.
func (c *misspellingContext) walkGenDecl(decl *ast.GenDecl) {
	c.checkComments(decl.Doc)
	for _, spec := range decl.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			c.checkText(s.Name.Name, s.Name.NamePos)
			if st, ok := s.Type.(*ast.StructType); ok {
				c.walkStructFields(st)
			}
		case *ast.ValueSpec:
			c.walkValueSpec(s)
		}
	}
}

// walkFuncDecl inspects the doc, name, and parameter names of a function declaration.
func (c *misspellingContext) walkFuncDecl(decl *ast.FuncDecl) {
	c.checkComments(decl.Doc)
	if decl.Name != nil {
		c.checkText(decl.Name.Name, decl.Name.NamePos)
	}
	if decl.Type == nil || decl.Type.Params == nil {
		return
	}
	for _, field := range decl.Type.Params.List {
		c.walkField(field)
	}
}

// walkStructFields walks each field in a struct type, inspecting names, docs, and tags.
func (c *misspellingContext) walkStructFields(st *ast.StructType) {
	if st.Fields == nil {
		return
	}
	for _, field := range st.Fields.List {
		c.walkField(field)
	}
}

// walkField inspects a single field's doc, names, and struct tag for misspellings.
func (c *misspellingContext) walkField(field *ast.Field) {
	c.checkComments(field.Doc)
	for _, name := range field.Names {
		c.checkText(name.Name, name.NamePos)
	}
	if field.Tag != nil {
		c.checkText(field.Tag.Value, field.Tag.ValuePos)
	}
}

// walkValueSpec inspects the doc and names attached to a value spec.
func (c *misspellingContext) walkValueSpec(spec *ast.ValueSpec) {
	c.checkComments(spec.Doc)
	for _, name := range spec.Names {
		c.checkText(name.Name, name.NamePos)
	}
}

// dictionary returns the merged default and user-supplied misspelling dictionary.
func (r MisspellingRule) dictionary() map[string]string {
	out := make(map[string]string, len(defaultMisspellingDictionary)+len(r.Extra))
	for wrong, right := range defaultMisspellingDictionary {
		out[wrong] = right
	}
	for wrong, right := range r.Extra {
		key := strings.ToLower(strings.TrimSpace(wrong))
		value := strings.TrimSpace(right)
		if key != "" && value != "" {
			out[key] = value
		}
	}
	return out
}

// ignoreSet normalises the configured ignore list into a lookup set of lowercase tokens.
func (r MisspellingRule) ignoreSet() map[string]bool {
	out := make(map[string]bool, len(r.Ignore))
	for _, name := range r.Ignore {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			out[strings.ToLower(trimmed)] = true
		}
	}
	return out
}

// tokenizeForMisspelling splits text into lowercase word tokens, respecting camelCase boundaries.
func tokenizeForMisspelling(text string) []string {
	runes := []rune(text)
	var tokens []string
	start := 0
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if !unicode.IsLetter(r) {
			if i > start {
				tokens = append(tokens, strings.ToLower(string(runes[start:i])))
			}
			start = i + 1
			continue
		}
		if i == start {
			continue
		}
		if shouldSplitMisspellingToken(runes, i) {
			tokens = append(tokens, strings.ToLower(string(runes[start:i])))
			start = i
		}
	}
	if len(runes) > start {
		tokens = append(tokens, strings.ToLower(string(runes[start:])))
	}
	return tokens
}

// shouldSplitMisspellingToken reports whether position i marks a camelCase word boundary.
func shouldSplitMisspellingToken(runes []rune, i int) bool {
	prev := runes[i-1]
	cur := runes[i]
	if unicode.IsLower(prev) && unicode.IsUpper(cur) {
		return true
	}
	if i+1 < len(runes) && unicode.IsUpper(prev) && unicode.IsUpper(cur) && unicode.IsLower(runes[i+1]) {
		return true
	}
	return false
}
