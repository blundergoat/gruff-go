// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements docs.suppression-without-rationale, which flags nolint and nosec comments that give no reason for the suppression.
// The rule emits one finding per unexplained directive; vendored files and skipped generated files report nothing.
package rule

import (
	"go/ast"
	"strings"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// SuppressionWithoutRationaleRule flags tool suppression comments that omit the reason.
//
// It backs docs.suppression-without-rationale, on by default, with one finding per nolint or nosec directive that gives no reason.
// A reason after the directive, an adjacent reason: comment, or in a parsed file a free-standing prose block right above it clears the finding.
type SuppressionWithoutRationaleRule struct{}

// Definition declares the docs.suppression-without-rationale rule for suppression comments.
// It returns the same fixed metadata on every call: advisory severity, medium confidence, the documentation pillar, and enabled by default.
func (SuppressionWithoutRationaleRule) Definition() Definition {
	return Definition{
		ID:             "docs.suppression-without-rationale",
		Title:          "Suppression without rationale",
		Description:    "Flags nolint and nosec suppression comments that do not explain why the suppression is intentional.",
		Pillar:         finding.PillarDocumentation,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"comments", "documentation"},
		Remediation:    "Add a short reason after the suppression, such as `-- false positive because ...` or `// tracked in ISSUE-123`.",
	}
}

// AnalyzeUnit emits findings for suppression directives that contain no rationale.
//
// When unit has a parsed AST and FileSet, only real Go comments are checked; otherwise only trimmed lines starting with nolint or #nosec are checked.
// ctx is passed to shouldSkipGeneratedUnit, which decides whether a generated unit is skipped.
// It returns one finding per checked directive lacking a rationale, and nil for an empty source, a skipped generated unit or a vendored path.
func (SuppressionWithoutRationaleRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.Source == "" || shouldSkipGeneratedUnit(unit, ctx) || isVendorPath(unit.File.Path) {
		return nil
	}
	if unit.AST != nil && unit.FileSet != nil {
		return suppressionFindingsFromGoComments(unit)
	}
	findings := []finding.Finding{}
	lines := strings.Split(unit.Source, "\n")
	// Without a parse tree only a trimmed line that begins with the bare directive word matches, so a line written with comment slashes is missed.
	for lineNumber, line := range lines {
		directive, rest, ok := suppressionDirectiveTail(strings.TrimSpace(line))
		if !ok || suppressionHasRationale(rest) || nearbyLineHasRationale(lines, lineNumber) {
			continue
		}
		findings = append(findings, finding.Finding{
			Message:  "suppression comment lacks a rationale",
			File:     unit.File.Path,
			Location: &finding.Location{Line: lineNumber + 1},
			Metadata: map[string]any{"directive": directive},
		})
	}
	return findings
}

// suppressionFindingsFromGoComments emits findings only for actual Go comments, so a directive quoted inside a string literal is never flagged.
//
// The unit must carry the parsed AST and FileSet that AnalyzeUnit checks for; each finding records the comment's line, column and directive.
// It returns one finding per directive comment that lacks a rationale, and an empty slice when every directive is explained.
func suppressionFindingsFromGoComments(unit parser.Unit) []finding.Finding {
	comments := parsedComments(unit)
	findings := []finding.Finding{}
	for index, comment := range comments {
		directive, rest, ok := suppressionDirectiveTail(comment.Text)
		if !ok || suppressionHasRationale(rest) || nearbyCommentHasRationale(comments, index) {
			continue
		}
		findings = append(findings, finding.Finding{
			Message:  "suppression comment lacks a rationale",
			File:     unit.File.Path,
			Location: &finding.Location{Line: comment.Line, Column: comment.Column},
			Metadata: map[string]any{"directive": directive},
		})
	}
	return findings
}

// parsedComment is a normalized Go comment with source position.
type parsedComment struct {
	// Text is the comment body with its // or /* */ delimiters removed and surrounding space trimmed.
	Text string
	// Line is the 1-based line the comment starts on.
	Line int
	// Column is the 1-based column the comment starts at.
	Column int
	// InDocGroup marks a comment inside a package, declaration or field doc comment, which describes that code rather than a suppression.
	// The prose search above a directive stops at such a comment; an adjacent comment starting reason:, rationale: or because: still counts.
	InDocGroup bool
	// FreeStanding marks a comment preceded only by whitespace on its source line, so a block comment followed by code still qualifies.
	// The prose search stops at a comment trailing code, which explains that code; adjacent explicit reason: comments ignore this flag.
	FreeStanding bool
}

// parsedComments turns each comment in the file into a parsedComment, keeping its position and whether it documents a declaration.
//
// The unit must carry a parsed AST and FileSet.
// It returns one parsedComment per comment in file order, carrying its cleaned text, line, column, InDocGroup and FreeStanding flags.
// The result is an empty slice when the file has no comments.
func parsedComments(unit parser.Unit) []parsedComment {
	docLines := declarationDocLines(unit)
	sourceLines := strings.Split(unit.Source, "\n")
	comments := []parsedComment{}
	for _, group := range unit.AST.Comments {
		for _, comment := range group.List {
			position := unit.FileSet.Position(comment.Pos())
			comments = append(comments, parsedComment{
				Text:         cleanCommentText(comment.Text),
				Line:         position.Line,
				Column:       position.Column,
				InDocGroup:   docLines[position.Line],
				FreeStanding: commentStartsItsLine(sourceLines, position.Line, position.Column),
			})
		}
	}
	return comments
}

// declarationDocLines records the line each comment starts on in the package doc and in every declaration's doc comment.
//
// A doc group sits where a rationale would but explains the declaration, so "Execute runs the command." cannot excuse a nolint below it.
//
// It reads the package doc and the Doc of every FuncDecl, GenDecl, TypeSpec, ValueSpec and Field in unit, whose AST and FileSet must be set.
// It returns a set keyed by the line each such comment starts on, and an empty map when unit has no such comments.
// A multi-line block comment therefore marks only its first line.
func declarationDocLines(unit parser.Unit) map[int]bool {
	lines := map[int]bool{}
	record := func(group *ast.CommentGroup) {
		if group == nil {
			return
		}
		for _, comment := range group.List {
			lines[unit.FileSet.Position(comment.Pos()).Line] = true
		}
	}
	record(unit.AST.Doc)
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.FuncDecl:
			record(current.Doc)
		case *ast.GenDecl:
			record(current.Doc)
		case *ast.TypeSpec:
			record(current.Doc)
		case *ast.ValueSpec:
			record(current.Doc)
		case *ast.Field:
			record(current.Doc)
		}
		return true
	})
	return lines
}

// commentStartsItsLine reports whether only whitespace precedes a comment on its source line.
//
// Positions are 1-based, and a malformed position reports false, so the prose search cannot credit that comment as a rationale.
// An adjacent explicit reason: comment is checked separately and can still count.
//
// sourceLines holds the file split on newlines; line picks the comment's line from it and column is the comment's 1-based byte column.
func commentStartsItsLine(sourceLines []string, line int, column int) bool {
	if line < 1 || line > len(sourceLines) || column < 1 {
		return false
	}
	text := sourceLines[line-1]
	if column-1 > len(text) {
		return false
	}
	return strings.TrimSpace(text[:column-1]) == ""
}

// cleanCommentText strips Go comment delimiters from one parsed comment so the directive and reason checks see only its words.
//
// text is the raw comment as go/ast stores it; a leading // is removed, then a leading /* and trailing */ even inside a line comment.
// It returns what remains with whitespace trimmed, which is empty for a comment holding only delimiters.
func cleanCommentText(text string) string {
	text = strings.TrimSpace(strings.TrimPrefix(text, "//"))
	text = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(text, "/*"), "*/"))
	return text
}

// suppressionDirectiveTail returns a leading suppression directive and the trailing text after it.
//
// line is a cleaned comment or trimmed source line; it matches only when it begins with nolint or #nosec, giving nolint or nosec and true.
// Any other line gives two empty strings and false.
func suppressionDirectiveTail(line string) (string, string, bool) {
	if strings.HasPrefix(line, "nolint") {
		return "nolint", line[len("nolint"):], true
	}
	if strings.HasPrefix(line, "#nosec") {
		return "nosec", line[len("#nosec"):], true
	}
	return "", "", false
}

// suppressionHasRationale reports whether the text after a directive holds a human reason; a bare rule list or gosec code is not one.
//
// rest is the text after the directive; a leading colon rule list and gosec codes are dropped before hasReasonWord looks for a reason.
// An empty rest, or one holding only a rule list or codes, reports false.
func suppressionHasRationale(rest string) bool {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return false
	}
	if strings.HasPrefix(rest, ":") {
		rest = trimSuppressionRuleList(rest[1:])
	}
	rest = trimNoSecCodes(rest)
	rest = strings.TrimLeft(rest, " \t:-/")
	if rest == "" {
		return false
	}
	return hasReasonWord(rest)
}

// nearbyCommentHasRationale accepts an immediately adjacent explicit rationale comment.
//
// comments holds the file's parsed comments in order and index is the directive's position in it, which must be in range.
// It reports true when the comment just before or after, within one line, starts with reason:, rationale: or because: plus a reason word.
// Otherwise the result comes from contiguousCommentBlockExplains, so false means neither check found a rationale.
func nearbyCommentHasRationale(comments []parsedComment, index int) bool {
	line := comments[index].Line
	for _, neighbor := range []int{index - 1, index + 1} {
		if neighbor < 0 || neighbor >= len(comments) {
			continue
		}
		// This explicit check ignores InDocGroup and FreeStanding, so a reason: line in a doc comment or after code still clears the directive.
		if absInt(comments[neighbor].Line-line) <= 1 && explicitRationaleComment(comments[neighbor].Text) {
			return true
		}
	}
	return contiguousCommentBlockExplains(comments, index)
}

// contiguousCommentBlockExplains reports whether free-standing comments with consecutive start lines above the directive contain prose.
//
// Ordinary prose counts without a reason: marker, as in cobra's command.go; a line gap, a doc group or a comment trailing code stops the search.
// Free-standing directives in between are skipped, so one prose block can explain several directives stacked under it.
//
// comments holds the file's parsed comments in order, and index is the directive's position in it, which must be in range.
// Directives and comments with no reason word are passed over; a line gap, a doc-group line or a trailing comment stops the search with false.
// It reports true at the first comment above holding a word hasReasonWord accepts, and false when it runs out of comments.
func contiguousCommentBlockExplains(comments []parsedComment, index int) bool {
	expectedLine := comments[index].Line - 1
	for cursor := index - 1; cursor >= 0; cursor-- {
		candidate := comments[cursor]
		if candidate.Line != expectedLine {
			return false
		}
		expectedLine = candidate.Line - 1
		if candidate.InDocGroup || !candidate.FreeStanding {
			return false
		}
		if _, _, isDirective := suppressionDirectiveTail(candidate.Text); isDirective {
			continue
		}
		if hasReasonWord(candidate.Text) {
			return true
		}
	}
	return false
}

// nearbyLineHasRationale accepts an immediately adjacent explicit rationale line in text units.
//
// lines holds the unit source split on newlines and index is the directive line's 0-based position in it.
// It reports true when the line above or below, minus a leading // or # marker, starts with reason:, rationale: or because: plus a reason word.
// It reports false when neither neighbour exists or qualifies.
func nearbyLineHasRationale(lines []string, index int) bool {
	for _, neighbor := range []int{index - 1, index + 1} {
		if neighbor < 0 || neighbor >= len(lines) {
			continue
		}
		if explicitRationaleComment(stripLineCommentPrefix(lines[neighbor])) {
			return true
		}
	}
	return false
}

// explicitRationaleComment reports whether text starts with reason:, rationale: or because:, in any case, followed by a reason word.
// Leading space is ignored; a bare marker, or text without one, reports false.
func explicitRationaleComment(text string) bool {
	trimmed := strings.TrimSpace(text)
	lower := strings.ToLower(trimmed)
	for _, prefix := range []string{"reason:", "rationale:", "because:"} {
		if strings.HasPrefix(lower, prefix) {
			return hasReasonWord(trimmed[len(prefix):])
		}
	}
	return false
}

// stripLineCommentPrefix removes common text-file comment prefixes from rationale lines.
//
// line is one raw source line; it is trimmed, then a single leading // or # marker is removed and the remainder trimmed again.
// It returns the trimmed line unchanged when it has neither marker, and an empty string for a blank or marker-only line.
func stripLineCommentPrefix(line string) string {
	line = strings.TrimSpace(line)
	for _, prefix := range []string{"//", "#"} {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return line
}

// trimSuppressionRuleList removes a nolint rule-list prefix.
//
// rest is the directive tail after its colon, such as a comma-separated linter list followed by any explanation.
// It returns rest from the first space, tab or slash onward, and an empty string when rest has none of those, as in a bare rule list.
func trimSuppressionRuleList(rest string) string {
	index := strings.IndexAny(rest, " \t/")
	if index < 0 {
		return ""
	}
	return rest[index:]
}

// trimNoSecCodes removes leading gosec rule codes such as G101 or G204.
//
// rest is the suppression text after the directive, with any colon rule list already removed.
// It returns rest unchanged when its first word is not a gosec code, and otherwise the words after the codes joined by single spaces.
// The result is empty when rest holds nothing but codes.
func trimNoSecCodes(rest string) string {
	fields := strings.Fields(rest)
	leadingCodes := 0
	for leadingCodes < len(fields) && looksLikeNoSecCode(fields[leadingCodes]) {
		leadingCodes++
	}
	if leadingCodes == 0 {
		return rest
	}
	return strings.Join(fields[leadingCodes:], " ")
}

// looksLikeNoSecCode reports whether value is a gosec code token such as G101.
func looksLikeNoSecCode(value string) bool {
	if len(value) < 2 || value[0] != 'G' {
		return false
	}
	for _, r := range value[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// hasReasonWord requires at least one alphabetic word outside punctuation and gosec rule codes.
//
// value is comment or suppression text; fields shorter than three bytes after trimming punctuation, and gosec codes, are skipped.
// It reports true when any remaining field holds a letter, and false otherwise, so a bare nolint rule list such as errcheck still counts.
func hasReasonWord(value string) bool {
	for _, field := range strings.Fields(value) {
		field = strings.Trim(field, " \t-:/.,;#()[]{}")
		if len(field) < 3 || looksLikeNoSecCode(field) {
			continue
		}
		for _, r := range field {
			if unicode.IsLetter(r) {
				return true
			}
		}
	}
	return false
}

// absInt returns the absolute value of an int.
func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

// isVendorPath reports whether path is under a vendored dependency tree; this rule's AnalyzeUnit reports nothing for such a file.
// Backslashes count as forward slashes, so a path that starts with vendor/ or holds /vendor/ matches on Windows too.
func isVendorPath(path string) bool {
	clean := strings.ReplaceAll(path, "\\", "/")
	return strings.HasPrefix(clean, "vendor/") || strings.Contains(clean, "/vendor/")
}
