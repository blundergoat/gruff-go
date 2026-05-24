// Package rule defines gruff-go's rule registry and analysers.
// This file implements documentation checks for suppression comments.
package rule

import (
	"strings"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// SuppressionWithoutRationaleRule flags tool suppression comments that omit the reason.
type SuppressionWithoutRationaleRule struct{}

// Definition declares the docs.suppression-without-rationale rule for suppression comments.
func (SuppressionWithoutRationaleRule) Definition() Definition {
	return Definition{
		ID:             "docs.suppression-without-rationale",
		Title:          "Suppression without rationale",
		Description:    "Flags nolint and nosec suppression comments that do not explain why the suppression is intentional.",
		Pillar:         finding.PillarDocumentation,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"comments", "documentation"},
		Remediation:    "Add a short reason after the suppression, such as `-- false positive because ...` or `// tracked in ISSUE-123`.",
	}
}

// AnalyzeUnit emits findings for suppression directives that contain no rationale.
func (SuppressionWithoutRationaleRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.Source == "" || hasGeneratedHeader(unit.Source) || isVendorPath(unit.File.Path) {
		return nil
	}
	if unit.AST != nil && unit.FileSet != nil {
		return suppressionFindingsFromGoComments(unit)
	}
	findings := []finding.Finding{}
	lines := strings.Split(unit.Source, "\n")
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

// suppressionFindingsFromGoComments emits findings only for actual Go comments, not raw string examples.
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
	Text   string
	Line   int
	Column int
}

// parsedComments normalizes Go comments while preserving file positions.
func parsedComments(unit parser.Unit) []parsedComment {
	comments := []parsedComment{}
	for _, group := range unit.AST.Comments {
		for _, comment := range group.List {
			position := unit.FileSet.Position(comment.Pos())
			comments = append(comments, parsedComment{
				Text:   cleanCommentText(comment.Text),
				Line:   position.Line,
				Column: position.Column,
			})
		}
	}
	return comments
}

// cleanCommentText strips Go comment delimiters from one parsed comment.
func cleanCommentText(text string) string {
	text = strings.TrimSpace(strings.TrimPrefix(text, "//"))
	text = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(text, "/*"), "*/"))
	return text
}

// suppressionDirectiveTail returns a leading suppression directive and the trailing text after it.
func suppressionDirectiveTail(line string) (string, string, bool) {
	if strings.HasPrefix(line, "nolint") {
		return "nolint", line[len("nolint"):], true
	}
	if strings.HasPrefix(line, "#nosec") {
		return "nosec", line[len("#nosec"):], true
	}
	return "", "", false
}

// suppressionHasRationale reports whether trailing suppression text contains a human reason.
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
func nearbyCommentHasRationale(comments []parsedComment, index int) bool {
	line := comments[index].Line
	for _, neighbor := range []int{index - 1, index + 1} {
		if neighbor < 0 || neighbor >= len(comments) {
			continue
		}
		if absInt(comments[neighbor].Line-line) <= 1 && explicitRationaleComment(comments[neighbor].Text) {
			return true
		}
	}
	return false
}

// nearbyLineHasRationale accepts an immediately adjacent explicit rationale line in text units.
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

// explicitRationaleComment reports whether text starts with a rationale marker plus reason words.
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
func trimSuppressionRuleList(rest string) string {
	index := strings.IndexAny(rest, " \t/")
	if index < 0 {
		return ""
	}
	return rest[index:]
}

// trimNoSecCodes removes leading gosec rule codes such as G101 or G204.
func trimNoSecCodes(rest string) string {
	fields := strings.Fields(rest)
	trimmed := 0
	for trimmed < len(fields) && looksLikeNoSecCode(fields[trimmed]) {
		trimmed++
	}
	if trimmed == 0 {
		return rest
	}
	return strings.Join(fields[trimmed:], " ")
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

// hasReasonWord requires at least one alphabetic word outside punctuation and rule lists.
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

// isVendorPath reports whether a path is under a vendored dependency tree.
func isVendorPath(path string) bool {
	clean := strings.ReplaceAll(path, "\\", "/")
	return strings.HasPrefix(clean, "vendor/") || strings.Contains(clean, "/vendor/")
}
