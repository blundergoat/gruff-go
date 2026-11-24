// Read suppression comments before findings reach the score, gate, and report.
//
// The filter recognizes supported checks in Go, YAML, and dotenv comments. It keeps their removal visible in the suppression audit.
// Use this path for directives written beside a finding or alone on the preceding line.
package analysis

import (
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// SuppressionSourceInline marks an audit row that another tool's suppression comment produced.
//
// ApplyInlineSuppressions sets it as the Source of each row it appends; rows for built-in suppressions carry SuppressionSourceBuiltIn.
const SuppressionSourceInline = "inline"

// InlineSuppressionReason is the reason on each inline audit row; every port publishes these exact words (FAMILY-CONTRACT.md section 13c).
//
// It is also the justification on each suppressed finding, which a SARIF reader sees on the suppressed result.
const InlineSuppressionReason = "Another tool's suppression comment names this check, so the finding is suppressed where it was written."

// SuppressedFinding holds a finding and the reason its source comment suppressed it.
//
// The ordinary findings list and score omit it.
// SARIF keeps it as a suppressed result so code scanning can distinguish it from a fix.
type SuppressedFinding struct {
	// Finding is the suppressed finding as the rule reported it.
	Finding finding.Finding
	// Justification is the audit reason a SARIF reader sees on the suppressed result.
	Justification string
}

// gosecCheckRules maps each gosec check that section 13c names for gruff-go to the rule that makes the same claim.
//
// G101, hard-coded credentials, is not listed; it covers every sensitive-data rule through gosecCredentialCheck.
// Any other named check, such as G304, adds no suppression; mapped checks in the same list still cover their rules.
var gosecCheckRules = map[string]string{
	"G112": "security.http-server-no-timeout",
	"G402": "security.tls-insecure-config",
	"G204": "security.shell-command",
}

// zizmorCheckRules maps each zizmor audit section 13c names to the workflow rule that makes the same claim.
// An unmapped audit name adds no suppression; mapped audits in the same comment still cover their rules.
var zizmorCheckRules = map[string]string{
	"unpinned-uses":      "security.github-actions-unpinned-action",
	"dangerous-triggers": "security.github-actions-pull-request-target",
}

// gosecCredentialCheck is gosec's hard-coded-credentials check, which makes every sensitive-data rule's claim.
const gosecCredentialCheck = "G101"

// functionLengthRule is the rule golangci-lint's `funlen` linter covers.
const functionLengthRule = "size.function-length"

// gosecCode matches one canonical uppercase gosec check code such as G204.
var gosecCode = regexp.MustCompile(`^G\d+$`)

// nolintDirective matches golangci-lint's `//nolint` anchored to the start of a Go line comment, e.g. `//nolint:funlen,gosec`.
var nolintDirective = regexp.MustCompile(`^//nolint(?::([\w,-]+))?(?:[^\w:,-]|$)`)

// zizmorDirective matches zizmor's `# zizmor: ignore[...]` directive anchored to the start of a YAML hash comment.
var zizmorDirective = regexp.MustCompile(`^#\s*zizmor:\s*ignore\[([^\]]*)\]`)

// ApplyInlineSuppressions honors supported comments beside a finding or alone on the preceding line.
//
// sources holds source text by finding path. Without text for a path, its findings stay visible.
// Returns visible findings in order, summaries with one row per path and rule after built-in rows, and suppressed findings with their justification.
// When no directive matches, summaries keeps its original rows.
func ApplyInlineSuppressions(findings []finding.Finding, summaries []SuppressionSummary, sources map[string]string) ([]finding.Finding, []SuppressionSummary, []SuppressedFinding) {
	type fileAndRule struct{ file, rule string }
	countByFileAndRule := map[fileAndRule]int{}
	commentsByFile := map[string]map[int][]inlineComment{}
	kept := make([]finding.Finding, 0, len(findings))
	suppressed := []SuppressedFinding{}
	// Each finding gets its own decision, even when another finding on the same line has a covered rule.
	for _, item := range findings {
		comments, read := commentsByFile[item.File]
		// A file can have several findings. Read its comments once so all of its findings use the same line lookup.
		if !read {
			comments = suppressionCommentsByLine(item.File, sources[item.File])
			commentsByFile[item.File] = comments
		}
		// Findings without a matching directive still reach the score, exit gate, and report.
		if !isSuppressedInline(comments, item) {
			kept = append(kept, item)
			continue
		}
		countByFileAndRule[fileAndRule{item.File, item.RuleID}]++
		suppressed = append(suppressed, SuppressedFinding{Finding: item, Justification: InlineSuppressionReason})
	}
	keys := make([]fileAndRule, 0, len(countByFileAndRule))
	for key := range countByFileAndRule {
		keys = append(keys, key)
	}
	// Byte order, path first and then rule id, matches the built-in rows.
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].file != keys[right].file {
			return keys[left].file < keys[right].file
		}
		return keys[left].rule < keys[right].rule
	})
	nextIndex := 0
	for _, summary := range summaries {
		if summary.Source == SuppressionSourceBuiltIn {
			nextIndex++
		}
	}
	for offset, key := range keys {
		summaries = append(summaries, SuppressionSummary{
			Index:      nextIndex + offset,
			Rule:       key.rule,
			Paths:      []string{key.file},
			Reason:     InlineSuppressionReason,
			Suppressed: countByFileAndRule[key],
			Source:     SuppressionSourceInline,
		})
	}
	return kept, summaries, suppressed
}

// sourcesByFile indexes each parsed file's text by the path a finding carries, which may be absolute for an input outside the analysis root.
// It returns a map from the File.Path of each parsed unit in units to its Source, which is empty, not nil, when units is empty.
func sourcesByFile(units []parser.Unit) map[string]string {
	sources := make(map[string]string, len(units))
	for _, unit := range units {
		sources[unit.File.Path] = unit.Source
	}
	return sources
}

// inlineComment holds source comment text and whether it stands alone on its line.
//
// A standalone comment can cover a finding on the following line.
// Any matching comment can cover a finding on its own line.
type inlineComment struct {
	text       string
	standalone bool
}

// suppressionCommentsByLine indexes comments in text by line for the source syntax identified by path.
// A nil or empty result means the file supplies no suppression comments for the findings.
func suppressionCommentsByLine(path, text string) map[int][]inlineComment {
	// Most files contain no directive text, so they need no comment scan.
	if !strings.Contains(text, "#nosec") && !strings.Contains(text, "nolint") && !strings.Contains(text, "zizmor") {
		return nil
	}
	comments := map[int][]inlineComment{}
	extension := strings.ToLower(filepath.Ext(path))
	switch {
	case extension == ".go":
		line, lastCommentOffset := 1, 0
		parser.ScanGoTokens(text, func(kind token.Token, offset int, literal string) {
			// Directive text inside a Go string stays visible to the rule that flagged the code.
			if kind != token.COMMENT {
				return
			}
			line += strings.Count(text[lastCommentOffset:offset], "\n")
			lastCommentOffset = offset
			start := strings.LastIndexByte(text[:offset], '\n') + 1
			end := offset + len(literal)
			trailing := text[end:]
			if newline := strings.IndexByte(trailing, '\n'); newline >= 0 {
				trailing = trailing[:newline]
			}
			// A comment stands alone only when nothing precedes or follows it on its line, so `/* #nosec */ code` never covers the next line.
			standalone := strings.TrimSpace(text[start:offset]) == "" && strings.TrimSpace(trailing) == "" && !strings.Contains(literal, "\n")
			comments[line] = append(comments[line], inlineComment{literal, standalone})
		})
	case extension == ".yaml" || extension == ".yml":
		return hashSuppressionComments(text, true)
	case extension == ".env" || strings.HasPrefix(filepath.Base(path), ".env"):
		return hashSuppressionComments(text, false)
	}
	return comments
}

// yamlBlockMarker recognizes literal and folded YAML block indicators.
var yamlBlockMarker = regexp.MustCompile(`(?:^|:\s+|-\s+)[|>]([1-9+-]{0,2})\s*$`)

// hashSuppressionComments returns the comments in text for YAML or dotenv findings.
// Set yaml to protect literal and folded blocks as data. A file with no comments gives an empty map.
func hashSuppressionComments(text string, yaml bool) map[int][]inlineComment {
	comments, blockParent, blockContent := map[int][]inlineComment{}, -1, -1
	var quote byte
	// A workflow block or quoted value can span lines, so carry its state across the whole file.
	for number, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		indent := len(line) - len(trimmed)
		// Blank lines inside a block carry no comment and leave the block open.
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		// A YAML author who omits the indentation indicator sets the content column with the first indented line.
		if blockParent >= 0 && blockContent < 0 && indent > blockParent {
			blockContent = indent
		}
		// An indented shell command or sample in a YAML block cannot turn into a suppression.
		if blockContent >= 0 && indent >= blockContent {
			continue
		}
		blockParent, blockContent = -1, -1
		offset := hashCommentOffset(line, &quote)
		// Only a hash outside the value can start a comment for the rule or the next line.
		if offset >= 0 {
			comments[number+1] = []inlineComment{{line[offset:], offset == indent}}
			line = line[:offset]
		}
		// A quoted pipe is part of the value. A YAML block header can protect later lines from being read as directives.
		if yaml && quote == 0 {
			blockParent, blockContent = yamlBlockColumns(line, indent)
		}
	}
	return comments
}

// yamlBlockColumns returns the parent and explicit content columns of a YAML block header.
//
// indent is the number of leading spaces or tabs on line.
// A missing header yields two negative columns. An implicit content column stays negative until the first content line.
func yamlBlockColumns(line string, indent int) (int, int) {
	marker := yamlBlockMarker.FindStringSubmatch(line)
	// An ordinary YAML line starts no block, so later suppression comments are still eligible.
	if marker == nil {
		return -1, -1
	}
	// In a list item like "- run: |2", indentation is measured from the key so the whole script stays protected.
	if line[indent] == '-' && strings.HasPrefix(marker[0], ":") {
		start := line[indent+1:]
		indent += 1 + len(start) - len(strings.TrimLeft(start, " \t"))
	}
	// An explicit digit fixes the content column even when the first script line is more deeply indented.
	if digit := strings.IndexAny(marker[1], "123456789"); digit >= 0 {
		return indent, indent + int(marker[1][digit]-'0')
	}
	return indent, -1
}

// hashCommentOffset updates quote state for line and returns the hash offset, or -1 when the line has no comment outside a scalar.
func hashCommentOffset(line string, quote *byte) int {
	// Read quotes and escapes in order so a hash typed inside a config value stays part of that value.
	for i := 0; i < len(line); i++ {
		b := line[i]
		atBoundary := i == 0 || strings.ContainsRune(" \t:[{,=", rune(line[i-1]))
		switch {
		case *quote == '"' && b == '\\':
			i++
		case *quote == '\'' && b == '\'' && i+1 < len(line) && line[i+1] == '\'':
			i++
		case *quote != 0 && b == *quote:
			*quote = 0
		case *quote == 0 && atBoundary && (b == '"' || b == '\''):
			*quote = b
		case *quote == 0 && b == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t'):
			return i
		}
	}
	return -1
}

// isSuppressedInline reports whether comments on or immediately above item cover it, using the line index in comments.
// A finding without a line or matching comment stays visible.
func isSuppressedInline(comments map[int][]inlineComment, item finding.Finding) bool {
	// A file-wide finding has no line to which an inline directive can attach.
	if item.Location == nil || item.Location.Line < 1 {
		return false
	}
	line := item.Location.Line
	// A directive beside a reported line can cover that finding, even after executable code.
	for _, comment := range comments[line] {
		// An unrelated directive leaves the finding visible, even when it suppresses a different check on the same line.
		if inlineCommentCovers(comment.text, item) {
			return true
		}
	}
	// A directive beside a different line of code belongs to that line, so only a standalone comment can carry forward.
	for _, comment := range comments[line-1] {
		// A matching directive above this line carries over only when it stands alone.
		if comment.standalone && inlineCommentCovers(comment.text, item) {
			return true
		}
	}
	return false
}

// inlineCommentCovers reports whether one line names a check section 13c maps to the finding's rule.
//
// A bare #nosec, //nolint, //nolint:all or //nolint:gosec covers every security and sensitive-data rule, as gosec and golangci-lint read them.
//
// A bare //nolint or //nolint:all also covers size.function-length, the funlen rule.
// A #nosec naming checks covers only those the table lists, so #nosec G304 covers nothing and #nosec G101 covers every sensitive-data rule.
//
// The line is checked for gosec, golangci-lint and zizmor directives against the rule of item.
// The item counts as broad when its pillar is security or its rule ID has the sensitive-data prefix.
func inlineCommentCovers(line string, item finding.Finding) bool {
	broad := item.Pillar == finding.PillarSecurity || strings.HasPrefix(item.RuleID, "sensitive-data.")
	return gosecCommentCovers(line, item.RuleID, broad) || nolintCommentCovers(line, item.RuleID, broad) ||
		zizmorCommentCovers(line, item.RuleID)
}

// gosecCommentCovers reports whether line starts with a #nosec directive that suppresses ruleID.
//
// Prose mentioning #nosec later in a comment is ignored, and malformed lists such as #nosec: G304 or #nosec g304 never fall back to bare #nosec.
// Canonical G-codes cover only their mapped rules (with G101 covering all sensitive-data rules); bare #nosec or #nosec -- note requires broad=true.
//
// Returns false when line is empty, is not a comment starting with #nosec, or names no check covering ruleID.
func gosecCommentCovers(line, ruleID string, broad bool) bool {
	commentBody, ok := commentDirectiveBody(line)
	if !ok || !strings.HasPrefix(commentBody, "#nosec") {
		return false
	}
	afterMarker := commentBody[len("#nosec"):]
	// Reject longer tokens such as #nosec_note that merely share the prefix.
	if afterMarker != "" && afterMarker[0] != ' ' && afterMarker[0] != '\t' && afterMarker[0] != ':' {
		return false
	}
	directiveRest := strings.TrimLeft(afterMarker, " \t")
	// Bare `#nosec` or `#nosec -- rationale` applies to every security and sensitive-data finding.
	if directiveRest == "" || strings.HasPrefix(directiveRest, "--") {
		return broad
	}
	checkList, _, _ := strings.Cut(directiveRest, "--")
	checkList = strings.TrimSpace(strings.TrimPrefix(checkList, ":"))
	// A colon or check list with no recognised mapped check never degrades to wildcard bare #nosec.
	if checkList == "" {
		return false
	}
	// Check each comma- or whitespace-separated token so a developer listing multiple G-codes suppresses every matching rule.
	for _, token := range strings.FieldsFunc(checkList, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if !gosecCode.MatchString(token) {
			continue
		}
		if gosecCheckRules[token] == ruleID || (token == gosecCredentialCheck && strings.HasPrefix(ruleID, "sensitive-data.")) {
			return true
		}
	}
	return false
}

// commentDirectiveBody strips the leading Go or hash comment syntax from raw and returns the trimmed directive text and true.
// It returns an empty string and false when raw does not begin with a supported comment opener.
func commentDirectiveBody(raw string) (string, bool) {
	switch {
	case strings.HasPrefix(raw, "//"):
		return strings.TrimSpace(raw[2:]), true
	case strings.HasPrefix(raw, "/*"):
		return strings.TrimSpace(strings.TrimSuffix(raw[2:], "*/")), true
	case strings.HasPrefix(raw, "#nosec"):
		return strings.TrimSpace(raw), true
	case strings.HasPrefix(raw, "#"):
		return strings.TrimSpace(raw[1:]), true
	default:
		return "", false
	}
}

// nolintCommentCovers reports whether a //nolint on the line covers the rule; a bare //nolint counts as //nolint:all.
//
// Each listed linter, or all for a bare one, is checked against ruleID with nolintLinterCovers.
// The broad flag marks a security or sensitive-data finding.
func nolintCommentCovers(line, ruleID string, broad bool) bool {
	for _, match := range nolintDirective.FindAllStringSubmatch(line, -1) {
		linters := []string{"all"}
		if match[1] != "" {
			linters = strings.Split(match[1], ",")
		}
		for _, linter := range linters {
			if nolintLinterCovers(linter, ruleID, broad) {
				return true
			}
		}
	}
	return false
}

// nolintLinterCovers reports whether one golangci-lint linter name covers the rule.
//
// The names all and gosec cover every security and sensitive-data rule, and all and funlen cover size.function-length.
// The ruleID is the finding's rule and broad marks a security or sensitive-data finding; any other linter name covers nothing.
func nolintLinterCovers(linter, ruleID string, broad bool) bool {
	switch linter {
	case "all":
		return broad || ruleID == functionLengthRule
	case "gosec":
		return broad
	case "funlen":
		return ruleID == functionLengthRule
	}
	return false
}

// zizmorCommentCovers reports whether a zizmor ignore comment on the line names an audit mapped to the rule.
// Audits are comma-separated and trimmed, and ruleID must equal the rule zizmorCheckRules maps an audit to; unknown audits cover nothing.
func zizmorCommentCovers(line, ruleID string) bool {
	for _, match := range zizmorDirective.FindAllStringSubmatch(line, -1) {
		for _, audit := range strings.Split(match[1], ",") {
			if zizmorCheckRules[strings.TrimSpace(audit)] == ruleID {
				return true
			}
		}
	}
	return false
}
