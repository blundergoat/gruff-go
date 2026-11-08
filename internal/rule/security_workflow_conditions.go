// Package rule defines gruff-go's rule registry and analysers.
//
// This file finds the lines of a GitHub Actions workflow that a pull_request_target run cannot reach.
// A job or step counts only when its own if condition is proven false for that event; trigger and secret discovery stay elsewhere, unchanged.
//
// An anchor or tab indent outside a block scalar names no lines, and a guard it cannot evaluate suppresses no warnings on its own.
package rule

import (
	"encoding/json"
	"regexp"
	"strings"
)

// workflowGuardNode is one mapping key or list item of the workflow YAML, with the 1-based inclusive line range it owns.
//
// content is the inline value after the key, or a scalar list item's text, and stays empty for a block that opens children.
// indent is the key's column, or the dash column for an item, which isItem marks; start and end bound the lines workflowGuardMark blocks.
type workflowGuardNode struct {
	key, content       string
	indent, start, end int
	isItem             bool
	children           []*workflowGuardNode
}

// workflowGuardEntry matches a key line: a plain or quoted key, or the << merge key, then a colon and the inline value.
// A structural line it does not match, such as an unquoted key with a space, ends the proof for the whole workflow unless it is a list item.
var workflowGuardEntry = regexp.MustCompile("^(?:([A-Za-z0-9_.-]+)|'([^']+)'|\"([^\"\\\\]+)\"|(<<)):\\s*(.*)$")

// workflowGuardItem matches a list marker, a dash followed by spaces or the end of the line.
// Its width moves the first key's indent past the dash, so keys on the following lines land under the same item.
var workflowGuardItem = regexp.MustCompile("^-(?: +|$)")

// workflowGuardAlias matches a YAML anchor such as &defaults or an alias such as *defaults; either one ends the proof for the whole workflow.
// An unquoted shell glob after a space, such as run: rm *tmp, matches too and has the same effect.
var workflowGuardAlias = regexp.MustCompile("(?:^|\\s)[&*][A-Za-z0-9_-]+")

// workflowGuardScalar matches a block scalar header such as | or >- written as a key's value.
// The more-indented lines below it are script text, so they are skipped rather than read as keys.
var workflowGuardScalar = regexp.MustCompile("^[|>](?:[+-]?\\d*|\\d*[+-]?)$")

// workflowGuardQuote matches one complete single- or double-quoted span at the start of its input, so a # inside quotes is not a comment.
var workflowGuardQuote = regexp.MustCompile("^(?:'(?:[^']|'')*'|\"(?:[^\"\\\\]|\\\\.)*\")")

// workflowGuardToken matches one token of the small if expression language this file can evaluate.
//
// Tokens are whitespace, a single-quoted string, a dotted name, ==, !=, &&, ||, ! and parentheses.
// Anything else, such as a number, a comparison like <, or a function call's comma, leaves the guard unknown and its warnings in place.
var workflowGuardToken = regexp.MustCompile("^(?:\\s+|'(?:[^']|'')*'|[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*|==|!=|&&|\\|\\||[!()])")

// workflowGuardIdentifier matches a dotted context name such as github.actor; it parses, but its value stays unknown and proves nothing alone.
var workflowGuardIdentifier = regexp.MustCompile("^[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*$")

// workflowUnreachableSecretLines names the workflow lines a pull_request_target run cannot reach, so a secret warning on them can be dropped.
//
// source is the workflow YAML text; a job, or a steps list item, counts only when its own if key is proven false for pull_request_target.
// It returns the 1-based lines those jobs and steps span, each mapped to true, including lines above an if key placed late in the block.
//
// The map is empty, not nil, when no guard is proven false or the structure is too ambiguous to tell which job owns a line.
// Ambiguity keeps every existing warning rather than guessing ownership.
func workflowUnreachableSecretLines(source string) map[int]bool {
	blocked := map[int]bool{}
	root := workflowGuardOwnership(source)
	// An anchor, tab indent, unclosed quote or duplicate key outside block scalar text lands here, so the whole workflow keeps its secret warnings.
	if root == nil {
		return blocked
	}
	jobs := workflowGuardChild(root, "jobs")
	// A workflow without a top-level jobs block, or with jobs written inline as a flow mapping, has no job to prove unreachable.
	if jobs == nil || jobs.content != "" {
		return blocked
	}
	for _, job := range jobs.children {
		if job.isItem || job.content != "" {
			continue
		}
		if workflowGuardRejects(job) {
			workflowGuardMark(job, blocked)
		}
		steps := workflowGuardChild(job, "steps")
		if steps == nil || steps.content != "" {
			continue
		}
		for _, step := range steps.children {
			if step.isItem && workflowGuardRejects(step) {
				workflowGuardMark(step, blocked)
			}
		}
	}
	return blocked
}

// workflowGuardChild looks only at direct children, so an if nested deeper, such as under with, never counts as the job's own guard.
// It returns the direct mapping child of parent whose key equals key, skipping list items; nil when parent has no such child.
func workflowGuardChild(parent *workflowGuardNode, key string) *workflowGuardNode {
	for _, child := range parent.children {
		if !child.isItem && child.key == key {
			return child
		}
	}
	return nil
}

// workflowGuardRejects checks node's own if against pull_request_target, the single pull request event the existing secret detector covers.
// It reports true only when node has a direct if child proven false for pull_request_target; a missing or unproven guard gives false.
func workflowGuardRejects(node *workflowGuardNode) bool {
	guard := workflowGuardChild(node, "if")
	return guard != nil && workflowEventGuardTruth(guard.content, "pull_request_target") == workflowGuardFalse
}

// workflowGuardMark blocks every line of a rejected job or step, including secret references written above its if key.
// It marks every line from node start through node end, inclusive, as true in blocked.
func workflowGuardMark(node *workflowGuardNode, blocked map[int]bool) {
	for line := node.start; line <= node.end; line++ {
		blocked[line] = true
	}
}

// workflowGuardYAMLText strips a trailing comment from one YAML line, keeping any # inside quotes, and rejects a quote that never closes.
//
// raw is one source line; an unquoted hash at its start or after a space or tab starts a comment.
// It returns the trimmed text before any comment with true, or an empty string and false when a quote before any comment never closes.
func workflowGuardYAMLText(raw string) (string, bool) {
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\'' || raw[i] == '"' {
			quoted := workflowGuardQuote.FindString(raw[i:])
			// An apostrophe in a plain value, such as name: Don't deploy, also lands here, so the whole workflow keeps its secret warnings.
			if quoted == "" {
				return "", false
			}
			i += len(quoted) - 1
			continue
		}
		if raw[i] == '#' && (i == 0 || raw[i-1] == ' ' || raw[i-1] == '\t') {
			return strings.TrimSpace(raw[:i]), true
		}
	}
	return strings.TrimSpace(raw), true
}

// workflowGuardOwnership builds the key and list-item tree of a workflow, closing every node's line range before any guard is evaluated.
//
// source is the workflow YAML text, with Windows line endings normalised first.
// It returns a root node whose children mirror the block mapping keys and list items of source, each with a 1-based inclusive line range.
// The result is nil on ambiguity, such as a tab indent, an unclosed quote, an anchor, alias, merge or duplicate key, or a stray non-key line.
func workflowGuardOwnership(source string) *workflowGuardNode {
	lines := strings.Split(strings.ReplaceAll(source, "\r\n", "\n"), "\n")
	root := &workflowGuardNode{indent: -1, start: 1, end: len(lines)}
	stack := []*workflowGuardNode{root}
	scalarIndent := -1
	for index, raw := range lines {
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		indent := leadingSpaces(raw)
		// Lines indented under a block scalar such as run: | are script text, so they are skipped instead of being read as keys.
		if scalarIndent >= 0 && indent > scalarIndent {
			continue
		}
		scalarIndent = -1
		if strings.HasPrefix(raw[indent:], "\t") {
			return nil
		}
		text, ok := workflowGuardYAMLText(raw)
		if !ok {
			return nil
		}
		prefix := workflowGuardItem.FindString(text)
		parent := workflowGuardParent(&stack, indent, index, prefix, len(lines))
		if parent == nil {
			return nil
		}
		node := workflowGuardAppend(parent, text, prefix, &workflowGuardNode{indent: indent, start: index + 1, end: len(lines)})
		if node == nil {
			return nil
		}
		if node != parent {
			stack = append(stack, node)
		}
		if workflowGuardScalar.MatchString(node.content) {
			scalarIndent = node.indent
		}
	}
	return root
}

// workflowGuardParent closes sibling scopes before attaching another list item.
//
// stack holds the open nodes; each at indent or deeper is popped with its end set to index, the zero-based position of the current line.
// With an empty prefix it returns the enclosing node; otherwise it pushes and returns a new item spanning line index plus one to total.
// The result is nil when the enclosing node has inline content or already holds children of the other kind, keys versus items.
func workflowGuardParent(stack *[]*workflowGuardNode, indent, index int, prefix string, total int) *workflowGuardNode {
	for len(*stack) > 1 && (*stack)[len(*stack)-1].indent >= indent {
		(*stack)[len(*stack)-1].end = index
		*stack = (*stack)[:len(*stack)-1]
	}
	parent := (*stack)[len(*stack)-1]
	if parent.content != "" {
		return nil
	}
	for _, child := range parent.children {
		if child.isItem != (prefix != "") {
			return nil
		}
	}
	if prefix == "" {
		return parent
	}
	item := &workflowGuardNode{indent: indent, start: index + 1, end: total, isItem: true}
	parent.children = append(parent.children, item)
	*stack = append(*stack, item)
	return item
}

// workflowGuardAppend vetoes duplicates and YAML aliases; scalar lists cannot own guards.
//
// text is the trimmed, comment-free line and prefix its list marker, if any; node is the prepared entry that receives the key and content.
// It returns node, appended to parent with its indent moved past prefix, or parent itself after a scalar list item's text becomes its content.
// The result is nil for an anchor or alias, a merge key, a key parent already has, or a non-key line without a list prefix.
func workflowGuardAppend(parent *workflowGuardNode, text, prefix string, node *workflowGuardNode) *workflowGuardNode {
	if workflowGuardAlias.MatchString(text) {
		return nil
	}
	entry := workflowGuardEntry.FindStringSubmatch(text[len(prefix):])
	if entry == nil {
		if prefix == "" {
			return nil
		}
		parent.content = text[len(prefix):]
		return parent
	}
	key := ""
	for _, candidate := range entry[1:5] {
		if candidate != "" {
			key = candidate
			break
		}
	}
	content := entry[5]
	if key == "<<" {
		return nil
	}
	for _, child := range parent.children {
		if child.key == key {
			return nil
		}
	}
	node.key = key
	node.content = content
	node.indent += len(prefix)
	parent.children = append(parent.children, node)
	return node
}

// workflowGuardTruth is what this file can prove about an if condition, not its runtime value for arbitrary context data.
//
// Only workflowGuardFalse lets a job or step's own guard block its lines; workflowGuardUnknown and workflowGuardTrue block nothing.
type workflowGuardTruth uint8

const (
	// workflowGuardUnknown is the zero value: nothing was proven, so this guard blocks no lines.
	workflowGuardUnknown workflowGuardTruth = iota
	// workflowGuardFalse proves this event cannot reach the guarded scope, so its lines are blocked.
	workflowGuardFalse
	// workflowGuardTrue proves the condition true for this event; an enclosing job's false guard can still block a step's lines.
	workflowGuardTrue
)

// workflowGuardOperand is one parsed operand: kind is event for github.event_name, literal for a quoted string, or truth for anything else.
// literal holds the unquoted string text, and only a truth operand carries proof in truth.
type workflowGuardOperand struct {
	kind    string
	literal string
	truth   workflowGuardTruth
}

// workflowGuardParser parses if expression branches without short-circuiting, so a malformed later branch still voids the proof.
//
// event is the run's event name compared against string literals, and position is the next token to read.
// Its caller, workflowEventGuardTruth, gives workflowGuardUnknown when isValid is false or any token is left unconsumed.
type workflowGuardParser struct {
	tokens   []string
	position int
	isValid  bool
	event    string
}

// workflowEventGuardTruth evaluates one if value for event, after removing YAML quoting and the dollar-brace expression wrapper.
//
// content is the raw if value and event the event name assumed to trigger the run, matched case-insensitively against string literals.
// It returns workflowGuardFalse or workflowGuardTrue only when every token parses into one complete, valid expression.
// Bad quoting, an unclosed wrapper, an unknown token, more than 128 tokens or an empty expression all give workflowGuardUnknown.
func workflowEventGuardTruth(content, event string) workflowGuardTruth {
	expression := strings.TrimSpace(content)
	if strings.HasPrefix(expression, "\"") {
		if json.Unmarshal([]byte(expression), &expression) != nil {
			return workflowGuardUnknown
		}
	} else if strings.HasPrefix(expression, "'") {
		if !regexp.MustCompile("^'(?:[^']|'')*'$").MatchString(expression) {
			return workflowGuardUnknown
		}
		expression = strings.ReplaceAll(expression[1:len(expression)-1], "''", "'")
	}
	expression = strings.TrimSpace(expression)
	if strings.HasPrefix(expression, "$"+"{{") {
		if !strings.HasSuffix(expression, "}}") {
			return workflowGuardUnknown
		}
		expression = strings.TrimSpace(expression[3 : len(expression)-2])
	}
	tokens := []string{}
	for expression != "" {
		token := workflowGuardToken.FindString(expression)
		if token == "" {
			return workflowGuardUnknown
		}
		if strings.TrimSpace(token) != "" {
			tokens = append(tokens, token)
		}
		expression = expression[len(token):]
		if len(tokens) > 128 {
			return workflowGuardUnknown
		}
	}
	if len(tokens) == 0 {
		return workflowGuardUnknown
	}
	state := workflowGuardParser{tokens: tokens, isValid: true, event: event}
	result := state.disjunction()
	if !state.isValid || state.position != len(tokens) {
		return workflowGuardUnknown
	}
	return result
}

// peek returns the next token without consuming it, or an empty string once every token is read, so parsing never reads past the slice.
func (state *workflowGuardParser) peek() string {
	if state.position >= len(state.tokens) {
		return ""
	}
	return state.tokens[state.position]
}

// unary preserves negation precedence; non-boolean operands remain unknown.
//
// It advances state.position past the operand, and sets state.isValid to false on an absent or unexpected token or an unclosed parenthesis.
// It returns a literal operand for a quoted string, an event operand for github.event_name, and otherwise a truth operand.
// Negation flips proven truth and a bare identifier stays workflowGuardUnknown.
func (state *workflowGuardParser) unary() workflowGuardOperand {
	token := state.peek()
	state.position++
	if token == "!" {
		operand := state.unary()
		result := operand.truth
		if operand.kind != "truth" {
			result = workflowGuardUnknown
		}
		if result == workflowGuardFalse {
			result = workflowGuardTrue
		} else if result == workflowGuardTrue {
			result = workflowGuardFalse
		}
		return workflowGuardOperand{kind: "truth", truth: result}
	}
	if token == "(" {
		result := state.disjunction()
		if state.peek() != ")" {
			state.isValid = false
		}
		state.position++
		return workflowGuardOperand{kind: "truth", truth: result}
	}
	if strings.HasPrefix(token, "'") {
		return workflowGuardOperand{kind: "literal", literal: strings.ReplaceAll(token[1:len(token)-1], "''", "'")}
	}
	if token == "github.event_name" {
		return workflowGuardOperand{kind: "event"}
	}
	if !workflowGuardIdentifier.MatchString(token) {
		state.isValid = false
	}
	// Any other context name, including true and false, is accepted with unknown truth, so a bare if: false never blocks a job or step.
	return workflowGuardOperand{kind: "truth"}
}

// comparison proves only exact event-name comparisons to a string literal.
//
// It advances state.position over one operand, or two around == or !=, and an invalid token there sets state.isValid to false.
// It returns workflowGuardTrue or workflowGuardFalse when github.event_name is compared by == or != with a quoted literal, ignoring case.
// Other comparisons give workflowGuardUnknown; with no operator the result is the left operand's truth, unknown for a bare literal or event.
func (state *workflowGuardParser) comparison() workflowGuardTruth {
	left := state.unary()
	operator := state.peek()
	if operator != "==" && operator != "!=" {
		return left.truth
	}
	state.position++
	right := state.unary()
	literal := ""
	if left.kind == "event" && right.kind == "literal" {
		literal = right.literal
	} else if right.kind == "event" && left.kind == "literal" {
		literal = left.literal
	} else {
		return workflowGuardUnknown
	}
	equal := strings.EqualFold(state.event, literal)
	if equal == (operator == "==") {
		return workflowGuardTrue
	}
	return workflowGuardFalse
}

// conjunction combines an && chain where one proven-false operand is enough, as in github.event_name == 'push' && github.actor == 'bot'.
//
// It advances state.position through the && chain even after a false operand, and unary may set state.isValid to false on a bad token.
// It returns workflowGuardFalse if any && operand is proven false, workflowGuardTrue if all are proven true, else workflowGuardUnknown.
func (state *workflowGuardParser) conjunction() workflowGuardTruth {
	result := state.comparison()
	for state.peek() == "&&" {
		state.position++
		right := state.comparison()
		if result == workflowGuardFalse || right == workflowGuardFalse {
			result = workflowGuardFalse
		} else if result == workflowGuardTrue && right == workflowGuardTrue {
			result = workflowGuardTrue
		} else {
			result = workflowGuardUnknown
		}
	}
	return result
}

// disjunction combines an OR chain; a branch proven true determines the result even when another branch is unknown.
//
// It advances state.position through the || chain even after a true operand, and unary may set state.isValid to false on a bad token.
// It returns workflowGuardTrue if any || operand is proven true, workflowGuardFalse if all are proven false, else workflowGuardUnknown.
func (state *workflowGuardParser) disjunction() workflowGuardTruth {
	result := state.conjunction()
	for state.peek() == "||" {
		state.position++
		right := state.conjunction()
		if result == workflowGuardTrue || right == workflowGuardTrue {
			result = workflowGuardTrue
		} else if result == workflowGuardFalse && right == workflowGuardFalse {
			result = workflowGuardFalse
		} else {
			result = workflowGuardUnknown
		}
	}
	return result
}
