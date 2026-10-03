// Package rule proves bounded event guards without changing trigger or secret discovery.
package rule

import (
	"encoding/json"
	"regexp"
	"strings"
)

// workflowGuardNode owns a mapping key or list item and its inclusive source lines.
type workflowGuardNode struct {
	key, content       string
	indent, start, end int
	isItem             bool
	children           []*workflowGuardNode
}

// workflowGuardEntry defines supported block mapping keys with a plain scalar.
var workflowGuardEntry = regexp.MustCompile("^(?:([A-Za-z0-9_.-]+)|'([^']+)'|\"([^\"\\\\]+)\"|(<<)):\\s*(.*)$")

// workflowGuardItem defines list prefix width establishes the mapping key column.
var workflowGuardItem = regexp.MustCompile("^-(?: +|$)")

// workflowGuardAlias defines anchors and aliases invalidate source ownership.
var workflowGuardAlias = regexp.MustCompile("(?:^|\\s)[&*][A-Za-z0-9_-]+")

// workflowGuardScalar defines block scalar headers prevent shell text from becoming YAML keys.
var workflowGuardScalar = regexp.MustCompile("^[|>](?:[+-]?\\d*|\\d*[+-]?)$")

// workflowGuardQuote defines quoted spans protect embedded comment characters.
var workflowGuardQuote = regexp.MustCompile("^(?:'(?:[^']|'')*'|\"(?:[^\"\\\\]|\\\\.)*\")")

// workflowGuardToken defines the complete bounded expression token grammar.
var workflowGuardToken = regexp.MustCompile("^(?:\\s+|'(?:[^']|'')*'|[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*|==|!=|&&|\\|\\||[!()])")

// workflowGuardIdentifier defines context identifiers remain unknown rather than proving safety.
var workflowGuardIdentifier = regexp.MustCompile("^[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*$")

// workflowUnreachableSecretLines covers only an own job or step, including late guards.
// Structural ambiguity retains every existing warning rather than guessing ownership.
func workflowUnreachableSecretLines(source string) map[int]bool {
	blocked := map[int]bool{}
	root := workflowGuardOwnership(source)
	if root == nil {
		return blocked
	}
	jobs := workflowGuardChild(root, "jobs")
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

// workflowGuardChild rejects nested misleading keys by looking only at direct children.
func workflowGuardChild(parent *workflowGuardNode, key string) *workflowGuardNode {
	for _, child := range parent.children {
		if !child.isItem && child.key == key {
			return child
		}
	}
	return nil
}

// workflowGuardRejects uses the existing detector's single covered PR event.
func workflowGuardRejects(node *workflowGuardNode) bool {
	guard := workflowGuardChild(node, "if")
	return guard != nil && workflowEventGuardTruth(guard.content, "pull_request_target") == workflowGuardFalse
}

// workflowGuardMark includes references preceding an own late condition.
func workflowGuardMark(node *workflowGuardNode, blocked map[int]bool) {
	for line := node.start; line <= node.end; line++ {
		blocked[line] = true
	}
}

// workflowGuardYAMLText preserves quoted hashes and rejects unmatched quotes.
func workflowGuardYAMLText(raw string) (string, bool) {
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\'' || raw[i] == '"' {
			quoted := workflowGuardQuote.FindString(raw[i:])
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

// workflowGuardOwnership completes all source ranges before evaluating guards.
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
	step := &workflowGuardNode{indent: indent, start: index + 1, end: total, isItem: true}
	parent.children = append(parent.children, step)
	*stack = append(*stack, step)
	return step
}

// workflowGuardAppend vetoes duplicates and YAML aliases; scalar lists cannot own guards.
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

// workflowGuardTruth represents proof, not runtime truthiness of arbitrary context values.
type workflowGuardTruth uint8

const (
	// workflowGuardUnknown cannot establish PR unreachability.
	workflowGuardUnknown workflowGuardTruth = iota
	// workflowGuardFalse proves this event cannot reach the guarded scope.
	workflowGuardFalse
	// workflowGuardTrue retains a reachable secret reference.
	workflowGuardTrue
)

// workflowGuardOperand keeps event/string operands separate from boolean proof.
type workflowGuardOperand struct {
	kind    string
	literal string
	truth   workflowGuardTruth
}

// workflowGuardParser parses every token, including branches whose truth is already false.
type workflowGuardParser struct {
	tokens   []string
	position int
	isValid  bool
	event    string
}

// workflowEventGuardTruth rejects incomplete scalars/wrappers before conservative evaluation.
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

// peek returns an empty sentinel at the end without reading outside the token slice.
func (state *workflowGuardParser) peek() string {
	if state.position >= len(state.tokens) {
		return ""
	}
	return state.tokens[state.position]
}

// unary preserves negation precedence; non-boolean operands remain unknown.
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
	return workflowGuardOperand{kind: "truth"}
}

// comparison proves only exact event-name comparisons to a string literal.
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

// conjunction allows false AND unknown proof while parsing both operands.
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

// disjunction preserves warnings whenever an OR branch remains unknown.
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
