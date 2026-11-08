// Package config YAML helpers parse the tiny subset of YAML used by .gruff-go.yaml.
//
// The parser rejects some shapes outside the documented configuration, but other unsupported YAML can be read as ordinary strings.
// Flow mappings right after a key or dash, map entries with no colon, duplicate keys and bad indentation fail with an error naming the line.
package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/rule"
)

// yamlLine is one normalised config line: its 1-based source line for error messages, its indent in spaces, and its trimmed text.
type yamlLine struct {
	number int
	indent int
	text   string
}

// parseYAML converts the YAML body into a validated Config value.
//
// data is the raw configuration file content, and definitions is the rule definition list passed to decodeConfigPayload with the payload.
// Returns the decoded Config, or the zero Config and a nil error when data has no line left after blank and comment-only lines are dropped.
// The error is non-nil when encodeYAMLAsJSON rejects the YAML structure or decodeConfigPayload fails on the payload.
func parseYAML(data []byte, definitions []rule.Definition) (Config, error) {
	encoded, err := encodeYAMLAsJSON(data)
	// Indentation errors, duplicate keys and flow mappings right after a key or dash stop here with their source lines.
	if err != nil {
		return Config{}, err
	}
	// A config file holding only blank lines and comments loads as the zero Config rather than failing.
	if encoded == nil {
		return Config{}, nil
	}
	return decodeConfigPayload(encoded, definitions)
}

// parseYAMLPermissive converts the YAML body into a Config like parseYAML, but drops unparseable per-rule severity overrides before validation.
//
// That lets a pre-0.2 config with legacy 5-bucket severity names still flow through the init --force preserve path.
//
// data is the raw configuration file content, and definitions is the rule definition list passed to decodeConfigPayloadPermissive.
// Returns the decoded Config, or the zero Config and a nil error when data has no line left after blank and comment-only lines are dropped.
// The error is non-nil when encodeYAMLAsJSON rejects the YAML structure or decodeConfigPayloadPermissive fails on the payload.
func parseYAMLPermissive(data []byte, definitions []rule.Definition) (Config, error) {
	encoded, err := encodeYAMLAsJSON(data)
	if err != nil {
		return Config{}, err
	}
	if encoded == nil {
		return Config{}, nil
	}
	return decodeConfigPayloadPermissive(encoded, definitions)
}

// encodeYAMLAsJSON parses the YAML body into the canonical JSON payload the decoders consume; parseYAML and parseYAMLPermissive both call it.
//
// data is the raw YAML file content; blank and comment-only lines are dropped before parsing.
// Returns the encoded mapping, or nil bytes when no line is left, so callers can tell an empty or comment-only config from a structural error.
// It fails when the root block is a list, a line sits shallower than the root block, or parseYAMLBlock or json.Marshal rejects the content.
func encodeYAMLAsJSON(data []byte) ([]byte, error) {
	lines := yamlLines(string(data))
	if len(lines) == 0 {
		return nil, nil
	}
	value, index, err := parseYAMLBlock(lines, 0, lines[0].indent)
	if err != nil {
		return nil, err
	}
	// A file whose first key is indented deeper than a later line stops here, such as two leading spaces before only the first key.
	if index != len(lines) {
		return nil, fmt.Errorf("invalid YAML indentation at line %d", lines[index].number)
	}
	// A config file that opens with a dash list instead of top-level keys fails here.
	payload, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config root must be an object")
	}
	return json.Marshal(payload)
}

// yamlLines splits the config text into trimmed, non-blank lines that keep their source line number and indentation.
//
// input is the whole file text; each line loses trailing spaces, tabs and carriage returns before its comment is stripped.
// Returns one yamlLine per line that still has text after stripYAMLComment, with its 1-based line number and count of leading spaces.
// The result is an empty, non-nil slice when every line of input is blank or a comment.
func yamlLines(input string) []yamlLine {
	out := []yamlLine{}
	for index, raw := range strings.Split(input, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		stripped := stripYAMLComment(line)
		if strings.TrimSpace(stripped) == "" {
			continue
		}
		// Only spaces count as indent, so a key indented with a tab is read at column zero and lands at the top level instead of nesting.
		indent := len(stripped) - len(strings.TrimLeft(stripped, " "))
		out = append(out, yamlLine{number: index + 1, indent: indent, text: strings.TrimSpace(stripped)})
	}
	return out
}

// parseYAMLBlock parses either a list or map block depending on the next line.
//
// lines is the normalised input, index is the cursor of the block's first line, and indent is the indentation its entries must sit at.
// Returns the parsed list or map and the cursor after the block, or an empty map with index unchanged when index is already past the end.
// The error comes from parseYAMLList or parseYAMLMap when a line breaks the block shape.
func parseYAMLBlock(lines []yamlLine, index int, indent int) (any, int, error) {
	if index >= len(lines) {
		return map[string]any{}, index, nil
	}
	if strings.HasPrefix(lines[index].text, "- ") {
		return parseYAMLList(lines, index, indent)
	}
	return parseYAMLMap(lines, index, indent)
}

// parseYAMLMap parses a mapping block at the given indent and returns the cursor.
//
// lines is the normalised input, index is the cursor of the first entry, and indent is the indentation every key in this mapping must have.
// Returns the key/value map and the cursor of the first line indented less than indent, or len(lines) when the input runs out.
//
// A key with an empty value and no deeper lines that follow maps to an empty map.
// It fails on a deeper-indented line, a line without a colon, an empty or duplicate key, a flow mapping value, or an error from a nested block.
func parseYAMLMap(lines []yamlLine, index int, indent int) (map[string]any, int, error) {
	out := map[string]any{}
	firstLines := map[string]int{}
	for index < len(lines) {
		line := lines[index]
		if line.indent < indent {
			break
		}
		// An extra space before one key of a block, or a deeper line under a key that already has a value, fails here.
		if line.indent > indent {
			return nil, index, fmt.Errorf("unexpected YAML indentation at line %d", line.number)
		}
		key, valueText, ok := strings.Cut(line.text, ":")
		// A line with no colon, such as a bare word or a --- document marker, fails here.
		if !ok {
			return nil, index, fmt.Errorf("expected YAML key/value at line %d", line.number)
		}
		key = strings.TrimSpace(key)
		valueText = strings.TrimSpace(valueText)
		if key == "" {
			return nil, index, fmt.Errorf("empty YAML key at line %d", line.number)
		}
		// Writing the same key twice in one block fails here, and the message names both lines so the user can pick one.
		if firstLine, exists := firstLines[key]; exists {
			return nil, index, fmt.Errorf("duplicate YAML key %q: first defined at line %d, duplicated at line %d", key, firstLine, line.number)
		}
		firstLines[key] = line.number
		if err := yamlFlowMappingError(fmt.Sprintf("key %q", key), valueText, line.number); err != nil {
			return nil, index, err
		}
		if valueText != "" {
			out[key] = parseYAMLScalar(valueText)
			index++
			continue
		}
		next := index + 1
		// A key with nothing indented below it becomes an empty map, so a list whose dashes sit at the key's own column is not read as its value.
		if next >= len(lines) || lines[next].indent <= indent {
			out[key] = map[string]any{}
			index = next
			continue
		}
		value, parsedIndex, err := parseYAMLBlock(lines, next, lines[next].indent)
		if err != nil {
			return nil, parsedIndex, err
		}
		out[key] = value
		index = parsedIndex
	}
	return out, index, nil
}

// parseYAMLList parses a sequence block of dash-prefixed entries.
//
// An item is parsed as a scalar or inline list unless its text opens a mapping, in which case it and its deeper lines form one map.
// That map shape is what sensitiveExclusions needs, per FAMILY-CONTRACT.md section 13a.
//
// lines is the normalised input, index is the cursor of the first dash entry, and indent is the indentation every dash must sit at.
// Returns the parsed items and the cursor of the first line indented less than indent, or len(lines) when the input runs out.
// It fails on a deeper-indented or dash-less line, a flow mapping item, or an error from parseYAMLListItemMap.
func parseYAMLList(lines []yamlLine, index int, indent int) ([]any, int, error) {
	out := []any{}
	for index < len(lines) {
		line := lines[index]
		if line.indent < indent {
			break
		}
		// A key: value line at the dash column, or a dash indented deeper after a plain item, fails here as an unexpected list item.
		if line.indent > indent || !strings.HasPrefix(line.text, "- ") {
			return nil, index, fmt.Errorf("unexpected YAML list item at line %d", line.number)
		}
		valueText := strings.TrimSpace(strings.TrimPrefix(line.text, "- "))
		if err := yamlFlowMappingError("list item", valueText, line.number); err != nil {
			return nil, index, err
		}
		if !yamlListItemOpensMap(valueText) {
			out = append(out, parseYAMLScalar(valueText))
			index++
			continue
		}
		value, next, err := parseYAMLListItemMap(lines, index, indent, valueText)
		if err != nil {
			return nil, index, err
		}
		out = append(out, value)
		index = next
	}
	return out, index, nil
}

// yamlFlowMappingError builds the refusal for a flow mapping such as {} after a key or dash, so the error describes the shape the user wrote.
//
// Without it, a flow mapping fell through parseYAMLScalar as a string and failed at unmarshal time on a Go struct field name the user never wrote.
//
// subject names the offending key or list item in the message, valueText is the trimmed value, and lineNumber is its 1-based source line.
// Returns nil when valueText does not start with an opening brace, so callers can check every value.
// Otherwise the error quotes valueText and tells the user to write the entries as an indented block or omit the value.
func yamlFlowMappingError(subject string, valueText string, lineNumber int) error {
	if !strings.HasPrefix(valueText, "{") {
		return nil
	}
	return fmt.Errorf(
		"%s at line %d uses the YAML flow mapping %s, which this configuration parser does not read; write its entries as an indented block on the following lines, or omit the value entirely to leave the mapping empty",
		subject,
		lineNumber,
		valueText,
	)
}

// yamlListItemOpensMap reports whether a list item's text starts a mapping rather than a scalar.
//
// text is the item after its dash; an unquoted item holding a colon and space, or ending in a colon, gives true and parses as a map.
// A quoted item gives false even when it contains a colon, so the existing string lists keep their meaning.
func yamlListItemOpensMap(text string) bool {
	if strings.HasPrefix(text, "'") || strings.HasPrefix(text, "\"") {
		return false
	}
	return strings.Contains(text, ": ") || strings.HasSuffix(text, ":")
}

// parseYAMLListItemMap parses one dash-introduced mapping item: its first key/value plus every following line indented deeper than the dash.
//
// lines is the normalised input, index is the cursor of the dash line, indent is the dash's indentation, and firstText is the text after the dash.
// Continuation keys must sit two spaces deeper than the dash, the column firstText is treated as starting at.
//
// Returns the item map and the cursor of the first line indented no deeper than the dash, or len(lines) when the input runs out.
// That cursor may sit on the next list item or on a key of an enclosing block.
// It fails when parseYAMLMap rejects the item or a continuation line sits shallower than that key column; the cursor then stays at index.
func parseYAMLListItemMap(lines []yamlLine, index int, indent int, firstText string) (map[string]any, int, error) {
	itemIndent := indent + 2
	itemLines := []yamlLine{{number: lines[index].number, indent: itemIndent, text: firstText}}
	next := index + 1
	for next < len(lines) && lines[next].indent > indent {
		itemLines = append(itemLines, lines[next])
		next++
	}
	value, cursor, err := parseYAMLMap(itemLines, 0, itemIndent)
	if err != nil {
		return nil, index, err
	}
	// A continuation key one space deeper than the dash, instead of two, stops here as unexpected indentation.
	if cursor != len(itemLines) {
		return nil, index, fmt.Errorf("unexpected YAML indentation at line %d", itemLines[cursor].number)
	}
	return value, next, nil
}

// parseYAMLScalar converts a raw token into a string, bool, number, null, or inline list.
//
// input is a raw value token from a key, list item or inline-list part, and surrounding spaces are trimmed first.
// Returns a list for bracketed text, a bool for true or false, nil for null or a tilde, the unquoted string, or a float64 for numeric text.
// Any other token, including a double-quoted one strconv.Unquote rejects, comes back as the trimmed input string.
func parseYAMLScalar(input string) any {
	input = strings.TrimSpace(input)
	if input == "[]" {
		return []any{}
	}
	if strings.HasPrefix(input, "[") && strings.HasSuffix(input, "]") {
		return parseYAMLInlineList(strings.TrimSuffix(strings.TrimPrefix(input, "["), "]"))
	}
	if input == "true" {
		return true
	}
	if input == "false" {
		return false
	}
	if input == "null" || input == "~" {
		return nil
	}
	if value, ok := unquoteYAML(input); ok {
		return value
	}
	// Unquoted inf or nan parse as numbers here and json.Marshal then rejects the config; quote such a value to keep it a string.
	if number, err := strconv.ParseFloat(input, 64); err == nil {
		return number
	}
	return input
}

// parseYAMLInlineList parses a comma-separated inline list of scalars.
//
// input is the text between the brackets; each comma-separated part is trimmed and passed to parseYAMLScalar, with no quote-aware splitting.
// Returns the parsed values in order, or an empty, non-nil list when input is blank.
func parseYAMLInlineList(input string) []any {
	if strings.TrimSpace(input) == "" {
		return []any{}
	}
	// A quoted item holding a comma, such as 'a,b', splits into two broken items here.
	parts := strings.Split(input, ",")
	out := make([]any, 0, len(parts))
	for _, part := range parts {
		out = append(out, parseYAMLScalar(strings.TrimSpace(part)))
	}
	return out
}

// unquoteYAML strips matching single or double quotes from a scalar token and reports whether it did.
//
// input is a trimmed scalar token; a single-quoted body has doubled single quotes collapsed, and a double-quoted one goes through strconv.Unquote.
// Returns the unquoted text and true for a quoted token, which is how a value written as 'true' or '10' stays a string.
// Returns an empty string and false when input is shorter than two characters, lacks matching outer quotes, or strconv.Unquote rejects it.
func unquoteYAML(input string) (string, bool) {
	if len(input) < 2 {
		return "", false
	}
	if strings.HasPrefix(input, "'") && strings.HasSuffix(input, "'") {
		return strings.ReplaceAll(input[1:len(input)-1], "''", "'"), true
	}
	if strings.HasPrefix(input, "\"") && strings.HasSuffix(input, "\"") {
		value, err := strconv.Unquote(input)
		return value, err == nil
	}
	return "", false
}

// stripYAMLComment removes a trailing hash comment that sits outside quoted text.
//
// input is one config line; a single or double quote opens quoted state until the same quote character recurs, with no escape handling.
// Returns the text before the first hash outside quotes with trailing spaces trimmed, or input unchanged when there is no such hash.
func stripYAMLComment(input string) string {
	var quote rune
	for index, current := range input {
		switch current {
		// An apostrophe in unquoted text also opens quoted state, so a later hash comment on that line stays in the value.
		case '\'', '"':
			if quote == 0 {
				quote = current
			} else if quote == current {
				quote = 0
			}
		// An unquoted hash starts a comment even with no space before it, so a value written as a#b keeps only a.
		case '#':
			if quote == 0 {
				return strings.TrimRight(input[:index], " ")
			}
		}
	}
	return input
}
