package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/rule"
)

type yamlLine struct {
	indent int
	text   string
}

func parseYAML(data []byte, definitions []rule.Definition) (Config, error) {
	lines := yamlLines(string(data))
	if len(lines) == 0 {
		return Config{}, nil
	}
	value, index, err := parseYAMLBlock(lines, 0, lines[0].indent)
	if err != nil {
		return Config{}, err
	}
	if index != len(lines) {
		return Config{}, fmt.Errorf("invalid YAML indentation near %q", lines[index].text)
	}
	payload, ok := value.(map[string]any)
	if !ok {
		return Config{}, fmt.Errorf("config root must be an object")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Config{}, err
	}
	return parseJSON(encoded, definitions)
}

func yamlLines(input string) []yamlLine {
	out := []yamlLine{}
	for _, raw := range strings.Split(input, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		stripped := stripYAMLComment(line)
		if strings.TrimSpace(stripped) == "" {
			continue
		}
		indent := len(stripped) - len(strings.TrimLeft(stripped, " "))
		out = append(out, yamlLine{indent: indent, text: strings.TrimSpace(stripped)})
	}
	return out
}

func parseYAMLBlock(lines []yamlLine, index int, indent int) (any, int, error) {
	if index >= len(lines) {
		return map[string]any{}, index, nil
	}
	if strings.HasPrefix(lines[index].text, "- ") {
		return parseYAMLList(lines, index, indent)
	}
	return parseYAMLMap(lines, index, indent)
}

func parseYAMLMap(lines []yamlLine, index int, indent int) (map[string]any, int, error) {
	out := map[string]any{}
	for index < len(lines) {
		line := lines[index]
		if line.indent < indent {
			break
		}
		if line.indent > indent {
			return nil, index, fmt.Errorf("unexpected YAML indentation near %q", line.text)
		}
		key, valueText, ok := strings.Cut(line.text, ":")
		if !ok {
			return nil, index, fmt.Errorf("expected YAML key/value near %q", line.text)
		}
		key = strings.TrimSpace(key)
		valueText = strings.TrimSpace(valueText)
		if key == "" {
			return nil, index, fmt.Errorf("empty YAML key")
		}
		if valueText != "" {
			out[key] = parseYAMLScalar(valueText)
			index++
			continue
		}
		next := index + 1
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

func parseYAMLList(lines []yamlLine, index int, indent int) ([]any, int, error) {
	out := []any{}
	for index < len(lines) {
		line := lines[index]
		if line.indent < indent {
			break
		}
		if line.indent > indent || !strings.HasPrefix(line.text, "- ") {
			return nil, index, fmt.Errorf("unexpected YAML list item near %q", line.text)
		}
		valueText := strings.TrimSpace(strings.TrimPrefix(line.text, "- "))
		out = append(out, parseYAMLScalar(valueText))
		index++
	}
	return out, index, nil
}

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
	if number, err := strconv.ParseFloat(input, 64); err == nil {
		return number
	}
	return input
}

func parseYAMLInlineList(input string) []any {
	if strings.TrimSpace(input) == "" {
		return []any{}
	}
	parts := strings.Split(input, ",")
	out := make([]any, 0, len(parts))
	for _, part := range parts {
		out = append(out, parseYAMLScalar(strings.TrimSpace(part)))
	}
	return out
}

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

func stripYAMLComment(input string) string {
	var quote rune
	for index, current := range input {
		switch current {
		case '\'', '"':
			if quote == 0 {
				quote = current
			} else if quote == current {
				quote = 0
			}
		case '#':
			if quote == 0 {
				return strings.TrimRight(input[:index], " ")
			}
		}
	}
	return input
}
