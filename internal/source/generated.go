// Package source owns source-file boundary detection helpers.
package source

import (
	"bufio"
	"os"
	"strings"
)

// HasGeneratedGoHeader reports whether source begins with a generated-code
// header before the package clause. The marker requires both "generated" and
// "do not edit" in leading comments so ordinary prose that only says one of
// those phrases stays in scope for analysis.
func HasGeneratedGoHeader(source string) bool {
	scanner := bufio.NewScanner(strings.NewReader(source))
	inBlockComment := false
	var leading strings.Builder
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if inBlockComment {
			leading.WriteByte('\n')
			leading.WriteString(line)
			if strings.Contains(line, "*/") {
				inBlockComment = false
			}
			continue
		}
		if strings.HasPrefix(line, "package ") {
			break
		}
		switch {
		case strings.HasPrefix(line, "//"):
			leading.WriteByte('\n')
			leading.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "//")))
		case strings.HasPrefix(line, "/*"):
			leading.WriteByte('\n')
			leading.WriteString(line)
			if !strings.Contains(line[2:], "*/") {
				inBlockComment = true
			}
		default:
			return false
		}
	}
	lower := strings.ToLower(leading.String())
	return strings.Contains(lower, "generated") && strings.Contains(lower, "do not edit")
}

// isGeneratedGo reads a Go file and applies the shared generated-code header contract.
func isGeneratedGo(path string) bool {
	// #nosec G304 -- scanner intentionally opens files selected by discovery.
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return HasGeneratedGoHeader(string(data))
}
