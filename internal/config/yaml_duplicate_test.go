// Package config tests duplicate-key and sanitized-error behavior in the
// supported YAML subset.
package config

import (
	"strings"
	"testing"
)

// TestParseYAMLRejectsDuplicateKeysByMappingScope covers root, nested, and
// deeply nested mappings with original 1-based source line evidence.
func TestParseYAMLRejectsDuplicateKeysByMappingScope(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "root with blank and comment lines",
			yaml: "schemaVersion: gruff-go.config.v0.1\n\n# retained source line\nschemaVersion: gruff-go.config.v0.1\n",
			want: `duplicate YAML key "schemaVersion": first defined at line 1, duplicated at line 4`,
		},
		{
			name: "nested rule mapping",
			yaml: "rules:\n  size.file-length:\n    enabled: true\n    enabled: false\n",
			want: `duplicate YAML key "enabled": first defined at line 3, duplicated at line 4`,
		},
		{
			name: "deep options mapping",
			yaml: "rules:\n  docs.comment-rubric:\n    options:\n      includePaths:\n        - internal/config/yaml.go\n      includePaths:\n        - internal/config/config.go\n",
			want: `duplicate YAML key "includePaths": first defined at line 4, duplicated at line 6`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml), defaultDefinitions())
			if err == nil {
				t.Fatal("expected duplicate-key error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error did not contain expected sanitized duplicate marker %q", tt.want)
			}
		})
	}
}

// TestParseYAMLAllowsSameKeyInSeparateScopes proves duplicate identity is local
// to one mapping invocation rather than global across the document.
func TestParseYAMLAllowsSameKeyInSeparateScopes(t *testing.T) {
	_, err := Parse([]byte("rules:\n  size.file-length:\n    enabled: true\n  size.function-length:\n    enabled: false\n"), defaultDefinitions())
	if err != nil {
		t.Fatalf("same key in separate mappings should parse: %v", err)
	}
}

// TestParseYAMLDuplicateErrorDoesNotEchoValueOrLine uses a runtime-built,
// secret-shaped value so the regression fixture cannot self-flag in dogfood.
func TestParseYAMLDuplicateErrorDoesNotEchoValueOrLine(t *testing.T) {
	hiddenValue := yamlSensitiveFixtureValue()
	duplicateLine := "    enabled: " + hiddenValue
	body := strings.Join([]string{
		"rules:",
		"  size.file-length:",
		"    enabled: true",
		"",
		"    # original line numbers include comments",
		duplicateLine,
	}, "\n")

	_, err := Parse([]byte(body), defaultDefinitions())
	if err == nil {
		t.Fatal("expected duplicate-key error")
	}
	message := err.Error()
	want := `duplicate YAML key "enabled": first defined at line 3, duplicated at line 6`
	if !strings.Contains(message, want) {
		t.Fatal("error did not contain expected key and original line numbers")
	}
	if strings.Contains(message, hiddenValue) {
		t.Fatal("duplicate-key error contains the secret-shaped value")
	}
	if strings.Contains(message, duplicateLine) {
		t.Fatal("duplicate-key error contains the raw source line")
	}
}

// TestParseYAMLStructuralErrorsDoNotEchoSource covers every structural error
// path that previously interpolated normalized config text.
func TestParseYAMLStructuralErrorsDoNotEchoSource(t *testing.T) {
	hiddenValue := yamlSensitiveFixtureValue()
	tests := []struct {
		name    string
		yaml    string
		rawLine string
		want    string
	}{
		{
			name:    "invalid indentation after indented root",
			yaml:    "  schemaVersion: gruff-go.config.v0.1\nenabled: " + hiddenValue + "\n",
			rawLine: "enabled: " + hiddenValue,
			want:    "invalid YAML indentation at line 2",
		},
		{
			name:    "unexpected map indentation",
			yaml:    "schemaVersion: gruff-go.config.v0.1\n  enabled: " + hiddenValue + "\n",
			rawLine: "  enabled: " + hiddenValue,
			want:    "unexpected YAML indentation at line 2",
		},
		{
			name:    "missing key value separator",
			yaml:    "schemaVersion: gruff-go.config.v0.1\n" + hiddenValue + "\n",
			rawLine: hiddenValue,
			want:    "expected YAML key/value at line 2",
		},
		{
			name:    "unexpected list item",
			yaml:    "paths:\n  ignore:\n    - kept/**\n    enabled: " + hiddenValue + "\n",
			rawLine: "    enabled: " + hiddenValue,
			want:    "unexpected YAML list item at line 4",
		},
		{
			name:    "empty key",
			yaml:    "schemaVersion: gruff-go.config.v0.1\n: " + hiddenValue + "\n",
			rawLine: ": " + hiddenValue,
			want:    "empty YAML key at line 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml), defaultDefinitions())
			if err == nil {
				t.Fatal("expected structural YAML error")
			}
			message := err.Error()
			if !strings.Contains(message, tt.want) {
				t.Fatalf("error did not contain sanitized line marker %q", tt.want)
			}
			if strings.Contains(message, hiddenValue) {
				t.Fatal("structural YAML error contains the secret-shaped value")
			}
			if strings.Contains(message, strings.TrimSpace(tt.rawLine)) {
				t.Fatal("structural YAML error contains the raw source line")
			}
		})
	}
}

// yamlSensitiveFixtureValue returns one secret-shaped runtime token assembled
// from short source fragments so the repository's own scanner remains clean.
func yamlSensitiveFixtureValue() string {
	return strings.Join([]string{"M07q9L", "v2N8x", "R4p7K", "d6T3s"}, "")
}
