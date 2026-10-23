package config

import (
	"strings"
	"testing"
)

// A flow mapping is valid YAML that four sibling ports read and this parser deliberately does not.
// The refusal has to say so: before M44 it surfaced as `json: cannot unmarshal string into Go struct
// field Config.rules of type map[string]config.RuleConfig`, which names an internal type rather than
// the user's file.
func TestFlowMappingRefusalNamesTheShapeAndTheBlockForm(t *testing.T) {
	for _, testCase := range []struct {
		name string
		body string
		want string
	}{
		{name: "empty mapping value", body: "schemaVersion: \"1\"\nrules: {}\n", want: "key \"rules\" at line 2"},
		{name: "populated mapping value", body: "schemaVersion: \"1\"\npaths: {ignore: []}\n", want: "key \"paths\" at line 2"},
		{name: "list item", body: "schemaVersion: \"1\"\nsensitiveExclusions:\n  - {path: a}\n", want: "list item at line 3"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := encodeYAMLAsJSON([]byte(testCase.body))
			if err == nil {
				t.Fatalf("expected a refusal for %q", testCase.body)
			}
			message := err.Error()
			if !strings.Contains(message, testCase.want) {
				t.Errorf("refusal does not locate the flow mapping: got %q, want it to contain %q", message, testCase.want)
			}
			if !strings.Contains(message, "flow mapping") {
				t.Errorf("refusal does not name the shape: %q", message)
			}
			if !strings.Contains(message, "indented block") {
				t.Errorf("refusal does not name the supported form: %q", message)
			}
			if strings.Contains(message, "cannot unmarshal") || strings.Contains(message, "config.RuleConfig") {
				t.Errorf("refusal still leaks an internal Go type: %q", message)
			}
		})
	}
}

// A quoted value that merely starts with a brace is a string, not a flow mapping, and must still parse.
func TestQuotedBraceValueRemainsAScalar(t *testing.T) {
	encoded, err := encodeYAMLAsJSON([]byte("schemaVersion: \"1\"\nreportTitle: \"{project}\"\n"))
	if err != nil {
		t.Fatalf("quoted brace value was refused: %v", err)
	}
	if !strings.Contains(string(encoded), "{project}") {
		t.Errorf("quoted brace value did not survive encoding: %s", encoded)
	}
}
