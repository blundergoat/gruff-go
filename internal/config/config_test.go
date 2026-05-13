package config

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/rule"
)

func TestParseValidatesStrictConfig(t *testing.T) {
	cfg, err := Parse([]byte(`{
		"schemaVersion": "gruff-go.config.v0.1",
		"select": ["size-file-length"],
		"ignorePaths": ["fixtures/**"],
		"acceptedAbbreviations": ["ID", "HTTP"],
		"rules": {
			"size-file-length": {
				"enabled": true,
				"thresholds": {"maxLines": 120}
			},
			"size-function-length": {
				"enabled": false
			}
		},
		"sensitiveData": {"previewAllowlist": ["testdata/**"]}
	}`), rule.Defaults().Definitions())
	if err != nil {
		t.Fatal(err)
	}
	options := cfg.RuleOptions()
	if !options.Enabled["size-file-length"] || options.Enabled["size-function-length"] {
		t.Fatalf("enabled map = %#v, want selected rule only", options.Enabled)
	}
	if options.Thresholds["size-file-length"]["maxLines"] != 120 {
		t.Fatalf("thresholds = %#v, want configured maxLines", options.Thresholds)
	}
}

func TestParseYAMLGruffShape(t *testing.T) {
	cfg, err := ParseFile(".gruff.yaml", []byte(`
paths:
  ignore:
    - 'fixtures/**'
allowlists:
  acceptedAbbreviations:
    - ID
  secretPreviews:
    - 'testdata/**'
selection:
  rules:
    - waste.empty-block
  excludeRules:
    - size.file-length
rules:
  complexity.cyclomatic:
    enabled: true
    threshold: 100
    severity: error
  size.function-length:
    enabled: false
`), rule.Defaults().Definitions())
	if err != nil {
		t.Fatal(err)
	}
	options := cfg.RuleOptions()
	if !options.Enabled["waste-empty-block"] || options.Enabled["size-file-length"] || options.Enabled["size-function-length"] {
		t.Fatalf("enabled map = %#v, want selected waste and excluded size rules", options.Enabled)
	}
	if options.Thresholds["complexity-cyclomatic"]["maxComplexity"] != 100 {
		t.Fatalf("thresholds = %#v, want singular threshold mapped", options.Thresholds)
	}
	if options.Severities["complexity-cyclomatic"] != "high" {
		t.Fatalf("severities = %#v, want error alias mapped to high", options.Severities)
	}
	if len(cfg.IgnorePaths) != 1 || cfg.IgnorePaths[0] != "fixtures/**" {
		t.Fatalf("ignore paths = %#v, want fixtures ignore", cfg.IgnorePaths)
	}
}

func TestParseRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{name: "unknown top-level key", json: `{"unknown": true}`, want: "unknown field"},
		{name: "unknown selected rule", json: `{"select": ["missing-rule"]}`, want: "unknown selected rule"},
		{name: "unknown rule", json: `{"rules": {"missing-rule": {"enabled": true}}}`, want: "unknown rule"},
		{name: "unknown threshold", json: `{"rules": {"size-file-length": {"thresholds": {"maxBytes": 1}}}}`, want: "unknown threshold"},
		{name: "invalid threshold", json: `{"rules": {"size-file-length": {"thresholds": {"maxLines": 0}}}}`, want: "must be positive"},
		{name: "invalid ignore", json: `{"ignorePaths": ["../outside"]}`, want: "must stay inside"},
		{name: "invalid abbreviation", json: `{"acceptedAbbreviations": ["id"]}`, want: "must be uppercase"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.json), rule.Defaults().Definitions())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}
