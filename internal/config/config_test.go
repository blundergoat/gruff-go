package config

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/rule"
)

func TestParseValidatesStrictConfig(t *testing.T) {
	cfg, err := Parse([]byte(`{
		"schemaVersion": "gruff-go.config.v0.1",
		"select": ["size.file-length"],
		"ignorePaths": ["fixtures/**"],
		"acceptedAbbreviations": ["ID", "HTTP"],
		"rules": {
			"size.file-length": {
				"enabled": true,
				"thresholds": {"maxLines": 120}
			},
			"size.function-length": {
				"enabled": false
			}
		},
		"sensitiveData": {"previewAllowlist": ["testdata/**"]}
	}`), rule.Defaults().Definitions())
	if err != nil {
		t.Fatal(err)
	}
	options := cfg.RuleOptions()
	if !options.Enabled["size.file-length"] || options.Enabled["size.function-length"] {
		t.Fatalf("enabled map = %#v, want selected rule only", options.Enabled)
	}
	if options.Thresholds["size.file-length"]["maxLines"] != 120 {
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
    - dead-code.empty-block
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
	if !options.Enabled["dead-code.empty-block"] || options.Enabled["size.file-length"] || options.Enabled["size.function-length"] {
		t.Fatalf("enabled map = %#v, want selected dead-code rule and excluded size rules", options.Enabled)
	}
	if options.Thresholds["complexity.cyclomatic"]["maxComplexity"] != 100 {
		t.Fatalf("thresholds = %#v, want singular threshold mapped", options.Thresholds)
	}
	if options.Severities["complexity.cyclomatic"] != "high" {
		t.Fatalf("severities = %#v, want error alias mapped to high", options.Severities)
	}
	if len(cfg.IgnorePaths) != 1 || cfg.IgnorePaths[0] != "fixtures/**" {
		t.Fatalf("ignore paths = %#v, want fixtures ignore", cfg.IgnorePaths)
	}
}

func TestParseAcceptsExpansionRuleConfig(t *testing.T) {
	cfg, err := ParseFile(".gruff.yaml", []byte(`
rules:
  size.parameter-count:
    enabled: true
    threshold: 8
    severity: warning
  complexity.nesting-depth:
    enabled: true
    thresholds:
      maxDepth: 6
  docs.exported-symbol-comment:
    enabled: true
    severity: error
    options:
      ignoreInternalPackages: true
	`), rule.Defaults().Definitions())
	if err != nil {
		t.Fatal(err)
	}
	options := cfg.RuleOptions()
	if !options.Enabled["size.parameter-count"] || !options.Enabled["complexity.nesting-depth"] || !options.Enabled["docs.exported-symbol-comment"] {
		t.Fatalf("enabled map = %#v, want all three M06 rules enabled", options.Enabled)
	}
	if options.Thresholds["size.parameter-count"]["maxParameters"] != 8 {
		t.Fatalf("thresholds = %#v, want size.parameter-count maxParameters=8", options.Thresholds)
	}
	if options.Thresholds["complexity.nesting-depth"]["maxDepth"] != 6 {
		t.Fatalf("thresholds = %#v, want complexity.nesting-depth maxDepth=6", options.Thresholds)
	}
	if options.Severities["size.parameter-count"] != "medium" {
		t.Fatalf("severities = %#v, want warning alias mapped to medium for size.parameter-count", options.Severities)
	}
	if options.Severities["docs.exported-symbol-comment"] != "high" {
		t.Fatalf("severities = %#v, want error alias mapped to high for docs.exported-symbol-comment", options.Severities)
	}
	if options.Options["docs.exported-symbol-comment"]["ignoreInternalPackages"] != true {
		t.Fatalf("options = %#v, want ignoreInternalPackages=true", options.Options)
	}
}

func TestParseAcceptsLegacyRuleIDAliases(t *testing.T) {
	cfg, err := ParseFile(".gruff.yaml", []byte(`
selection:
  rules:
    - size-file-length
rules:
  documentation.package-comment:
    enabled: false
  documentation-exported-symbol-comment:
    enabled: true
`), rule.Defaults().Definitions())
	if err != nil {
		t.Fatal(err)
	}
	options := cfg.RuleOptions()
	if !options.Enabled["size.file-length"] {
		t.Fatalf("enabled map = %#v, want legacy hyphen alias mapped to size.file-length", options.Enabled)
	}
	if options.Enabled["docs.package-comment"] {
		t.Fatalf("enabled map = %#v, want documentation package alias disabled", options.Enabled)
	}
	if !options.Enabled["docs.exported-symbol-comment"] {
		t.Fatalf("enabled map = %#v, want documentation exported alias enabled", options.Enabled)
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
		{name: "unknown threshold", json: `{"rules": {"size.file-length": {"thresholds": {"maxBytes": 1}}}}`, want: "unknown threshold"},
		{name: "invalid threshold", json: `{"rules": {"size.file-length": {"thresholds": {"maxLines": 0}}}}`, want: "must be positive"},
		{name: "invalid ignore", json: `{"ignorePaths": ["../outside"]}`, want: "must stay inside"},
		{name: "invalid abbreviation", json: `{"acceptedAbbreviations": ["id"]}`, want: "must be uppercase"},
		{name: "unknown threshold on parameter-count", json: `{"rules": {"size.parameter-count": {"thresholds": {"maxArgs": 3}}}}`, want: "unknown threshold"},
		{name: "invalid threshold on nesting-depth", json: `{"rules": {"complexity.nesting-depth": {"thresholds": {"maxDepth": 0}}}}`, want: "must be positive"},
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
