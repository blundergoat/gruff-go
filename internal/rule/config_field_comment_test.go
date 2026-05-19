// Package rule defines gruff-go's rule registry and analysers.
// This file exercises the docs.config-field-comment rule across path scoping
// and field shapes (exported, unexported, embedded, no exported fields).
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
)

// configFieldRuleScoped returns a ConfigFieldCommentRule pinned to the canonical includePaths used
// by the M29 fixture tests; tests that need different scopes build the rule inline.
func configFieldRuleScoped() ConfigFieldCommentRule {
	return ConfigFieldCommentRule{IncludePaths: []string{"internal/config/**"}}
}

// TestConfigFieldCommentRuleDocumentedFieldPasses confirms a field with a useful doc comment
// produces no finding under the rule.
func TestConfigFieldCommentRuleDocumentedFieldPasses(t *testing.T) {
	unit := parseOne(t, "internal/config/config.go", `package config

type Config struct {
	// Name explains the configuration identifier used downstream.
	Name string
}
`)
	if findings := configFieldRuleScoped().AnalyzeUnit(unit, Context{}); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for documented field", findings)
	}
}

// TestConfigFieldCommentRuleUndocumentedFieldFails confirms an undocumented exported field in scope
// produces a finding with symbol Type.Field and the expected metadata.
func TestConfigFieldCommentRuleUndocumentedFieldFails(t *testing.T) {
	unit := parseOne(t, "internal/config/config.go", `package config

type Config struct {
	Name string
}
`)
	findings := configFieldRuleScoped().AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one Name finding", findings)
	}
	if findings[0].Symbol != "Config.Name" {
		t.Fatalf("finding symbol = %q, want Config.Name", findings[0].Symbol)
	}
	if findings[0].Metadata["field"] != "Name" || findings[0].Metadata["type"] != "Config" {
		t.Fatalf("finding metadata = %#v, want field=Name type=Config", findings[0].Metadata)
	}
}

// TestConfigFieldCommentRuleUnexportedFieldExempt confirms unexported fields are never flagged.
func TestConfigFieldCommentRuleUnexportedFieldExempt(t *testing.T) {
	unit := parseOne(t, "internal/config/config.go", `package config

type Config struct {
	secret string
}
`)
	if findings := configFieldRuleScoped().AnalyzeUnit(unit, Context{}); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for unexported field", findings)
	}
}

// TestConfigFieldCommentRuleEmbeddedFieldExempt confirms embedded fields (no Names) are exempt
// across the common embedding shapes (bare type, pointer, selector).
func TestConfigFieldCommentRuleEmbeddedFieldExempt(t *testing.T) {
	unit := parseOne(t, "internal/config/config.go", `package config

type Base struct{}

type Config struct {
	Base
	*Inner
	external.Imported
}

type Inner struct{}
`)
	findings := configFieldRuleScoped().AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for embedded fields", findings)
	}
}

// TestConfigFieldCommentRuleIncludePathsGates confirms files outside the configured includePaths
// produce no findings even when they contain undocumented exported fields.
func TestConfigFieldCommentRuleIncludePathsGates(t *testing.T) {
	unit := parseOne(t, "internal/other/other.go", `package other

type External struct {
	Name string
}
`)
	if findings := configFieldRuleScoped().AnalyzeUnit(unit, Context{}); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none outside includePaths", findings)
	}
}

// TestConfigFieldCommentRuleExcludePathsRemovesPath confirms a path listed in excludePaths is not
// enforced even when it sits inside includePaths.
func TestConfigFieldCommentRuleExcludePathsRemovesPath(t *testing.T) {
	unit := parseOne(t, "internal/config/legacy.go", `package config

type Legacy struct {
	Name string
}
`)
	rule := ConfigFieldCommentRule{
		IncludePaths: []string{"internal/config/**"},
		ExcludePaths: []string{"internal/config/legacy.go"},
	}
	if findings := rule.AnalyzeUnit(unit, Context{}); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for excluded path", findings)
	}
}

// TestConfigFieldCommentRuleNoExportedFields confirms structs with only unexported fields produce
// no findings.
func TestConfigFieldCommentRuleNoExportedFields(t *testing.T) {
	unit := parseOne(t, "internal/config/config.go", `package config

type private struct {
	hidden string
}

type Holder struct {
	internal int
}
`)
	if findings := configFieldRuleScoped().AnalyzeUnit(unit, Context{}); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none when no exported fields exist", findings)
	}
}

// TestConfigFieldCommentRuleNameRestatementFails confirms a comment that just repeats the field
// name fails the same "normalises differently from the symbol" check as docs.comment-rubric.
func TestConfigFieldCommentRuleNameRestatementFails(t *testing.T) {
	unit := parseOne(t, "internal/config/config.go", `package config

type Config struct {
	// Name
	Name string
}
`)
	findings := configFieldRuleScoped().AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "Config.Name" {
		t.Fatalf("findings = %#v, want one Config.Name finding (name restatement)", findings)
	}
}

// TestConfigFieldCommentRuleNoIncludePathsAppliesEverywhere confirms an unconfigured rule applies
// to every Go file. Projects are expected to set includePaths to keep noise down.
func TestConfigFieldCommentRuleNoIncludePathsAppliesEverywhere(t *testing.T) {
	unit := parseOne(t, "anywhere.go", `package anywhere

type Open struct {
	Field string
}
`)
	rule := ConfigFieldCommentRule{}
	findings := rule.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one finding when includePaths is unset", findings)
	}
}

// TestConfigFieldCommentRuleDefaultsConfigured verifies the rule registers default-disabled and
// that the strict-config path correctly threads includePaths.
func TestConfigFieldCommentRuleDefaultsConfigured(t *testing.T) {
	unit := parseOne(t, "internal/config/config.go", `package config

type Config struct {
	Name string
}
`)
	defaults := Defaults()
	if findings := defaults.Analyze([]parser.Unit{unit}, Context{}); containsRuleID(findings, "docs.config-field-comment") {
		t.Fatalf("default findings = %#v, want docs.config-field-comment disabled", findings)
	}

	registry, err := DefaultsConfigured(Config{
		Enabled: map[string]bool{"docs.config-field-comment": true},
		Options: map[string]map[string]any{
			"docs.config-field-comment": {
				"includePaths": []any{"internal/config/**"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings := registry.Analyze([]parser.Unit{unit}, Context{})
	if !containsRuleID(findings, "docs.config-field-comment") {
		t.Fatalf("findings = %#v, want docs.config-field-comment when enabled with includePaths", findings)
	}
}
