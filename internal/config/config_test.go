// Package config tests cover YAML parsing, rule validation, and discovery.
// They guard the strict schema, rule overrides, and legacy alias compatibility.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/rule"
)

// defaultDefinitions returns rule definitions from the default registry for tests.
func defaultDefinitions() []rule.Definition {
	defaults := rule.Defaults()
	return defaults.Definitions()
}

// TestParseValidatesStrictConfig checks the strict schema accepts a typical config.
func TestParseValidatesStrictConfig(t *testing.T) {
	cfg, err := Parse([]byte(`
schemaVersion: gruff-go.config.v0.1
select: [size.file-length]
ignorePaths:
  - fixtures/**
acceptedAbbreviations: [ID, HTTP]
rules:
  size.file-length:
    enabled: true
    thresholds:
      maxLines: 120
  size.function-length:
    enabled: false
sensitiveData:
  previewAllowlist:
    - testdata/**
`), defaultDefinitions())
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
	if options.AcceptedAbbreviations[0] != "HTTP" || options.AcceptedAbbreviations[1] != "ID" {
		t.Fatalf("accepted abbreviations = %#v, want sorted HTTP/ID", options.AcceptedAbbreviations)
	}
}

// TestParseYAMLGruffShape verifies the gruff-go YAML shape maps to rule options.
func TestParseYAMLGruffShape(t *testing.T) {
	cfg, err := ParseFile(".gruff-go.yaml", []byte(`
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
`), defaultDefinitions())
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
	if options.Severities["complexity.cyclomatic"] != "error" {
		t.Fatalf("severities = %#v, want error stored verbatim", options.Severities)
	}
	if len(cfg.IgnorePaths) != 1 || cfg.IgnorePaths[0] != "fixtures/**" {
		t.Fatalf("ignore paths = %#v, want fixtures ignore", cfg.IgnorePaths)
	}
	if len(options.AcceptedAbbreviations) != 1 || options.AcceptedAbbreviations[0] != "ID" {
		t.Fatalf("accepted abbreviations = %#v, want normalized ID", options.AcceptedAbbreviations)
	}
	if len(options.SensitiveDataPreviewAllowlist) != 1 || options.SensitiveDataPreviewAllowlist[0] != "testdata/**" {
		t.Fatalf("secret preview allowlist = %#v, want normalized testdata pattern", options.SensitiveDataPreviewAllowlist)
	}
}

// TestParseMergesLegacyAndGruffShapeLists verifies gruff-family aliases extend
// rather than replace legacy top-level list fields.
func TestParseMergesLegacyAndGruffShapeLists(t *testing.T) {
	cfg, err := ParseFile(".gruff-go.yaml", []byte(`
select: [size.file-length]
excludeRules: [complexity.cyclomatic]
ignorePaths: ['legacy/**']
acceptedAbbreviations: [HTTP]
sensitiveData:
  previewAllowlist: ['legacy-secrets/**']
paths:
  ignore:
    - 'nested/**'
allowlists:
  acceptedAbbreviations:
    - ID
  secretPreviews:
    - 'nested-secrets/**'
selection:
  rules:
    - dead-code.empty-block
  excludeRules:
    - size.function-length
`), defaultDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(cfg.Select, ","), "dead-code.empty-block,size.file-length"; got != want {
		t.Fatalf("select = %q, want %q", got, want)
	}
	if got, want := strings.Join(cfg.ExcludeRules, ","), "complexity.cyclomatic,size.function-length"; got != want {
		t.Fatalf("exclude rules = %q, want %q", got, want)
	}
	if got, want := strings.Join(cfg.IgnorePaths, ","), "legacy/**,nested/**"; got != want {
		t.Fatalf("ignore paths = %q, want %q", got, want)
	}
	if got, want := strings.Join(cfg.AcceptedAbbreviations, ","), "HTTP,ID"; got != want {
		t.Fatalf("accepted abbreviations = %q, want %q", got, want)
	}
	if got, want := strings.Join(cfg.SensitiveData.PreviewAllowlist, ","), "legacy-secrets/**,nested-secrets/**"; got != want {
		t.Fatalf("secret preview allowlist = %q, want %q", got, want)
	}
}

// TestResolvePathLoadsOnlyGruffGoYAML asserts auto-discovery prefers .gruff-go.yaml.
func TestResolvePathLoadsOnlyGruffGoYAML(t *testing.T) {
	root := t.TempDir()
	definitions := defaultDefinitions()
	writeConfig(t, root, ".gruff-go.yaml", "rules:\n  size.file-length:\n    enabled: true\n")

	loaded, err := LoadAuto(root, "", false, definitions)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Path != filepath.ToSlash(filepath.Join(root, ".gruff-go.yaml")) {
		t.Fatalf("path = %q, want .gruff-go.yaml", loaded.Path)
	}
	if loaded.Config.Rules["size.file-length"].Enabled == nil || !*loaded.Config.Rules["size.file-length"].Enabled {
		t.Fatalf("loaded config = %#v, want preferred .gruff-go.yaml", loaded.Config.Rules)
	}
}

// TestResolvePathIgnoresNonDefaultConfigFiles asserts non-default filenames are skipped.
func TestResolvePathIgnoresNonDefaultConfigFiles(t *testing.T) {
	root := t.TempDir()
	definitions := defaultDefinitions()
	writeConfig(t, root, "config.yaml", "rules:\n  size.file-length:\n    enabled: false\n")

	loaded, err := LoadAuto(root, "", false, definitions)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Path != "" {
		t.Fatalf("path = %q, want no auto-discovered config", loaded.Path)
	}
	if len(loaded.Config.Rules) != 0 {
		t.Fatalf("loaded config = %#v, want empty config", loaded.Config)
	}
}

// TestParseFileRejectsUnsupportedConfigExtension ensures only .yaml configs are accepted.
func TestParseFileRejectsUnsupportedConfigExtension(t *testing.T) {
	for _, path := range []string{"config.txt", "config.yml"} {
		t.Run(path, func(t *testing.T) {
			_, err := ParseFile(path, []byte(`rules: {}`), defaultDefinitions())
			if err == nil || !strings.Contains(err.Error(), "unsupported config file extension") {
				t.Fatalf("err = %v, want unsupported extension", err)
			}
		})
	}
}

// TestParseAcceptsExpansionRuleConfig covers expansion documentation and naming rule options.
func TestParseAcceptsExpansionRuleConfig(t *testing.T) {
	cfg, err := ParseFile(".gruff-go.yaml", []byte(`
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
  docs.comment-rubric:
    enabled: true
    threshold: 2
    options:
      includePaths:
        - internal/analysis/report.go
      excludePaths:
        - internal/analysis/*_test.go
      requirePackageSummary: true
      requireFunctionComments: true
      requireNamedTypeComments: true
      requireConstComments: true
      requireVarComments: true
      ignoreTests: false
  naming.acronym-case:
    enabled: true
    options:
      acronyms:
        - UUID
      allow:
        - ThirdPartyHttpName
  naming.receiver-consistency:
    enabled: true
    options:
      allowMixed:
        - Registry
      inspectGroup: pointer
  naming.get-prefix:
    enabled: true
    options:
      excludePaths:
        - '**/*.pb.go'
      excludeNames:
        - GetProtoUser
  naming.contextual-generic:
    enabled: true
    thresholds:
      minBodyLines: 9
      minFunctionLines: 40
    options:
      genericNames:
        - record
      accumulatorNames:
        - buffer
      requireMultiple: false
	`), defaultDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	options := cfg.RuleOptions()
	assertExpansionRuleEnablement(t, options)
	assertExpansionRuleThresholds(t, options)
	assertExpansionRuleOptions(t, options)
}

// assertExpansionRuleEnablement checks the expansion rules are enabled in options.
func assertExpansionRuleEnablement(t *testing.T, options rule.Config) {
	t.Helper()
	if !options.Enabled["size.parameter-count"] || !options.Enabled["complexity.nesting-depth"] || !options.Enabled["docs.exported-symbol-comment"] || !options.Enabled["docs.comment-rubric"] || !options.Enabled["naming.acronym-case"] || !options.Enabled["naming.receiver-consistency"] || !options.Enabled["naming.get-prefix"] || !options.Enabled["naming.contextual-generic"] {
		t.Fatalf("enabled map = %#v, want expansion documentation and naming rules enabled", options.Enabled)
	}
}

// assertExpansionRuleThresholds verifies parsed numeric thresholds and severity aliases for the size, complexity, naming, and docs expansion rules against expected values like maxDepth=6 and minBodyLines=9.
func assertExpansionRuleThresholds(t *testing.T, options rule.Config) {
	t.Helper()
	if options.Thresholds["size.parameter-count"]["maxParameters"] != 8 {
		t.Fatalf("thresholds = %#v, want size.parameter-count maxParameters=8", options.Thresholds)
	}
	if options.Thresholds["complexity.nesting-depth"]["maxDepth"] != 6 {
		t.Fatalf("thresholds = %#v, want complexity.nesting-depth maxDepth=6", options.Thresholds)
	}
	if options.Severities["size.parameter-count"] != "warning" {
		t.Fatalf("severities = %#v, want warning stored verbatim for size.parameter-count", options.Severities)
	}
	if options.Severities["docs.exported-symbol-comment"] != "error" {
		t.Fatalf("severities = %#v, want error stored verbatim for docs.exported-symbol-comment", options.Severities)
	}
	if options.Options["docs.exported-symbol-comment"]["ignoreInternalPackages"] != true {
		t.Fatalf("options = %#v, want ignoreInternalPackages=true", options.Options)
	}
	if options.Thresholds["docs.comment-rubric"]["minPackageCommentLines"] != 2 {
		t.Fatalf("thresholds = %#v, want docs.comment-rubric minPackageCommentLines=2", options.Thresholds)
	}
	if options.Thresholds["naming.contextual-generic"]["minBodyLines"] != 9 {
		t.Fatalf("thresholds = %#v, want naming.contextual-generic minBodyLines=9", options.Thresholds)
	}
	if options.Thresholds["naming.contextual-generic"]["minFunctionLines"] != 40 {
		t.Fatalf("thresholds = %#v, want naming.contextual-generic minFunctionLines=40", options.Thresholds)
	}
}

// assertExpansionRuleOptions checks parsed option maps for expansion rules.
func assertExpansionRuleOptions(t *testing.T, options rule.Config) {
	t.Helper()
	if options.Options["docs.comment-rubric"]["requireFunctionComments"] != true {
		t.Fatalf("options = %#v, want docs.comment-rubric requireFunctionComments=true", options.Options)
	}
	if options.Options["naming.acronym-case"]["allow"].([]any)[0] != "ThirdPartyHttpName" {
		t.Fatalf("options = %#v, want naming.acronym-case allow list", options.Options)
	}
	if options.Options["naming.receiver-consistency"]["inspectGroup"] != "pointer" {
		t.Fatalf("options = %#v, want naming.receiver-consistency inspectGroup=pointer", options.Options)
	}
	if options.Options["naming.get-prefix"]["excludeNames"].([]any)[0] != "GetProtoUser" {
		t.Fatalf("options = %#v, want naming.get-prefix excludeNames", options.Options)
	}
	if options.Options["naming.contextual-generic"]["genericNames"].([]any)[0] != "record" {
		t.Fatalf("options = %#v, want naming.contextual-generic genericNames", options.Options)
	}
	if options.Options["naming.contextual-generic"]["accumulatorNames"].([]any)[0] != "buffer" {
		t.Fatalf("options = %#v, want naming.contextual-generic accumulatorNames", options.Options)
	}
	if options.Options["naming.contextual-generic"]["requireMultiple"] != false {
		t.Fatalf("options = %#v, want naming.contextual-generic requireMultiple=false", options.Options)
	}
}

// TestParseAcceptsCompositeRuleConfig verifies composite design rules parse and validate.
func TestParseAcceptsCompositeRuleConfig(t *testing.T) {
	cfg, err := ParseFile(".gruff-go.yaml", []byte(`
rules:
  design.god-function:
    enabled: true
  design.hotspot-file:
    enabled: true
    thresholds:
      minFindings: 4
      minPillars: 3
`), defaultDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	options := cfg.RuleOptions()
	if !options.Enabled["design.god-function"] || !options.Enabled["design.hotspot-file"] {
		t.Fatalf("enabled map = %#v, want composite rules enabled", options.Enabled)
	}
	if options.Thresholds["design.hotspot-file"]["minFindings"] != 4 {
		t.Fatalf("thresholds = %#v, want design.hotspot-file minFindings=4", options.Thresholds)
	}
	if options.Thresholds["design.hotspot-file"]["minPillars"] != 3 {
		t.Fatalf("thresholds = %#v, want design.hotspot-file minPillars=3", options.Thresholds)
	}
}

// TestParseAcceptsLegacyRuleIDAliases covers hyphenated and renamed legacy rule IDs.
func TestParseAcceptsLegacyRuleIDAliases(t *testing.T) {
	cfg, err := ParseFile(".gruff-go.yaml", []byte(`
selection:
  rules:
    - size-file-length
rules:
  documentation.package-comment:
    enabled: false
  documentation-exported-symbol-comment:
    enabled: true
`), defaultDefinitions())
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

// writeConfig writes a config file under the test root for discovery tests.
func writeConfig(t *testing.T, root, rel, contents string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestParseRejectsInvalidConfig table-tests rejection cases for invalid configurations.
func TestParseRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "unknown top-level key", yaml: `unknown: true`, want: "unknown field"},
		{name: "unknown selected rule", yaml: "select:\n  - missing-rule\n", want: "unknown selected rule"},
		{name: "unknown rule", yaml: "rules:\n  missing-rule:\n    enabled: true\n", want: "unknown rule"},
		{name: "unknown threshold", yaml: "rules:\n  size.file-length:\n    thresholds:\n      maxBytes: 1\n", want: "unknown threshold"},
		{name: "invalid threshold", yaml: "rules:\n  size.file-length:\n    thresholds:\n      maxLines: 0\n", want: "must be positive"},
		{name: "combined threshold forms", yaml: "rules:\n  size.file-length:\n    threshold: 100\n    thresholds:\n      maxLines: 120\n", want: "cannot combine threshold and thresholds"},
		{name: "invalid ignore", yaml: "ignorePaths:\n  - ../outside\n", want: "must stay inside"},
		{name: "blank abbreviation", yaml: "acceptedAbbreviations:\n  - ''\n", want: "must not be blank"},
		{name: "unknown threshold on parameter-count", yaml: "rules:\n  size.parameter-count:\n    thresholds:\n      maxArgs: 3\n", want: "unknown threshold"},
		{name: "invalid threshold on nesting-depth", yaml: "rules:\n  complexity.nesting-depth:\n    thresholds:\n      maxDepth: 0\n", want: "must be positive"},
		{name: "unknown threshold on hotspot", yaml: "rules:\n  design.hotspot-file:\n    thresholds:\n      maxFindings: 3\n", want: "unknown threshold"},
		{name: "unknown option on comment rubric", yaml: "rules:\n  docs.comment-rubric:\n    options:\n      requireEmoji: true\n", want: "unknown option"},
		{name: "unknown threshold on comment rubric", yaml: "rules:\n  docs.comment-rubric:\n    thresholds:\n      minCommentVibes: 3\n", want: "unknown threshold"},
		{name: "unknown option on acronym case", yaml: "rules:\n  naming.acronym-case:\n    options:\n      canonicalOnly: true\n", want: "unknown option"},
		{name: "unknown option on receiver consistency", yaml: "rules:\n  naming.receiver-consistency:\n    options:\n      allowValue: true\n", want: "unknown option"},
		{name: "unknown option on get prefix", yaml: "rules:\n  naming.get-prefix:\n    options:\n      allowGenerated: true\n", want: "unknown option"},
		{name: "unknown option on contextual generic", yaml: "rules:\n  naming.contextual-generic:\n    options:\n      allowShortLoops: true\n", want: "unknown option"},
		{name: "unknown threshold on contextual generic", yaml: "rules:\n  naming.contextual-generic:\n    thresholds:\n      maxGenericNames: 2\n", want: "unknown threshold"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml), defaultDefinitions())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}
