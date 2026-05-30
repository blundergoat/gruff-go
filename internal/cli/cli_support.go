// CLI support helpers: registry configuration, output-format and flag validation,
// and display-filter parsing - split out of cli.go to keep that file focused on
// command dispatch.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// configuredRegistry builds the rule registry honouring the loaded config file.
// Also returns the loaded Config so callers can consult MinimumSeverity. When
// no config file is on disk the returned Config is zero-valued; nil-map lookups
// on cfg.MinimumSeverity[cmd] yield empty string, which is the "no value"
// signal callers expect.
func configuredRegistry(configPath string, noConfig bool) (rule.Registry, []string, cfgpkg.Config, error) {
	defaults := rule.Defaults()
	root, err := os.Getwd()
	if err != nil {
		return rule.Registry{}, nil, cfgpkg.Config{}, err
	}
	loaded, err := cfgpkg.LoadAuto(root, configPath, noConfig, defaults.Definitions())
	if err != nil {
		return rule.Registry{}, nil, cfgpkg.Config{}, err
	}
	if loaded.Path == "" {
		return defaults, nil, cfgpkg.Config{}, nil
	}
	cfg := loaded.Config
	registry, err := rule.DefaultsConfigured(cfg.RuleOptions())
	if err != nil {
		return rule.Registry{}, nil, cfgpkg.Config{}, err
	}
	return registry, cfg.IgnorePaths, cfg, nil
}

// supportedAnalysisFormat reports whether format names a known analyse output.
func supportedAnalysisFormat(format string) bool {
	switch format {
	case "text", "json", "summary-json", "sarif", "github", "html", "markdown", "md":
		return true
	default:
		return false
	}
}

// supportedEditorLink reports whether value names a supported editor-link mode.
func supportedEditorLink(value string) bool {
	switch value {
	case "none", "vscode", "phpstorm":
		return true
	default:
		return false
	}
}

// validateAnalyseEnums rejects out-of-range --format, --report-editor-link, and
// --changed-scope values with the same wording the inline parser used, so a typo
// fails before any config load or scan.
func validateAnalyseEnums(format, editorLink, changedScope string, stderr io.Writer) bool {
	if !supportedAnalysisFormat(format) {
		fmt.Fprintf(stderr, "unsupported format %q\n", format)
		return false
	}
	if !supportedEditorLink(editorLink) {
		fmt.Fprintf(stderr, "unsupported --report-editor-link %q (want none, vscode, or phpstorm)\n", editorLink)
		return false
	}
	if changedScope != "symbol" && changedScope != "hunk" {
		fmt.Fprintf(stderr, "unsupported --changed-scope %q (want symbol or hunk)\n", changedScope)
		return false
	}
	return true
}

// parseDisplayFilter validates the rule and pillar filter flags into a DisplayFilter.
func parseDisplayFilter(includeRules, excludeRules, includePillars, excludePillars string, definitions []rule.Definition) (analysis.DisplayFilter, error) {
	ruleIDs := map[string]struct{}{}
	for _, definition := range definitions {
		ruleIDs[definition.ID] = struct{}{}
	}
	filter := analysis.DisplayFilter{
		IncludeRules: splitCSV(includeRules),
		ExcludeRules: splitCSV(excludeRules),
	}
	for _, id := range append(append([]string{}, filter.IncludeRules...), filter.ExcludeRules...) {
		if _, ok := ruleIDs[id]; !ok {
			return analysis.DisplayFilter{}, fmt.Errorf("unknown rule %q", id)
		}
	}
	var err error
	filter.IncludePillars, err = parsePillars(includePillars)
	if err != nil {
		return analysis.DisplayFilter{}, err
	}
	filter.ExcludePillars, err = parsePillars(excludePillars)
	if err != nil {
		return analysis.DisplayFilter{}, err
	}
	return filter, nil
}

// parsePillars converts a comma-separated pillar list into validated Pillar values.
func parsePillars(input string) ([]finding.Pillar, error) {
	values := splitCSV(input)
	out := make([]finding.Pillar, 0, len(values))
	for _, value := range values {
		pillar := finding.Pillar(value)
		if !pillar.Valid() {
			return nil, fmt.Errorf("unknown pillar %q", value)
		}
		out = append(out, pillar)
	}
	return out, nil
}

// splitCSV splits a comma-separated input string and trims surrounding whitespace.
func splitCSV(input string) []string {
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
