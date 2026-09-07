// CLI support helpers: registry configuration, output-format and flag validation,
// and display-filter parsing - split out of cli.go to keep that file focused on
// command dispatch.
package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// projectRootFromTargets picks the directory that every reported path is written relative to.
//
// Run `gruff-go analyse .` from inside a project and the answer is that directory.
// Run `gruff-go analyse /srv/checkout` from a home directory, as CI and scripted scans do, and the answer is
// /srv/checkout, so the report still reads `internal/api/handler.go` rather than an absolute path.
//
// Returns an error when targets sit under different filesystem roots, leaving no single project to report against.
func projectRootFromTargets(paths []string) (string, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Someone typed `gruff-go analyse` with no target, so the directory they ran it from is the project.
	if len(paths) == 0 {
		return workingDirectory, nil
	}

	common := ""
	// Each target narrows the answer: the root has to be a directory that contains all of them.
	for _, path := range paths {
		absolute := path
		// A relative target like `internal/` is meant relative to where the command was typed.
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(workingDirectory, absolute)
		}
		absolute = filepath.Clean(absolute)

		directory := absolute
		// Naming a single file such as `main.go` means the project is the folder holding it, not the file.
		if info, statErr := os.Stat(absolute); statErr != nil || !info.IsDir() {
			directory = filepath.Dir(absolute)
		}

		// The first target sets the starting answer; later ones can only widen it.
		if common == "" {
			common = directory
			continue
		}
		for !isSameOrDescendant(directory, common) {
			parent := filepath.Dir(common)
			// Walking up hit the filesystem root, so these targets live in unrelated projects.
			if parent == common {
				return "", fmt.Errorf("scan targets do not share a filesystem root")
			}
			common = parent
		}
	}

	// The targets are inside the directory the command was run from, so that stays the project root. Moving it
	// down to a target's own folder would re-anchor config discovery, ignore patterns, and baseline paths.
	if isSameOrDescendant(common, workingDirectory) {
		return workingDirectory, nil
	}
	return common, nil
}

// isSameOrDescendant reports whether one directory is another or sits inside it.
// Comparison is by whole path segment, so a sibling folder like /work/apidocs is never mistaken for
// something inside /work/api.
func isSameOrDescendant(candidate, ancestor string) bool {
	// Identical paths need no segment work, and this is the common case for a single scan target.
	if candidate == ancestor {
		return true
	}
	separator := string(filepath.Separator)
	return strings.HasPrefix(candidate, strings.TrimSuffix(ancestor, separator)+separator)
}

// configuredRegistry builds the rule registry that honours the project's config file.
//
// It also returns the loaded Config so callers can consult MinimumSeverity.
// Running without a config file on disk returns a zero-valued Config, where a MinimumSeverity lookup
// yields an empty string, which callers read as "no value set".
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

// sensitiveExclusionsFor converts the loaded config's validated section 13a
// entries into the analysis-side scopes. The config package owns every rule,
// path, key, and rationale check, so this is a shape change only.
func sensitiveExclusionsFor(cfg cfgpkg.Config) []analysis.SensitiveExclusion {
	out := make([]analysis.SensitiveExclusion, 0, len(cfg.SensitiveExclusions))
	for _, entry := range cfg.SensitiveExclusions {
		out = append(out, analysis.SensitiveExclusion{
			Rule:   entry.Rule,
			Path:   entry.Path,
			Symbol: entry.Symbol,
			Reason: entry.Reason,
		})
	}
	return out
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
