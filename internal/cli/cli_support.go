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

// targetsForRoot writes each relative target as an absolute path from the launch directory whenever the project root
// is not the launch directory. The analyzer reads operands against the root, so `..` typed from `proj/src` names
// `proj`, but read against the root `proj` it named the directory above the project, which was then scanned.
func targetsForRoot(projectRoot string, paths []string) []string {
	workingDirectory, err := os.Getwd()
	// Inside the launch directory the root and the operands already agree, so they are passed on exactly as typed.
	if err != nil || workingDirectory == projectRoot {
		return paths
	}
	resolved := make([]string, len(paths))
	for index, path := range paths {
		resolved[index] = path
		if !filepath.IsAbs(path) {
			resolved[index] = filepath.Join(workingDirectory, path)
		}
	}
	return resolved
}

// rootRelativePath rewrites a path the user typed, such as --baseline, so that joined to the project root it names the
// file the user meant from the launch directory. It stays relative so the report never publishes a host path; a file
// outside the project keeps its ../ form, which the machine renderers leave out.
func rootRelativePath(projectRoot, path string) string {
	workingDirectory, err := os.Getwd()
	// Inside the launch directory the root and the typed path already agree, so the path is passed on as typed.
	if path == "" || filepath.IsAbs(path) || err != nil || workingDirectory == projectRoot {
		return path
	}
	relativePath, err := filepath.Rel(projectRoot, filepath.Join(workingDirectory, path))
	// Rel fails only when the two cannot share a base; the absolute path still names the right file.
	if err != nil {
		return filepath.Join(workingDirectory, path)
	}
	return relativePath
}

// analyseFromTargets analyses options.Paths against the project root those targets name, not the launch directory.
// Left to default, the root is the launch directory, so `summary ../proj --format=json` run from a sibling exited 2
// with nothing on stdout, and a baseline generated there keyed its identities by absolute host paths. Reports false
// once it has written the reason to stderr.
func analyseFromTargets(options analysis.Options, stderr io.Writer) (analysis.Report, bool) {
	projectRoot, err := projectRootFromTargets(options.Paths)
	// The caller named targets in unrelated projects, so there is no single root to report paths against.
	if err != nil {
		fmt.Fprintf(stderr, "project root: %v\n", err)
		return analysis.Report{}, false
	}
	options.Root = projectRoot
	options.Paths = targetsForRoot(projectRoot, options.Paths)
	options.BaselinePath = rootRelativePath(projectRoot, options.BaselinePath)
	analysisReport, err := analysis.Analyze(options)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return analysis.Report{}, false
	}
	return analysisReport, true
}

// targetOutsideLaunchDirectory returns the first of several targets that sits outside the launch directory.
//
// One target outside it is supported: `gruff-go analyse /srv/checkout` makes that target the project root. Several
// targets outside it are not, because the analyzer resolves each operand against the root it picks, so `../a` and
// `../b` from a sibling directory would resolve to paths that do not exist. The caller refuses that run up front.
func targetOutsideLaunchDirectory(paths []string) (string, bool) {
	workingDirectory, err := os.Getwd()
	// Without a launch directory nothing can be judged outside it, so the run proceeds to fail where it always did.
	if err != nil || len(paths) < 2 {
		return "", false
	}
	for _, path := range paths {
		absolute := path
		// A relative target is meant relative to where the command was typed.
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(workingDirectory, absolute)
		}
		if !isSameOrDescendant(filepath.Clean(absolute), workingDirectory) {
			return path, true
		}
	}
	return "", false
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

// configDiscoveryRoot names the directory the configuration is read from. An explicit --config path keeps the meaning
// the user typed, relative to the launch directory. Otherwise the configuration is the project's own, found at the
// root its targets name: `gruff-go analyse /srv/checkout` run from elsewhere used to look in the launch directory,
// find nothing, and silently scan without the project's rules, gates and sensitive exclusions.
func configDiscoveryRoot(configPath string, targets []string) (string, error) {
	if configPath != "" {
		return os.Getwd()
	}
	root, err := projectRootFromTargets(targets)
	// Targets in unrelated projects have no single root; the launch directory stands in and the analysis says why.
	if err != nil {
		return os.Getwd()
	}
	return root, nil
}

// configuredRegistry builds the rule registry that honours the project's config file.
//
// It also returns the loaded Config so callers can consult MinimumSeverity.
// Running without a config file on disk returns a zero-valued Config, where a MinimumSeverity lookup
// yields an empty string, which callers read as "no value set".
func configuredRegistry(configPath string, noConfig bool, targets []string) (rule.Registry, []string, cfgpkg.Config, error) {
	defaults := rule.Defaults()
	root, err := configDiscoveryRoot(configPath, targets)
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
