// CLI support helpers turn what the user typed into analysis inputs, so cli.go stays focused on command dispatch.
//
// They cover four areas.
//   - The project root and config directory, picked from the scan targets.
//   - The rule registry, configured from the project's config file.
//   - Output-format and flag checks, so a typo fails before any config load or scan.
//   - The rule and pillar display filters, checked against the known rule IDs and pillars.
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
//
// paths are the targets as typed, relative ones read from the launch directory; a file target, or one that does not exist, counts as its folder.
// It returns the launch directory when paths is empty or every target sits inside it, otherwise the deepest directory holding all of them.
// The error is also returned when the launch directory itself cannot be read.
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
			// Targets on different filesystem roots, such as Windows drives C: and D:, share no report root, so this returns an error.
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

// targetsForRoot rewrites each relative target as an absolute path from the launch directory when the project root is somewhere else.
//
// The analyzer reads operands against the root, so .. typed from proj/src, meaning proj, would otherwise scan the directory above proj.
//
// projectRoot is the chosen project root and paths are the targets as typed; absolute targets are always kept as they are.
// It returns paths unchanged when projectRoot is the launch directory or that cannot be read, otherwise a new slice of the same length.
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

// baselinePathForRun picks the baseline this run applies: the path --baseline names, or a regular gruff-baseline.json at projectRoot.
//
// The default file applies without being asked for, so committed accepted debt is honoured and the report names it.
// This follows ADR-006 and FAMILY-CONTRACT.md section 13c; --no-baseline declines it.
//
// values holds the parsed analyse flags: once baselinePath, noBaseline or generateBaselinePath is set, no default file is looked up.
// It returns the --baseline path passed through rootRelativePath, which keeps an absolute path absolute, or the default file's bare name.
// The result is an empty string when no baseline applies, such as --no-baseline alone or a project without the default file.
func baselinePathForRun(projectRoot string, values analyseFlagValues) string {
	if values.baselinePath != "" || values.noBaseline || values.generateBaselinePath != "" {
		return rootRelativePath(projectRoot, values.baselinePath)
	}
	if info, err := os.Stat(filepath.Join(projectRoot, analysis.DefaultBaselineFileName)); err == nil && info.Mode().IsRegular() {
		return analysis.DefaultBaselineFileName
	}
	return ""
}

// rootRelativePath rewrites a relative path the user typed, such as --baseline, so that joined to projectRoot it names the file they meant.
//
// It returns path unchanged when it is empty or absolute, when projectRoot is the launch directory, or when that directory cannot be read.
// Otherwise the result is path rewritten relative to projectRoot, falling back to path joined onto the launch directory when filepath.Rel fails.
//
// A re-anchored path stays relative, so the report does not publish a host path, and a file outside the project keeps its ../ form.
// The machine renderers leave that ../ form out; an absolute input and the filepath.Rel fallback stay absolute and can carry a host path.
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
//
// Run from a sibling directory, summary ../proj --format=json then reports paths inside proj, as it would from proj itself.
// A baseline generated that way keys its identities by paths inside the project, not absolute host paths.
//
// options carries the run's settings; Root is set to the chosen project root, and Paths and BaselinePath are rewritten to match it.
// It returns the analysis report and true, or an empty Report and false once the reason has been written to stderr.
func analyseFromTargets(options analysis.Options, stderr io.Writer) (analysis.Report, bool) {
	projectRoot, err := projectRootFromTargets(options.Paths)
	// An unreadable launch directory, or targets with no shared filesystem root, lands here and the run stops with a project root error.
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
// One target outside it is supported: gruff-go analyse /srv/checkout makes that target the project root.
// The analyse caller refuses a run with several targets when any lies outside the launch directory, and this helper names the first one.
//
// paths are the targets as typed, relative ones read from the launch directory.
// It returns that target as typed and true.
// It gives an empty string and false with fewer than two targets, when none is outside, or when the launch directory cannot be read.
func targetOutsideLaunchDirectory(paths []string) (string, bool) {
	workingDirectory, err := os.Getwd()
	// One target may sit outside the launch directory; with no readable launch directory the run goes on and fails where it always did.
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

// isSameOrDescendant reports whether candidate is ancestor or sits inside it.
//
// Comparison is by whole path segment, so a sibling folder like /work/apidocs is never mistaken for something inside /work/api.
// candidate is the path being tested and ancestor the directory it may sit in; both are compared as given, without cleaning or resolving links.
func isSameOrDescendant(candidate, ancestor string) bool {
	// Identical paths need no segment work, and this is the common case for a single scan target.
	if candidate == ancestor {
		return true
	}
	separator := string(filepath.Separator)
	return strings.HasPrefix(candidate, strings.TrimSuffix(ancestor, separator)+separator)
}

// configDiscoveryRoot names the directory the configuration is read from.
//
// An explicit --config path keeps the meaning the user typed, relative to the launch directory.
// Otherwise the config is the project's own, at the root its targets name, so gruff-go analyse /srv/checkout run from elsewhere finds it.
//
// A non-empty configPath makes it return the launch directory; otherwise it returns the root projectRootFromTargets picks for targets.
// When projectRootFromTargets fails, the launch directory stands in; an error comes only from failing to read the launch directory.
func configDiscoveryRoot(configPath string, targets []string) (string, error) {
	if configPath != "" {
		return os.Getwd()
	}
	root, err := projectRootFromTargets(targets)
	// When target root discovery fails, the launch directory stands in; if it cannot be read either, that error is returned.
	if err != nil {
		return os.Getwd()
	}
	return root, nil
}

// configuredRegistry builds the rule registry that honours the project's config file.
//
// It also returns the loaded Config so callers can consult MinimumSeverity.
// With no config file the returned Config is zero-valued, so a MinimumSeverity lookup yields an empty string, which callers read as no value set.
//
// configPath and noConfig are passed to the config loader as given, and targets decide the discovery root through configDiscoveryRoot.
// The string slice holds the config's IgnorePaths; it is nil when no config file is in use, and the registry is then rule.Defaults().
// It fails, returning zero values, when the launch directory cannot be read, the config does not load, or its rule options are rejected.
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

// sensitiveExclusionsFor converts the loaded config's validated section 13a entries into the analysis-side scopes.
//
// The config package owns every rule, path, key, and rationale check, so this is a shape change only.
// cfg is the loaded config; it returns one entry per SensitiveExclusions item, in order, copying Rule, Path, Symbol and Reason.
// The slice is empty, not nil, when cfg has no sensitive exclusions.
func sensitiveExclusionsFor(cfg cfgpkg.Config) []analysis.SensitiveExclusion {
	exclusions := make([]analysis.SensitiveExclusion, 0, len(cfg.SensitiveExclusions))
	for _, entry := range cfg.SensitiveExclusions {
		exclusions = append(exclusions, analysis.SensitiveExclusion{
			Rule:   entry.Rule,
			Path:   entry.Path,
			Symbol: entry.Symbol,
			Reason: entry.Reason,
		})
	}
	return exclusions
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

// validateAnalyseEnums rejects a bad --format, --report-editor-link or --changed-scope value, so a typo fails before any config load or scan.
//
// The message on stderr uses the same wording the inline parser used.
// format, editorLink and changedScope carry those flag values; only the first unsupported one is described on stderr.
//
// It reports false after writing that message, or true when every value is supported.
// Supported values are the known output formats, none, vscode or phpstorm for editorLink, and symbol or hunk for changedScope.
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
//
// includeRules and excludeRules are comma-separated rule IDs, and every one must match the ID of an entry in definitions.
// includePillars and excludePillars are comma-separated pillar names; an empty string leaves that part of the filter empty.
// It returns the filled DisplayFilter, or a zero DisplayFilter and an error naming the first unknown rule or invalid pillar.
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
//
// input is split by splitCSV, so blank items are dropped; it returns the pillars in order, an empty non-nil slice when input has none.
// It fails with an error naming the first value that is not a valid Pillar, returning nil.
func parsePillars(input string) ([]finding.Pillar, error) {
	values := splitCSV(input)
	pillars := make([]finding.Pillar, 0, len(values))
	for _, value := range values {
		pillar := finding.Pillar(value)
		if !pillar.Valid() {
			return nil, fmt.Errorf("unknown pillar %q", value)
		}
		pillars = append(pillars, pillar)
	}
	return pillars, nil
}

// splitCSV splits a comma-separated input string and trims surrounding whitespace.
// It returns the non-empty trimmed items in order; the result is nil for an empty input and an empty, non-nil slice when every item is blank.
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
