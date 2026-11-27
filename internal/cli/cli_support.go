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

// projectRootFromTargets finds the directory that owns the scan paths the user passed, so report paths and policy resolve together.
//
// Returns the launch directory for empty paths or paths inside it (unless an unmarked parent spans distinct projects).
// External paths resolve to their shared project marker root, or deepest common directory when unmarked; returns an error on disjoint roots.
func projectRootFromTargets(paths []string) (string, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// Someone typed `gruff-go analyse` with no target, so the directory they ran it from is the project.
	if len(paths) == 0 {
		return workingDirectory, nil
	}
	common, err := commonTargetDirectory(workingDirectory, paths)
	if err != nil {
		return "", err
	}
	// The targets are inside the directory the command was run from, so that stays the project root unless an unmarked parent spans distinct repos.
	if isSameOrDescendant(common, workingDirectory) {
		// Several targets under an unmarked folder, such as ~/src holding two repos, must belong to one project or paths and totals would mix.
		if len(paths) > 1 && nearestProjectMarkerRoot(workingDirectory) == "" {
			if _, shared := externalTargetsShareProject(workingDirectory, paths); !shared {
				return "", fmt.Errorf("scan targets do not share a project root")
			}
		}
		return workingDirectory, nil
	}
	// A single external target, such as ../other-repo/main.go, is reported from its own project root.
	if len(paths) == 1 {
		return singleExternalTargetRoot(workingDirectory, paths[0], common), nil
	}
	// Climbing all the way to the filesystem root (such as / or C:\) means the external targets do not belong to one project.
	if common == filepath.Dir(common) {
		return "", fmt.Errorf("scan targets do not share a project root")
	}
	// Reject multiple external targets whose nearest project markers disagree, and use their shared marker root when one exists.
	sharedRoot, ok := externalTargetsShareProject(workingDirectory, paths)
	// External targets from two different projects have no single root to report from.
	if !ok {
		return "", fmt.Errorf("scan targets do not share a project root")
	}
	// Targets inside one marked project, such as one go.mod, use that project's root.
	if sharedRoot != "" {
		return sharedRoot, nil
	}
	return common, nil
}

// commonTargetDirectory computes the deepest directory containing every operand in paths resolved relative to workingDirectory.
// It returns that cleaned directory path, or an error when targets live on different filesystem roots (such as Windows drives C: and D:).
func commonTargetDirectory(workingDirectory string, paths []string) (string, error) {
	common := ""
	for _, path := range paths {
		absolute := path
		// A relative target such as internal/cli resolves from the directory the user ran gruff-go in.
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(workingDirectory, absolute)
		}
		absolute = filepath.Clean(absolute)
		directory := absolute
		// A single file target such as main.go, or a missing path, contributes its parent folder to the common directory.
		if info, statErr := os.Stat(absolute); statErr != nil || !info.IsDir() {
			directory = filepath.Dir(absolute)
		}
		if common == "" {
			common = directory
			continue
		}
		for !isSameOrDescendant(directory, common) {
			parent := filepath.Dir(common)
			// Targets on different filesystem roots (such as Windows drives C: and D:) can never share a single root.
			if parent == common {
				return "", fmt.Errorf("scan targets do not share a filesystem root")
			}
			common = parent
		}
	}
	return common, nil
}

// singleExternalTargetRoot resolves the report root for one external operand target given workingDirectory and its containing directory common.
// It returns common when target is a directory, or enclosingProjectRoot(common) when target is a file.
func singleExternalTargetRoot(workingDirectory, target, common string) string {
	resolved := target
	// A relative target is resolved from the folder the user ran the command in.
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(workingDirectory, resolved)
	}
	// A file target, or one that cannot be read, reports from its enclosing project rather than its own folder.
	if info, statErr := os.Stat(resolved); statErr != nil || !info.IsDir() {
		return enclosingProjectRoot(common)
	}
	return common
}

// externalTargetsShareProject resolves whether every target in paths shares one enclosing project marker when markers exist.
//
// workingDirectory resolves relative entries before inspecting ancestors for project markers.
// Returns the shared marker root (empty when unmarked) and true when compatible, or empty and false when targets span distinct or mixed roots.
func externalTargetsShareProject(workingDirectory string, paths []string) (string, bool) {
	sharedRoot := ""
	hasUnmarked := false
	for _, target := range paths {
		targetPath := target
		if !filepath.IsAbs(targetPath) {
			targetPath = filepath.Join(workingDirectory, targetPath)
		}
		targetPath = filepath.Clean(targetPath)
		targetDir := targetPath
		// File targets anchor to their containing directory when searching upward for a project marker.
		if info, err := os.Stat(targetPath); err != nil || !info.IsDir() {
			targetDir = filepath.Dir(targetPath)
		}
		markerRoot := nearestProjectMarkerRoot(targetDir)
		// Reject mixing a marked repository with an external target outside any repository.
		if markerRoot == "" {
			if sharedRoot != "" {
				return "", false
			}
			hasUnmarked = true
			continue
		}
		if hasUnmarked {
			return "", false
		}
		if sharedRoot == "" {
			sharedRoot = markerRoot
			continue
		}
		if sharedRoot != markerRoot {
			return "", false
		}
	}
	return sharedRoot, true
}

// nearestProjectMarkerRoot returns the nearest ancestor of dir (or dir itself) holding a Gruff config, Go module, or Git marker.
// Returns an empty string when walking up to the filesystem root finds none of those markers.
func nearestProjectMarkerRoot(dir string) string {
	for candidate := dir; ; candidate = filepath.Dir(candidate) {
		for _, marker := range []string{defaultConfigFileName, "go.mod", ".git"} {
			if _, err := os.Stat(filepath.Join(candidate, marker)); err == nil {
				return candidate
			}
		}
		// Stop once filepath.Dir stops advancing at the filesystem root (/ or volume root).
		if filepath.Dir(candidate) == candidate {
			return ""
		}
	}
}

// enclosingProjectRoot returns the nearest parent of dir with a Gruff config, Go module, or Git marker.
// An external file with no enclosing project uses dir so its report paths still have a local anchor.
func enclosingProjectRoot(dir string) string {
	// Walk upward from an external file so a nested path can still inherit the enclosing policy.
	for candidate := dir; ; candidate = filepath.Dir(candidate) {
		// A Gruff config, Go module, or Git marker can establish the project whose paths the user expects in the report.
		for _, marker := range []string{defaultConfigFileName, "go.mod", ".git"} {
			// The nearest marker owns the scan, even when a parent directory also contains a project.
			if _, err := os.Stat(filepath.Join(candidate, marker)); err == nil {
				return candidate
			}
		}
		// A file outside any project keeps its own directory as the report root.
		if filepath.Dir(candidate) == candidate {
			return dir
		}
	}
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
//
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
//
// JSON and summary-json omit baseline path and diagnostic file fields for that ../ form; SARIF and GitHub retain diagnostic paths.
// An absolute input and the filepath.Rel fallback stay absolute and can carry a host path.
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
//
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
//
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
//
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
//
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
