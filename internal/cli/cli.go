// Package cli implements the gruff-go command-line interface.
// It wires command-line flags and dispatches subcommands to the analysis pipeline.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// toolVersion is the released gruff-go semantic version printed by --version.
const toolVersion = "0.3.0"

// Main is the CLI entrypoint that parses args and dispatches subcommands.
func Main(args []string, stdout, stderr io.Writer) int {
	args, ansiPref := extractAnsiFlags(args)
	args, quiet := extractQuiet(args)
	args, noInteraction := extractNoInteraction(args)
	args = extractVerbose(args)
	if quiet {
		stdout = io.Discard
	}
	interactive := !noInteraction && !quiet
	stdoutStyle := ansiStyler{enabled: ansiEnabled(stdout, ansiPref)}
	stderrStyle := ansiStyler{enabled: ansiEnabled(stderr, ansiPref)}

	if len(args) == 0 {
		usage(stderr, stderrStyle)
		return 2
	}

	if isVersionFlag(args[0]) {
		fmt.Fprintf(stdout, "gruff-go %s\n", toolVersion)
		return 0
	}

	switch args[0] {
	case "analyse", "analyze":
		return runAnalyse(args[1:], stdout, stderr, interactive)
	case "baseline":
		return runBaseline(args[1:], stdout, stderr)
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "completion":
		return runCompletion(args[1:], stdout, stderr)
	case "list-rules":
		return runListRules(args[1:], stdout, stderr)
	case "check-ignore":
		return runCheckIgnore(args[1:], stdout, stderr)
	case "summary":
		return runSummary(args[1:], stdout, stderr, interactive)
	case "report":
		return runReport(args[1:], stdout, stderr, interactive)
	case "dashboard":
		return runDashboard(args[1:], stdout, stderr, interactive)
	case "list":
		usage(stdout, stdoutStyle)
		return 0
	case "help", "-h", "--help":
		if len(args) > 1 {
			return helpForCommand(args[1], stdout, stderr, stdoutStyle, stderrStyle)
		}
		usage(stdout, stdoutStyle)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr, stderrStyle)
		return 2
	}
}

// extractQuiet removes -q / --quiet from args and returns the result plus a
// boolean indicating whether quiet mode was requested. The flag can appear at
// any position.
func extractQuiet(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	quiet := false
	for _, arg := range args {
		switch arg {
		case "-q", "--quiet", "--silent":
			quiet = true
		default:
			out = append(out, arg)
		}
	}
	return out, quiet
}

// extractVerbose accepts common Symfony-style verbosity flags. gruff-go does
// not currently vary output by verbosity, but accepting these flags keeps the
// global surface consistent across gruff implementations.
func extractVerbose(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		switch arg {
		case "-v", "-vv", "-vvv", "--verbose":
			continue
		default:
			out = append(out, arg)
		}
	}
	return out
}

// isVersionFlag reports whether the argument requests version output.
func isVersionFlag(arg string) bool {
	return arg == "-V" || arg == "--version"
}

// runAnalyse executes the analyse subcommand and renders the scan report.
func runAnalyse(args []string, stdout, stderr io.Writer, interactive bool) int {
	flags, values, ok := parseAnalyseFlags(args, stderr)
	if !ok {
		return 2
	}
	registry, ignorePaths, cfg, err := configuredRegistryInteractive(values.configPath, values.noConfig, interactive, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	failOn, ok := resolveFailOn(values.minSeverityRaw, values.minSeverityExplicit, cfg, "analyse", stderr)
	if !ok {
		return 2
	}
	if values.generateBaselinePath != "" {
		return writeBaselineFromScan(baselineScanOptions{
			paths:          flags.Args(),
			outPath:        values.generateBaselinePath,
			registry:       registry,
			ignorePaths:    ignorePaths,
			includeIgnored: values.includeIgnored,
		}, stdout, stderr)
	}
	displayFilter, err := parseDisplayFilter(values.includeRules, values.excludeRules, values.includePillars, values.excludePillars, registry.Definitions())
	if err != nil {
		fmt.Fprintf(stderr, "display filter: %v\n", err)
		return 2
	}
	analysisReport, err := analysis.Analyze(analysis.Options{
		Paths:          flags.Args(),
		Format:         values.format,
		FailOn:         failOn,
		Registry:       registry,
		IgnorePaths:    ignorePaths,
		IncludeIgnored: values.includeIgnored,
		BaselinePath:   values.baselinePath,
		DiffBase:       values.diffBase,
		DiffMode:       values.resolvedDiffMode(),
		DiffPatch:      values.diffPatch,
		ChangedRanges:  values.changedRanges,
		ChangedScope:   values.changedScope,
		BaselineShow:   values.baselineShow,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	analysis.ApplyDisplayFilter(&analysisReport, displayFilter)
	if err := writeAnalysisReport(stdout, values.format, analysisReport, report.HTMLOptions{EditorLink: values.editorLink, Interactive: values.reportInteractive}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return analysisReport.Summary.ExitCode
}

// analyseFlagValues is the parsed analyse command state after validation.
// minSeverityRaw + minSeverityExplicit replace the resolved FailThreshold so
// runAnalyse can apply the ADR-010 precedence (CLI flag > minimumSeverity.cmd
// > DefaultFailThresholdFor) after the config has been loaded.
type analyseFlagValues struct {
	format               string
	minSeverityRaw       string
	minSeverityExplicit  bool
	configPath           string
	noConfig             bool
	baselinePath         string
	generateBaselinePath string
	diffBase             string
	diffMode             string
	since                string
	diffPatch            []byte
	changedRanges        string
	changedScope         string
	baselineShow         bool
	includeRules         string
	excludeRules         string
	includePillars       string
	excludePillars       string
	editorLink           string
	reportInteractive    bool
	includeIgnored       bool
}

// resolvedDiffMode returns the effective changed-region source, preferring an
// explicit --since base ref over --diff so the alias wins when both are supplied.
func (values analyseFlagValues) resolvedDiffMode() string {
	if values.since != "" {
		return values.since
	}
	return values.diffMode
}

// normalizeAnalyseDiffArgs rewrites a bare `--diff` (no value, or followed by
// another flag) into `--diff=working-tree`, and `--diff -` into `--diff=-`, so it
// behaves like an optional-value flag - which Go's flag package does not support
// natively.
func normalizeAnalyseDiffArgs(args []string) []string {
	normalized := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg != "--diff" {
			normalized = append(normalized, arg)
			continue
		}
		if i+1 < len(args) && args[i+1] == "-" {
			normalized = append(normalized, "--diff=-")
			i++
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
			normalized = append(normalized, "--diff=working-tree")
			continue
		}
		// A following filesystem path (git refs cannot begin with '.' or '/') means
		// the user wants a working-tree diff scoped to that path, not a base ref, so
		// default the mode and leave the path as a positional argument instead of
		// silently consuming it as the diff base.
		if looksLikeDiffPath(args[i+1]) {
			normalized = append(normalized, "--diff=working-tree")
			continue
		}
		normalized = append(normalized, arg)
	}
	return normalized
}

// looksLikeDiffPath reports whether arg is a filesystem path rather than a git base
// ref. Git ref names cannot begin with '.' or '/', so a leading ".", "./", "../",
// "/", or "~" marks a path the user means to scope the working-tree diff to.
func looksLikeDiffPath(arg string) bool {
	return arg == "." || strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") ||
		strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "~")
}

// readDiffPatchIfRequested reads a unified diff from stdin when diffMode is "-",
// returning ok=false only on a read error; for any other mode it is a no-op that
// succeeds, so callers can invoke it unconditionally.
func readDiffPatchIfRequested(diffMode string, stderr io.Writer) ([]byte, bool) {
	if diffMode != "-" {
		return nil, true
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(stderr, "diff stdin: %v\n", err)
		return nil, false
	}
	return data, true
}

// resolveAndReadDiffPatch reads a stdin patch only when the effective diff mode is
// the "-" sentinel. --since overrides --diff (see resolvedDiffMode), so resolving
// the effective mode first means `--since X --diff=-` does not block on stdin that
// the resolved mode would discard.
func resolveAndReadDiffPatch(diffMode, since string, stderr io.Writer) ([]byte, bool) {
	effective := diffMode
	if since != "" {
		effective = since
	}
	return readDiffPatchIfRequested(effective, stderr)
}

// resolveFailOn applies the ADR-010 precedence rule for any CLI consumer:
// explicit CLI flag wins, otherwise the matching minimumSeverity.<cmd> config
// entry, otherwise the binary default from DefaultFailThresholdFor. Returns
// (threshold, ok); on parse failure prints the error to stderr and returns
// (zero-value, false) so the caller can `return 2`.
func resolveFailOn(rawValue string, flagExplicit bool, cfg cfgpkg.Config, cmd string, stderr io.Writer) (finding.FailThreshold, bool) {
	resolved := rawValue
	if !flagExplicit {
		if cfgValue := cfg.MinimumSeverity[cmd]; cfgValue != "" {
			resolved = cfgValue
		}
	}
	parsed, err := finding.ParseFailThreshold(resolved)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return "", false
	}
	return parsed, true
}

// checkMinSeverityFlag detects whether --min-severity / --fail-on was passed
// explicitly on the FlagSet, and early-validates the raw value when explicit so
// the user sees flag-syntax errors before any config load. Returns (explicit,
// ok); on parse failure prints to stderr and returns (_, false). Shared by
// runAnalyse / runSummary / runReport so the detection + early-validate block
// lives in one place.
func checkMinSeverityFlag(flags *flag.FlagSet, rawValue string, stderr io.Writer) (bool, bool) {
	explicit := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "min-severity" || f.Name == "fail-on" {
			explicit = true
		}
	})
	if explicit {
		if _, err := finding.ParseFailThreshold(rawValue); err != nil {
			fmt.Fprintln(stderr, err)
			return explicit, false
		}
	}
	return explicit, true
}

// parseAnalyseFlags parses and validates analyse flags, printing validation
// errors to stderr in the same style as the legacy inline parser.
func parseAnalyseFlags(args []string, stderr io.Writer) (*flag.FlagSet, analyseFlagValues, bool) {
	flags := flag.NewFlagSet("analyse", flag.ContinueOnError)
	flags.SetOutput(stderr)
	args = normalizeAnalyseDiffArgs(args)
	format := flags.String("format", "text", "output format: text, json, summary-json, sarif, github, html, or markdown")
	// ADR-009 + ADR-010: default is whatever DefaultFailThresholdFor("analyse")
	// returns (currently advisory, intentionally permissive after the 3-bucket
	// migration). Help text shows this default; precedence in runAnalyse lets
	// .gruff-go.yaml's minimumSeverity.analyse override it.
	minSeverity := string(finding.DefaultFailThresholdFor("analyse"))
	flags.StringVar(&minSeverity, "min-severity", minSeverity, "minimum severity that causes exit 1")
	flags.StringVar(&minSeverity, "fail-on", minSeverity, "alias for --min-severity")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	baselinePath := flags.String("baseline", "", "baseline file to apply")
	baselineShow := flags.Bool("baseline-show", false, "render the unchanged and resolved baseline sets (counts are always reported)")
	generateBaselinePath := flags.String("generate-baseline", "", "write current findings to a baseline file and exit cleanly")
	diffBase := flags.String("diff-base", "", "git base ref for changed-line filtering")
	diffMode := flags.String("diff", "", "changed-region source: working-tree, staged, unstaged, base ref, or - for unified diff on stdin")
	since := flags.String("since", "", "git base ref for changed-region filtering")
	changedRanges := flags.String("changed-ranges", "", "explicit changed line ranges such as 3-3,8-10")
	changedScope := flags.String("changed-scope", "symbol", "changed-region scope: symbol or hunk")
	includeRules := flags.String("include-rules", "", "comma-separated rule IDs to display")
	excludeRules := flags.String("exclude-rules", "", "comma-separated rule IDs to hide from display")
	includePillars := flags.String("include-pillars", "", "comma-separated pillars to display")
	excludePillars := flags.String("exclude-pillars", "", "comma-separated pillars to hide from display")
	editorLink := flags.String("report-editor-link", "none", "html report file:line link mode: none, vscode, or phpstorm")
	reportInteractive := flags.Bool("report-interactive", false, "enable interactive findings filter UI in html output")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	if err := flags.Parse(args); err != nil {
		return flags, analyseFlagValues{}, false
	}
	if !validateAnalyseEnums(*format, *editorLink, *changedScope, stderr) {
		return flags, analyseFlagValues{}, false
	}
	diffPatch, ok := resolveAndReadDiffPatch(*diffMode, *since, stderr)
	if !ok {
		return flags, analyseFlagValues{}, false
	}
	minSeverityExplicit, ok := checkMinSeverityFlag(flags, minSeverity, stderr)
	if !ok {
		return flags, analyseFlagValues{}, false
	}
	values := analyseFlagValues{
		format:               *format,
		minSeverityRaw:       minSeverity,
		minSeverityExplicit:  minSeverityExplicit,
		configPath:           *configPath,
		noConfig:             *noConfig,
		baselinePath:         *baselinePath,
		generateBaselinePath: *generateBaselinePath,
		diffBase:             *diffBase,
		diffMode:             *diffMode,
		since:                *since,
		diffPatch:            diffPatch,
		changedRanges:        *changedRanges,
		changedScope:         *changedScope,
		baselineShow:         *baselineShow,
		includeRules:         *includeRules,
		excludeRules:         *excludeRules,
		includePillars:       *includePillars,
		excludePillars:       *excludePillars,
		editorLink:           *editorLink,
		reportInteractive:    *reportInteractive,
		includeIgnored:       *includeIgnored,
	}
	if values.generateBaselinePath != "" {
		if err := validateGenerateBaselineFlags(generateBaselineFlagState{
			baselinePath:   values.baselinePath,
			diffBase:       values.diffBase,
			diffMode:       values.diffMode,
			since:          values.since,
			changedRanges:  values.changedRanges,
			includeRules:   values.includeRules,
			excludeRules:   values.excludeRules,
			includePillars: values.includePillars,
			excludePillars: values.excludePillars,
		}); err != nil {
			fmt.Fprintln(stderr, err)
			return flags, analyseFlagValues{}, false
		}
	}
	return flags, values, true
}

// generateBaselineFlagState groups analyse flags that change finding scope.
type generateBaselineFlagState struct {
	baselinePath   string
	diffBase       string
	diffMode       string
	since          string
	changedRanges  string
	includeRules   string
	excludeRules   string
	includePillars string
	excludePillars string
}

// validateGenerateBaselineFlags rejects combinations that would make the
// generated baseline partial rather than a fresh snapshot of current findings.
func validateGenerateBaselineFlags(state generateBaselineFlagState) error {
	switch {
	case state.baselinePath != "":
		return fmt.Errorf("--generate-baseline cannot be combined with --baseline")
	case state.diffBase != "":
		return fmt.Errorf("--generate-baseline cannot be combined with --diff-base")
	case state.diffMode != "" || state.since != "" || state.changedRanges != "":
		return fmt.Errorf("--generate-baseline cannot be combined with changed-region flags")
	case state.includeRules != "" || state.excludeRules != "" || state.includePillars != "" || state.excludePillars != "":
		return fmt.Errorf("--generate-baseline cannot be combined with display filters")
	default:
		return nil
	}
}

// writeAnalysisReport serialises the analysis report to writer in the chosen format.
func writeAnalysisReport(writer io.Writer, format string, analysisReport analysis.Report, htmlOpts report.HTMLOptions) error {
	switch format {
	case "json":
		return report.WriteJSON(writer, analysisReport)
	case "summary-json":
		return report.WriteSummaryJSON(writer, analysisReport)
	case "sarif":
		return report.WriteSARIF(writer, analysisReport)
	case "github":
		return report.WriteGitHub(writer, analysisReport)
	case "html":
		return report.WriteHTML(writer, analysisReport, htmlOpts)
	case "markdown", "md":
		return report.WriteMarkdown(writer, analysisReport)
	default:
		return report.WriteText(writer, analysisReport)
	}
}

// runListRules prints metadata for every registered rule.
func runListRules(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("list-rules", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "unsupported format %q\n", *format)
		return 2
	}
	registry, _, _, err := configuredRegistry(*configPath, *noConfig)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	definitions := registry.Definitions()
	if *format == "json" {
		payload := struct {
			SchemaVersion string            `json:"schemaVersion"`
			Rules         []rule.Definition `json:"rules"`
		}{
			SchemaVersion: analysis.SchemaVersion,
			Rules:         definitions,
		}
		if err := report.WriteJSON(stdout, payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return 0
	}
	if err := report.WriteRuleText(stdout, definitions); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}
