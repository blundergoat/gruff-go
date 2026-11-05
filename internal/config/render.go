// Package config emits a default .gruff-go.yaml from the registry catalogue for gruff-go init and the interactive bootstrap.
//
// Render writes the canonical YAML shape Load reads; with RenderOptions.Existing set it writes these values from the loaded config back out.
//   - paths.ignore, allowlists.acceptedAbbreviations and sensitiveExclusions.
//   - failOn, minimumSeverity and deepScanBudget.
//   - Per-rule enabled, severity, threshold and thresholds; options are written too but can lose their type or mapping shape.
//
// Rules missing from the registry are dropped and new ones land at defaults; init --force merges only when the existing config loads.
package config

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// RenderOptions controls how Render layers project-specific overrides onto the default template.
//
// A zero-value RenderOptions reproduces the original fresh-from-defaults output.
// Setting Existing writes the listed tuning back out, though option values can change type; selection lists are always reset to empty.
type RenderOptions struct {
	// Existing carries previously-tuned config to splice into the new file.
	// When nil, scaffolds use their defaults, including the accepted-abbreviation seed list, and rule blocks use registry defaults.
	Existing *Config
}

// Render returns a default .gruff-go.yaml body that mirrors the registry's per-rule enablement, severity, and threshold defaults.
//
// Rule blocks are sorted by rule ID; a list value yamlQuoteIfNeeded leaves bare, such as true, can read back through Load as another type.
// When opts.Existing is non-nil its scaffolds and per-rule overrides are layered into the output.
// definitions is copied before sorting, so the caller's slice keeps its order; opts carries the optional Existing config to merge.
func Render(definitions []rule.Definition, opts RenderOptions) []byte {
	sorted := append([]rule.Definition(nil), definitions...)
	slices.SortFunc(sorted, func(a, b rule.Definition) int { return strings.Compare(a.ID, b.ID) })

	var buf bytes.Buffer
	writeRenderHeader(&buf)
	writeRenderDeepScanBudget(&buf, opts)
	writeRenderMinimumSeverity(&buf, opts)
	writeRenderScaffolds(&buf, opts)
	writeRenderRules(&buf, sorted, opts)
	return buf.Bytes()
}

// writeRenderDeepScanBudget publishes the paired degradation bounds and preserves prior tuning.
//
// It writes the deepScanBudget block to buf, keeping each enabled, maxLines or maxBytes value set in the Existing config of opts.
// Unset values fall back to enabled true and the DefaultDeepScanMaxLines and DefaultDeepScanMaxBytes bounds.
func writeRenderDeepScanBudget(buf *bytes.Buffer, opts RenderOptions) {
	enabled := true
	maxLines := DefaultDeepScanMaxLines
	maxBytes := DefaultDeepScanMaxBytes
	// Regenerating over an existing config, as gruff-go init --force does, keeps each bound the user tuned.
	if opts.Existing != nil {
		if opts.Existing.DeepScanBudget.Enabled != nil {
			enabled = *opts.Existing.DeepScanBudget.Enabled
		}
		if opts.Existing.DeepScanBudget.MaxLines != nil {
			maxLines = *opts.Existing.DeepScanBudget.MaxLines
		}
		if opts.Existing.DeepScanBudget.MaxBytes != nil {
			maxBytes = *opts.Existing.DeepScanBudget.MaxBytes
		}
	}
	fmt.Fprintln(buf, "# Above either bound, retain text-level rules and omit AST-backed deep analysis.")
	fmt.Fprintln(buf, "deepScanBudget:")
	fmt.Fprintf(buf, "  enabled: %t\n", enabled)
	fmt.Fprintf(buf, "  maxLines: %d\n", maxLines)
	fmt.Fprintf(buf, "  maxBytes: %d\n\n", maxBytes)
}

// writeRenderMinimumSeverity emits the failOn exit gate and the minimumSeverity display floor, two keys the family contract separates.
//
// Gate values come from finding.DefaultFailThresholdFor unless the existing config already tuned a key, which is preserved verbatim.
// It writes both keys to buf, with failOn entries for analyse, summary, report and dashboard, reading any preserved values from opts.
func writeRenderMinimumSeverity(buf *bytes.Buffer, opts RenderOptions) {
	fmt.Fprintln(buf, "# Per-command exit-code thresholds (ADR-010). Each key overrides the binary")
	fmt.Fprintln(buf, "# default for the matching gruff-go subcommand. Values: advisory | warning |")
	fmt.Fprintln(buf, "# error | none (where 'none' disables the gate, exit 0 regardless of findings).")
	fmt.Fprintln(buf, "# Precedence: CLI flag > failOn.<cmd> > binary default.")
	fmt.Fprintln(buf, "failOn:")
	for _, cmd := range []string{"analyse", "summary", "report", "dashboard"} {
		fmt.Fprintf(buf, "  %s: %s\n", cmd, preservedFailOnFor(opts, cmd))
	}
	fmt.Fprintln(buf)

	fmt.Fprintln(buf, "# The display floor: the lowest severity a report shows. It never changes an")
	fmt.Fprintln(buf, "# exit code, a score, or a baseline; failOn above is what gates a build.")
	fmt.Fprintf(buf, "minimumSeverity: %s\n\n", preservedMinimumSeverity(opts))
}

// preservedFailOnFor returns the existing config's failOn entry for cmd when it carries one, otherwise the binary default.
//
// A present but blank entry also falls back to the default, since a blank value would fail ParseFailThreshold at load time.
// opts supplies that existing config; a nil Existing always gives the default for cmd.
func preservedFailOnFor(opts RenderOptions, cmd string) string {
	if opts.Existing != nil {
		if value, ok := opts.Existing.FailOn[cmd]; ok && value != "" {
			return value
		}
	}
	return string(finding.DefaultFailThresholdFor(cmd))
}

// preservedMinimumSeverity returns the existing display floor, defaulting to the lowest severity.
//
// The default means a regenerated configuration hides nothing the user had not already asked to hide.
// It reads the value from the Existing config in opts; a nil Existing or an empty value gives the advisory severity.
func preservedMinimumSeverity(opts RenderOptions) string {
	if opts.Existing != nil && opts.Existing.MinimumSeverity.Value != "" {
		return opts.Existing.MinimumSeverity.Value
	}
	return string(finding.SeverityAdvisory)
}

// writeRenderHeader writes the file-level banner and schemaVersion pin.
// It writes the comment banner and the quoted SchemaVersion line to buf, each followed by a blank line.
func writeRenderHeader(buf *bytes.Buffer) {
	fmt.Fprintln(buf, "# gruff-go configuration generated by `gruff-go init`.")
	fmt.Fprintln(buf, "# Edit values to tighten or relax the defaults for this project.")
	fmt.Fprintln(buf, "# Run `gruff-go list-rules --format json` for the live rule catalogue.")
	fmt.Fprintln(buf, "# Fresh start for existing findings: `gruff-go analyse --generate-baseline gruff-baseline.json .`.")
	fmt.Fprintln(buf)
	fmt.Fprintf(buf, "schemaVersion: %q\n", SchemaVersion)
	fmt.Fprintln(buf)
}

// writeRenderScaffolds writes to buf the paths, allowlists, sensitiveExclusions and selection sections, in that order.
//
// When opts.Existing is set, its paths.ignore and acceptedAbbreviations replace the defaults of no ignore paths and the seed abbreviations.
// That keeps project-wide allowlists through a regenerate-with-merge; selection lists are always written empty.
// A non-nil Existing in opts is used even when its lists are empty, so a config that cleared acceptedAbbreviations stays cleared.
func writeRenderScaffolds(buf *bytes.Buffer, opts RenderOptions) {
	fmt.Fprintln(buf, "# Discovery reads .gitignore first. paths.ignore is only for committed")
	fmt.Fprintln(buf, "# metadata, fixtures, or generated artifacts that should stay out of scans")
	fmt.Fprintln(buf, "# even when they are not ignored by Git.")
	fmt.Fprintln(buf, "paths:")
	writeRenderStringList(buf, "  ignore", preservedIgnorePaths(opts))
	fmt.Fprintln(buf)

	fmt.Fprintln(buf, "# Project-wide allowlists.")
	fmt.Fprintln(buf, "# acceptedAbbreviations relax naming.acronym-case. Sensitive-data markers are")
	fmt.Fprintln(buf, "# unconditional and carry no payload, so nothing configures them.")
	fmt.Fprintln(buf, "allowlists:")
	writeRenderStringList(buf, "  acceptedAbbreviations", preservedAcceptedAbbreviations(opts))
	fmt.Fprintln(buf)

	writeRenderSensitiveExclusionsSection(buf, opts)

	fmt.Fprintln(buf, "# Selection narrows the active rule set. Empty lists keep the default")
	fmt.Fprintln(buf, "# selection (every rule below whose `enabled` is true).")
	fmt.Fprintln(buf, "selection:")
	fmt.Fprintln(buf, "  rules: []")
	fmt.Fprintln(buf, "  excludeRules: []")
	fmt.Fprintln(buf, "  pillars: []")
	fmt.Fprintln(buf, "  excludePillars: []")
	fmt.Fprintln(buf)
}

// writeRenderSensitiveExclusionsSection emits the sensitiveExclusions block with a commented worked example so a user can discover it.
//
// Entries are authored by hand on purpose, as FAMILY-CONTRACT.md section 13a requires.
// No reported marker, preview, or matched value is ever converted into one.
// It writes the commented guidance and example, then the entries preserved in opts, to buf, followed by a blank line.
func writeRenderSensitiveExclusionsSection(buf *bytes.Buffer, opts RenderOptions) {
	fmt.Fprintln(buf, "# Sensitive-data exclusions. Each entry suppresses one sensitive-data rule in")
	fmt.Fprintln(buf, "# one project-relative file and requires a written reason. A symbol narrows the")
	fmt.Fprintln(buf, "# scope further. Message- and value-matching keys are rejected, and entries are")
	fmt.Fprintln(buf, "# written by hand: no reported marker or preview is ever turned into one for you.")
	fmt.Fprintln(buf, "# Every entry is counted in the report's suppressions array, zero matches included.")
	fmt.Fprintln(buf, "#")
	fmt.Fprintln(buf, "# sensitiveExclusions:")
	fmt.Fprintln(buf, "#   - rule: sensitive-data.aws-access-key")
	fmt.Fprintln(buf, "#     path: internal/rule/testdata/aws_sample.env")
	fmt.Fprintln(buf, "#     symbol: Fixtures.AWSSample")
	fmt.Fprintln(buf, "#     reason: Synthetic key used by the loader fixture; not a live credential.")
	writeRenderSensitiveExclusions(buf, preservedSensitiveExclusions(opts))
	fmt.Fprintln(buf)
}

// writeRenderSensitiveExclusions emits the section body, keeping each exclusion the user wrote in the order they wrote it.
//
// A project with no exclusions gets the inline empty list; otherwise each entry becomes one mapping item.
// Each of the entries is written to buf with yamlQuoteIfNeeded quoting, and its symbol key is left out when Symbol is empty.
func writeRenderSensitiveExclusions(buf *bytes.Buffer, entries []SensitiveExclusion) {
	if len(entries) == 0 {
		fmt.Fprintln(buf, "sensitiveExclusions: []")
		return
	}
	fmt.Fprintln(buf, "sensitiveExclusions:")
	for _, entry := range entries {
		fmt.Fprintf(buf, "  - rule: %s\n", yamlQuoteIfNeeded(entry.Rule))
		fmt.Fprintf(buf, "    path: %s\n", yamlQuoteIfNeeded(entry.Path))
		if entry.Symbol != "" {
			fmt.Fprintf(buf, "    symbol: %s\n", yamlQuoteIfNeeded(entry.Symbol))
		}
		fmt.Fprintf(buf, "    reason: %s\n", yamlQuoteIfNeeded(entry.Reason))
	}
}

// preservedSensitiveExclusions returns the existing config's sensitiveExclusions, so gruff-go init --force keeps accepted suppressions.
// It reads them from the Existing config in opts and gives nil when opts carries no Existing config.
func preservedSensitiveExclusions(opts RenderOptions) []SensitiveExclusion {
	if opts.Existing == nil {
		return nil
	}
	return opts.Existing.SensitiveExclusions
}

// preservedIgnorePaths returns the existing config's paths.ignore, canonically folded into IgnorePaths by Normalized.
// It reads IgnorePaths from the Existing config in opts, so nil comes back when opts carries no Existing config.
func preservedIgnorePaths(opts RenderOptions) []string {
	if opts.Existing == nil {
		return nil
	}
	return opts.Existing.IgnorePaths
}

// defaultAcceptedAbbreviations seeds new configs with the cross-port universal-vocabulary list every port shares verbatim.
//
// naming.acronym-case lowercases entries for matching, through lowerStringSet in internal/rule/naming_acronym.go.
// The case of the seed therefore only changes how the rendered .gruff-go.yaml reads.
// Project-specific acronyms should be appended in the user's config.
var defaultAcceptedAbbreviations = []string{
	"age", "app", "db", "fs", "id", "io", "key", "log", "max", "min", "now", "raw", "rx", "tx", "ui", "url",
}

// preservedAcceptedAbbreviations returns the existing config's acceptedAbbreviations, or the seed list for a fresh project.
//
// The seed is defaultAcceptedAbbreviations, which keeps the rendered file aligned with the rs, ts, py and php init defaults.
// The list of a non-nil Existing in opts comes back as is, even when empty, so the seed list applies only when Existing is nil.
func preservedAcceptedAbbreviations(opts RenderOptions) []string {
	if opts.Existing == nil {
		return defaultAcceptedAbbreviations
	}
	return opts.Existing.AcceptedAbbreviations
}

// writeRenderStringList emits a YAML list under indentedName; an empty or nil list renders in the inline empty form so Load parses it back.
// It writes indentedName to buf, then one item per entry of values, indented two spaces deeper and quoted with yamlQuoteIfNeeded.
func writeRenderStringList(buf *bytes.Buffer, indentedName string, values []string) {
	if len(values) == 0 {
		fmt.Fprintf(buf, "%s: []\n", indentedName)
		return
	}
	fmt.Fprintf(buf, "%s:\n", indentedName)
	childIndent := strings.Repeat(" ", indentWidth(indentedName)+2)
	for _, value := range values {
		fmt.Fprintf(buf, "%s- %s\n", childIndent, yamlQuoteIfNeeded(value))
	}
}

// indentWidth returns the leading space count of a `  key`-style string.
// Only space characters at the start of s count, so a tab ends the count, and an empty s gives 0.
func indentWidth(s string) int {
	count := 0
	for _, r := range s {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

// writeRenderRules writes every rule block under the top-level rules map, so each registered rule appears in the user's file.
//
// Sort order is preserved, per-rule overrides from opts.Existing are layered in, and rules without overrides get registry default knobs.
// It writes to buf in the order of definitions, looks up each rule's override in opts by ID, and puts a blank line between blocks.
func writeRenderRules(buf *bytes.Buffer, definitions []rule.Definition, opts RenderOptions) {
	fmt.Fprintln(buf, "rules:")
	for index, definition := range definitions {
		if index > 0 {
			fmt.Fprintln(buf)
		}
		writeRenderRuleBlock(buf, definition, ruleOverrideFor(opts, definition.ID))
	}
}

// ruleOverrideFor returns the existing per-rule override for id, or a zero RuleConfig when none is recorded.
// It reads the Rules map of the Existing config in opts, so a nil Existing or an unknown id both give the zero value.
func ruleOverrideFor(opts RenderOptions, id string) RuleConfig {
	if opts.Existing == nil {
		return RuleConfig{}
	}
	return opts.Existing.Rules[id]
}

// writeRenderRuleBlock writes one rule entry: a description comment, then enabled, severity, threshold or thresholds, and optional options.
//
// Each knob prefers the override value when set and otherwise falls back to the rule's registry default.
// It writes to buf under the ID of definition, leaving out the description comment when its Description is empty.
// An override severity that tryParseSeverity rejects is ignored, so the severity of definition is written instead.
func writeRenderRuleBlock(buf *bytes.Buffer, definition rule.Definition, override RuleConfig) {
	if definition.Description != "" {
		fmt.Fprintf(buf, "  # %s\n", definition.Description)
	}
	fmt.Fprintf(buf, "  %s:\n", definition.ID)

	enabled := definition.DefaultEnabled
	if override.Enabled != nil {
		enabled = *override.Enabled
	}
	fmt.Fprintf(buf, "    enabled: %t\n", enabled)

	severity := definition.Severity
	if override.Severity != "" {
		if parsed, ok := tryParseSeverity(override.Severity); ok {
			severity = parsed
		}
	}
	fmt.Fprintf(buf, "    severity: %s\n", renderSeverityAlias(severity))

	writeRenderThresholdsWithOverride(buf, definition.Thresholds, override)
	writeRenderOptionsBlock(buf, override.Options)
}

// writeRenderThresholdsWithOverride emits the threshold section from override when it sets any value, and from the rule's defaults otherwise.
// It writes to buf with writeRenderOverrideThresholds when override sets any threshold, and with writeRenderThresholds otherwise.
func writeRenderThresholdsWithOverride(buf *bytes.Buffer, defaults map[string]float64, override RuleConfig) {
	if override.Threshold != nil || len(override.Thresholds) > 0 {
		writeRenderOverrideThresholds(buf, defaults, override)
		return
	}
	writeRenderThresholds(buf, defaults)
}

// writeRenderOverrideThresholds emits threshold values from an override kept from the existing config.
//
// A rule with at most one default knob whose override sets only the singular Threshold keeps the singular threshold key.
// Otherwise override.Thresholds is merged over defaults and written to buf through writeRenderThresholds.
// A set Threshold replaces the sole value of a one-knob merge and is not written when the merge holds two or more knobs.
func writeRenderOverrideThresholds(buf *bytes.Buffer, defaults map[string]float64, override RuleConfig) {
	if len(defaults) <= 1 && len(override.Thresholds) == 0 && override.Threshold != nil {
		fmt.Fprintf(buf, "    threshold: %s\n", renderThresholdValue(*override.Threshold))
		return
	}
	merged := map[string]float64{}
	for name, value := range defaults {
		merged[name] = value
	}
	for name, value := range override.Thresholds {
		merged[name] = value
	}
	if override.Threshold != nil && len(merged) == 1 {
		for name := range merged {
			merged[name] = *override.Threshold
		}
	}
	writeRenderThresholds(buf, merged)
}

// writeRenderOptionsBlock writes a YAML options block for the override map, covering bool, string, integer, float and string-list values.
//
// A map-valued option such as naming.misspelling.extra falls to Go text in writeRenderOptionEntry and loses its mapping shape.
// It writes nothing to buf when options is empty, and otherwise each entry of options in sorted key order through writeRenderOptionEntry.
func writeRenderOptionsBlock(buf *bytes.Buffer, options map[string]any) {
	if len(options) == 0 {
		return
	}
	keys := make([]string, 0, len(options))
	for key := range options {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Fprintln(buf, "    options:")
	for _, key := range keys {
		writeRenderOptionEntry(buf, key, options[key])
	}
}

// writeRenderOptionEntry renders one option key and value under the options key of a rule block.
//
// Unsupported value types fall through to their fmt.Sprint form, so the entry is always emitted rather than silently dropped.
// Load may reject that text form or read it back as a different value.
// It writes key and value to buf at options depth; a slice of any becomes a string list of each item's fmt.Sprint form.
func writeRenderOptionEntry(buf *bytes.Buffer, key string, value any) {
	switch typed := value.(type) {
	case bool:
		fmt.Fprintf(buf, "      %s: %t\n", key, typed)
	case string:
		fmt.Fprintf(buf, "      %s: %s\n", key, yamlQuoteIfNeeded(typed))
	case int:
		fmt.Fprintf(buf, "      %s: %d\n", key, typed)
	case int64:
		fmt.Fprintf(buf, "      %s: %d\n", key, typed)
	case float64:
		fmt.Fprintf(buf, "      %s: %s\n", key, renderThresholdValue(typed))
	case []string:
		writeRenderStringList(buf, "      "+key, typed)
	case []any:
		listItems := make([]string, 0, len(typed))
		for _, item := range typed {
			listItems = append(listItems, fmt.Sprint(item))
		}
		writeRenderStringList(buf, "      "+key, listItems)
	default:
		fmt.Fprintf(buf, "      %s: %v\n", key, typed)
	}
}

// writeRenderThresholds picks the singular threshold key when a rule has exactly one knob and the plural thresholds map otherwise.
//
// Rules with no thresholds emit nothing in this section.
// It writes to buf in sorted key order, formatting each value with renderThresholdValue.
func writeRenderThresholds(buf *bytes.Buffer, thresholds map[string]float64) {
	if len(thresholds) == 0 {
		return
	}
	keys := make([]string, 0, len(thresholds))
	for name := range thresholds {
		keys = append(keys, name)
	}
	slices.Sort(keys)
	if len(keys) == 1 {
		fmt.Fprintf(buf, "    threshold: %s\n", renderThresholdValue(thresholds[keys[0]]))
		return
	}
	fmt.Fprintln(buf, "    thresholds:")
	for _, key := range keys {
		fmt.Fprintf(buf, "      %s: %s\n", key, renderThresholdValue(thresholds[key]))
	}
}

// renderSeverityAlias emits the canonical three-bucket severity name for the rendered config file.
//
// After ADR-009 the rendered name equals the Severity value verbatim; the helper stays so a future output alias changes one place.
// It pairs with parseConfigSeverity, which also uses finding.ParseSeverity, so emitted severity names keep their meaning when read back.
// It returns the string form of severity unchanged, so an empty severity gives an empty string.
func renderSeverityAlias(severity finding.Severity) string {
	return string(severity)
}

// tryParseSeverity converts a config-level severity string back into a finding.Severity when honouring a preserved override in init --force.
//
// It returns false as its second result when the input does not name a known level, so the caller writes the registry severity instead.
// value is trimmed of surrounding space and lowercased before finding.ParseSeverity reads it; a rejected value yields an empty Severity.
func tryParseSeverity(value string) (finding.Severity, bool) {
	severity, err := finding.ParseSeverity(strings.ToLower(strings.TrimSpace(value)))
	if err != nil {
		return "", false
	}
	return severity, true
}

// renderThresholdValue prints whole numbers as integers, so the file reads threshold: 80 rather than 80.0, matching the dogfood config.
// It returns value as integer text when it is whole, and otherwise as six-decimal text with trailing zeros trimmed, rounding finer digits away.
func renderThresholdValue(value float64) string {
	if value == float64(int64(value)) {
		return fmt.Sprintf("%d", int64(value))
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", value), "0"), ".")
}

// yamlQuoteIfNeeded quotes an empty string and a string holding selected YAML punctuation or leading or trailing whitespace.
//
// Other words stay bare, including a word such as true that Load reads back as a boolean rather than a string.
// It returns value in single quotes, each inner single quote doubled, when quoting is needed, and value unchanged otherwise.
// An empty value gives two single quotes, the YAML empty string.
func yamlQuoteIfNeeded(value string) string {
	if value == "" {
		return "''"
	}
	if strings.ContainsAny(value, "*?[]{}:#&!|>'\",%@`") || strings.TrimSpace(value) != value {
		escaped := strings.ReplaceAll(value, "'", "''")
		return "'" + escaped + "'"
	}
	return value
}
