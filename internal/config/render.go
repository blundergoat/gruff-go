// Package config emits a default .gruff-go.yaml from the registry catalogue.
// Render walks the supplied rule definitions and writes the canonical YAML shape
// that Load can round-trip, so `gruff-go init` and the interactive bootstrap
// produce a file that already expresses the registry's effective defaults.
//
// When RenderOptions.Existing is set, Render layers the project-specific values
// from the previously-loaded config onto the new template: `paths.ignore`,
// `allowlists.acceptedAbbreviations`,
// `sensitiveExclusions`, and any
// per-rule `enabled`/`severity`/`threshold`/`thresholds`/`options` overrides
// for rules that are still in the registry. Rules that no longer exist are
// dropped; rules that are new since the previous config land at registry
// defaults. This makes `gruff-go init --force` a safe regenerate-with-merge
// rather than a destructive clobber.
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

// RenderOptions controls how Render layers project-specific overrides onto the
// default template. A zero-value RenderOptions reproduces the original
// fresh-from-defaults output.
type RenderOptions struct {
	// Existing carries previously-tuned config to splice into the new file.
	// When nil, scaffolds emit empty lists and rule blocks use registry defaults.
	Existing *Config
}

// Render returns a default .gruff-go.yaml body that mirrors the registry's
// per-rule enablement, severity, and threshold defaults. The output is sorted
// by rule ID and parses back through Load without modification. When opts.Existing
// is non-nil its scaffolds and per-rule overrides are layered into the output.
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
func writeRenderDeepScanBudget(buf *bytes.Buffer, opts RenderOptions) {
	enabled := true
	maxLines := DefaultDeepScanMaxLines
	maxBytes := DefaultDeepScanMaxBytes
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

// writeRenderMinimumSeverity emits the two severity keys the family contract separates: the exit gate under failOn
// and the display floor under minimumSeverity. Gate values come from finding.DefaultFailThresholdFor unless the
// existing config already tuned a key, in which case the user's value is preserved verbatim - regenerate-with-merge,
// never a destructive clobber.
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

// preservedFailOnFor returns the existing config's failOn entry for cmd when it
// carries one, otherwise the binary default. The empty string case (entry
// present but blank) also falls back to the default since a blank value would
// fail ParseFailThreshold at load time.
func preservedFailOnFor(opts RenderOptions, cmd string) string {
	if opts.Existing != nil {
		if value, ok := opts.Existing.FailOn[cmd]; ok && value != "" {
			return value
		}
	}
	return string(finding.DefaultFailThresholdFor(cmd))
}

// preservedMinimumSeverity returns the existing display floor, defaulting to the
// lowest severity so a regenerated configuration hides nothing the user had not
// already asked to hide.
func preservedMinimumSeverity(opts RenderOptions) string {
	if opts.Existing != nil && opts.Existing.MinimumSeverity.Value != "" {
		return opts.Existing.MinimumSeverity.Value
	}
	return string(finding.SeverityAdvisory)
}

// writeRenderHeader writes the file-level banner and schemaVersion pin.
func writeRenderHeader(buf *bytes.Buffer) {
	fmt.Fprintln(buf, "# gruff-go configuration generated by `gruff-go init`.")
	fmt.Fprintln(buf, "# Edit values to tighten or relax the defaults for this project.")
	fmt.Fprintln(buf, "# Run `gruff-go list-rules --format json` for the live rule catalogue.")
	fmt.Fprintln(buf, "# Fresh start for existing findings: `gruff-go analyse --generate-baseline gruff-baseline.json .`.")
	fmt.Fprintln(buf)
	fmt.Fprintf(buf, "schemaVersion: %q\n", SchemaVersion)
	fmt.Fprintln(buf)
}

// writeRenderScaffolds writes the paths/allowlists/selection sections. When
// opts.Existing supplies values for paths.ignore or acceptedAbbreviations, those
// lists are emitted in place of the empty defaults so regenerate-with-merge
// preserves project-wide allowlists.
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

// writeRenderSensitiveExclusionsSection emits the sensitiveExclusions block with
// the commented worked example a user needs to discover the section. Entries are
// authored by hand on purpose: no reported marker, preview, or matched value is
// ever converted into one (FAMILY-CONTRACT.md section 13a).
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

// writeRenderSensitiveExclusions emits the section body: the inline empty list
// for a project with no exclusions, otherwise one mapping item per preserved
// entry in the order the user wrote them.
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

// preservedSensitiveExclusions returns the existing config's sensitiveExclusions
// so `gruff-go init --force` regenerates without dropping accepted suppressions.
func preservedSensitiveExclusions(opts RenderOptions) []SensitiveExclusion {
	if opts.Existing == nil {
		return nil
	}
	return opts.Existing.SensitiveExclusions
}

// preservedIgnorePaths returns the existing config's paths.ignore (canonically
// folded into IgnorePaths by Normalized) or nil when nothing is preserved.
func preservedIgnorePaths(opts RenderOptions) []string {
	if opts.Existing == nil {
		return nil
	}
	return opts.Existing.IgnorePaths
}

// defaultAcceptedAbbreviations seeds new configs with the cross-port
// universal-vocabulary list shared verbatim with gruff-rs / gruff-ts /
// gruff-py / gruff-php. naming.acronym-case lowercases entries for matching
// (see internal/rule/naming_acronym.go `lowerStringSet`), so the case of
// the seed only matters for how the rendered .gruff-go.yaml reads.
// Project-specific acronyms should be appended in the user's config.
var defaultAcceptedAbbreviations = []string{
	"age", "app", "db", "fs", "id", "io", "key", "log", "max", "min", "now", "raw", "rx", "tx", "ui", "url",
}

// preservedAcceptedAbbreviations returns the existing config's
// allowlists.acceptedAbbreviations when one was preserved, falling back to
// defaultAcceptedAbbreviations for fresh projects. Returning the seed list
// keeps the rendered file aligned with the rs/ts/py/php init defaults.
func preservedAcceptedAbbreviations(opts RenderOptions) []string {
	if opts.Existing == nil {
		return defaultAcceptedAbbreviations
	}
	return opts.Existing.AcceptedAbbreviations
}

// writeRenderStringList emits a YAML list under indent+name. Empty or nil lists
// render as the inline `[]` form so the round-trip parses cleanly.
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

// writeRenderRules writes every rule block under the top-level `rules:` map,
// preserving sort order, layering any per-rule overrides from opts.Existing,
// and emitting the registry's default knobs for rules without overrides.
func writeRenderRules(buf *bytes.Buffer, definitions []rule.Definition, opts RenderOptions) {
	fmt.Fprintln(buf, "rules:")
	for index, definition := range definitions {
		if index > 0 {
			fmt.Fprintln(buf)
		}
		writeRenderRuleBlock(buf, definition, ruleOverrideFor(opts, definition.ID))
	}
}

// ruleOverrideFor returns the existing per-rule override for id, or a zero
// RuleConfig when none is recorded.
func ruleOverrideFor(opts RenderOptions, id string) RuleConfig {
	if opts.Existing == nil {
		return RuleConfig{}
	}
	return opts.Existing.Rules[id]
}

// writeRenderRuleBlock writes one rule entry: a description comment followed
// by enabled, severity, threshold/thresholds, and an optional options block.
// Each knob prefers the override value when set; otherwise it falls back to
// the rule's registry default.
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

// writeRenderThresholdsWithOverride emits the threshold/thresholds section,
// preferring override values when present and otherwise falling back to the
// registry defaults the rule advertises.
func writeRenderThresholdsWithOverride(buf *bytes.Buffer, defaults map[string]float64, override RuleConfig) {
	if override.Threshold != nil || len(override.Thresholds) > 0 {
		writeRenderOverrideThresholds(buf, defaults, override)
		return
	}
	writeRenderThresholds(buf, defaults)
}

// writeRenderOverrideThresholds emits threshold values from an override. When
// the rule advertises exactly one default knob and the override only sets the
// singular Threshold, the rendered form stays as `threshold:`. When the rule
// advertises multiple knobs, the override's named Thresholds map (or a
// fallback singleton) is rendered under `thresholds:`.
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

// writeRenderOptionsBlock writes a YAML `options:` block for the override map.
// Supports bool, string, integer, float, and string-list values, which covers
// every option shape the shipped rules use today.
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

// writeRenderOptionEntry renders one option key/value pair under `    options:`.
// Unsupported value types fall through to a fmt.Sprint string form so the call
// always emits something rather than silently dropping the entry; Load will
// surface any resulting parse error during the round-trip.
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
		strs := make([]string, 0, len(typed))
		for _, item := range typed {
			strs = append(strs, fmt.Sprint(item))
		}
		writeRenderStringList(buf, "      "+key, strs)
	default:
		fmt.Fprintf(buf, "      %s: %v\n", key, typed)
	}
}

// writeRenderThresholds picks the singular `threshold:` form when a rule has
// exactly one knob and the plural `thresholds:` map otherwise. Rules with no
// thresholds emit nothing in this section.
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

// renderSeverityAlias emits the canonical 3-bucket severity name for the
// rendered config file. After ADR-009 the rendered name equals the internal
// Severity value verbatim; this helper is kept as a single indirection point
// so a future ADR that reintroduces output aliasing only has to change one
// place. Paired with parseConfigSeverity (which still goes through
// finding.ParseSeverity) so round-tripping a rendered file stays a no-op.
func renderSeverityAlias(severity finding.Severity) string {
	return string(severity)
}

// tryParseSeverity converts a config-level severity string back into a
// finding.Severity, returning ok=false when the input does not name a known
// level. Used when honouring a preserved override during `init --force`.
func tryParseSeverity(value string) (finding.Severity, bool) {
	severity, err := finding.ParseSeverity(strings.ToLower(strings.TrimSpace(value)))
	if err != nil {
		return "", false
	}
	return severity, true
}

// renderThresholdValue prints whole numbers without the float suffix so the
// rendered file matches the hand-written dogfood config style (`threshold: 80`,
// not `threshold: 80.0`).
func renderThresholdValue(value float64) string {
	if value == float64(int64(value)) {
		return fmt.Sprintf("%d", int64(value))
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", value), "0"), ".")
}

// yamlQuoteIfNeeded wraps a string in single quotes when it contains glob
// characters, leading/trailing whitespace, or other tokens that the YAML
// parser would otherwise interpret. Plain identifiers are left bare.
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
