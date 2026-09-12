// Package report renders gruff-go analysis results into output formats.
// Machine-readable reporters keep their payloads stable for CI systems, SARIF consumers, and automation.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// WriteSummaryJSON writes the scan-level JSON contract without the heavier per-finding payload.
func WriteSummaryJSON(writer io.Writer, report analysis.Report) error {
	payload, err := report.MachineSummary()
	if err != nil {
		return err
	}
	return WriteJSON(writer, payload)
}

// WriteSARIF writes the report as a SARIF 2.1.0 log including rule definitions, results, and run properties.
func WriteSARIF(writer io.Writer, report analysis.Report) error {
	payload := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:            report.Tool.Name,
				SemanticVersion: report.Tool.Version,
				Rules:           sarifRules(report.Rules),
			}},
			Invocations: sarifInvocations(report.Diagnostics),
			Results:     sarifResults(report.Findings, report.Rules, report.Baseline.Applied),
			Properties:  sarifRunPropertiesFromReport(report),
		}},
	}
	return WriteJSON(writer, payload)
}

// WriteGitHub writes each finding as a GitHub workflow annotation command on its own line.
func WriteGitHub(writer io.Writer, report analysis.Report) error {
	for _, diagnostic := range report.Diagnostics {
		level := "error"
		if diagnostic.InvalidatesRun != nil && !*diagnostic.InvalidatesRun {
			level = "notice"
		}
		location := ""
		if diagnostic.File != "" {
			line := 1
			if diagnostic.Location != nil && diagnostic.Location.Line > 0 {
				line = diagnostic.Location.Line
			}
			location = fmt.Sprintf("file=%s,line=%d,", escapeGitHubProperty(diagnostic.File), line)
		}
		if _, err := fmt.Fprintf(writer, "::%s %stitle=%s::%s\n", level, location, escapeGitHubProperty(diagnosticLabel(diagnostic)), escapeGitHubMessage(diagnostic.Message)); err != nil {
			return err
		}
	}
	for _, item := range report.Findings {
		level := githubLevel(item.Severity)
		location := githubLocation(item)
		title := escapeGitHubProperty(item.RuleID)
		message := escapeGitHubMessage(item.Message)
		if _, err := fmt.Fprintf(writer, "::%s %stitle=%s::%s\n", level, location, title, message); err != nil {
			return err
		}
	}
	return nil
}

// sarifLog is the top-level SARIF document envelope.
type sarifLog struct {
	// Version is the SARIF specification version string (e.g. "2.1.0").
	Version string `json:"version"`
	// Schema is the URI of the SARIF JSON schema the document conforms to.
	Schema string `json:"$schema"`
	// Runs lists each analyser run contained in the log.
	Runs []sarifRun `json:"runs"`
}

// sarifRun captures a single analyser run within the SARIF log.
type sarifRun struct {
	// Tool describes the analyser tool that produced the run.
	Tool sarifTool `json:"tool"`
	// Invocations carries runtime diagnostics that are not rule findings.
	Invocations []sarifInvocation `json:"invocations,omitempty"`
	// Results is the list of per-finding SARIF results emitted by the run.
	Results []sarifResult `json:"results"`
	// Properties carries gruff-specific run-level metadata.
	Properties sarifRunProperties `json:"properties"`
}

// sarifInvocation records runtime notifications and whether fatal diagnostics occurred.
type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications"`
}

// sarifNotification is one diagnostic emitted during the tool invocation.
type sarifNotification struct {
	Descriptor map[string]string `json:"descriptor"`
	Level      string            `json:"level"`
	Message    sarifText         `json:"message"`
	Locations  []sarifLocation   `json:"locations,omitempty"`
	Properties map[string]any    `json:"properties"`
}

// diagnosticLabel prefers the stable type while retaining legacy stage labels.
func diagnosticLabel(diagnostic analysis.Diagnostic) string {
	if diagnostic.DiagnosticType != "" {
		return diagnostic.DiagnosticType
	}
	return diagnostic.Stage
}

// hasInvalidatingDiagnostic reports whether any diagnostic retains legacy fatal semantics.
func hasInvalidatingDiagnostic(diagnostics []analysis.Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.InvalidatesRun == nil || *diagnostic.InvalidatesRun {
			return true
		}
	}
	return false
}

// sarifInvocations keeps ordinary diagnostic-free SARIF byte-stable while surfacing runtime notes.
func sarifInvocations(diagnostics []analysis.Diagnostic) []sarifInvocation {
	if len(diagnostics) == 0 {
		return nil
	}
	return []sarifInvocation{{
		ExecutionSuccessful:        !hasInvalidatingDiagnostic(diagnostics),
		ToolExecutionNotifications: sarifDiagnostics(diagnostics),
	}}
}

// sarifDiagnostics projects runtime diagnostics into invocation notifications.
func sarifDiagnostics(diagnostics []analysis.Diagnostic) []sarifNotification {
	out := make([]sarifNotification, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		level := "error"
		invalidatesRun := true
		if diagnostic.InvalidatesRun != nil && !*diagnostic.InvalidatesRun {
			level = "note"
			invalidatesRun = false
		}
		notification := sarifNotification{
			Descriptor: map[string]string{"id": diagnosticLabel(diagnostic)},
			Level:      level,
			Message:    sarifText{Text: diagnostic.Message},
			Properties: map[string]any{"invalidatesRun": invalidatesRun},
		}
		if diagnostic.File != "" {
			var region *sarifRegion
			if diagnostic.Location != nil && diagnostic.Location.Line > 0 {
				region = &sarifRegion{StartLine: diagnostic.Location.Line, StartColumn: diagnostic.Location.Column}
			}
			notification.Locations = []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: sarifURI(diagnostic.File)}, Region: region}}}
		}
		out = append(out, notification)
	}
	return out
}

// sarifTool describes the analyser tool block in a SARIF run.
type sarifTool struct {
	// Driver names the underlying analyser implementation and rule set.
	Driver sarifDriver `json:"driver"`
}

// sarifDriver names the analyser tool and lists the rules it can emit.
type sarifDriver struct {
	// Name is the analyser product name (gruff-go).
	Name string `json:"name"`
	// SemanticVersion is the analyser semantic version, omitted when empty.
	SemanticVersion string `json:"semanticVersion,omitempty"`
	// Rules is the catalogue of rules the analyser can emit findings for.
	Rules []sarifRule `json:"rules"`
}

// sarifRule mirrors the SARIF reportingDescriptor object for a single rule.
type sarifRule struct {
	// ID is the rule identifier referenced by results.
	ID string `json:"id"`
	// Name is the human-readable rule title.
	Name string `json:"name"`
	// ShortDescription is the brief rule summary string.
	ShortDescription sarifText `json:"shortDescription"`
	// FullDescription is the long-form rule description.
	FullDescription sarifText `json:"fullDescription"`
	// Help is the remediation guidance for the rule.
	Help sarifText `json:"help"`
	// Properties carries gruff-specific rule metadata.
	Properties sarifRuleProperty `json:"properties"`
	// DefaultConfiguration is the rule's default SARIF level configuration.
	DefaultConfiguration sarifDefaultConfiguration `json:"defaultConfiguration"`
}

// sarifDefaultConfiguration mirrors the SARIF defaultConfiguration object on a rule.
type sarifDefaultConfiguration struct {
	// Level is the SARIF severity level ("note", "warning", or "error").
	Level string `json:"level"`
}

// sarifRuleProperty carries the gruff-specific rule metadata under SARIF properties.
type sarifRuleProperty struct {
	// Pillar is the primary quality category the rule belongs to.
	Pillar finding.Pillar `json:"pillar"`
	// SecondaryPillars lists any additional quality categories the rule touches.
	SecondaryPillars []finding.Pillar `json:"secondaryPillars,omitempty"`
	// DefaultSeverity is the rule's default gruff severity.
	DefaultSeverity finding.Severity `json:"defaultSeverity"`
	// Confidence is the rule's reported certainty tier.
	Confidence finding.Confidence `json:"confidence"`
	// Capability tags the rule's analysis capability (parser-only, semantic, etc.).
	Capability rule.Capability `json:"capability"`
	// DefaultEnabled reports whether the rule fires under the default policy.
	DefaultEnabled bool `json:"defaultEnabled"`
	// Tags lists the rule's free-form classification tags.
	Tags []string `json:"tags,omitempty"`
	// Thresholds exposes the rule's configurable numeric thresholds.
	Thresholds map[string]float64 `json:"thresholds,omitempty"`
	// Options exposes any additional rule-specific configuration values.
	Options map[string]any `json:"options,omitempty"`
}

// sarifText is the SARIF multi-format string container used for messages and descriptions.
type sarifText struct {
	// Text is the plain-text message body.
	Text string `json:"text"`
}

// sarifResult mirrors a single SARIF result entry corresponding to one finding.
type sarifResult struct {
	// RuleID identifies the rule that produced the result.
	RuleID string `json:"ruleId"`
	// RuleIndex is the zero-based index into the driver Rules list, omitted when unknown.
	RuleIndex *int `json:"ruleIndex,omitempty"`
	// Level is the SARIF severity level for the result.
	Level string `json:"level"`
	// Message is the rule's human-readable finding message.
	Message sarifText `json:"message"`
	// Locations lists the source spans the result is anchored to.
	Locations []sarifLocation `json:"locations"`
	// PartialFingerprints carries identity hashes used to deduplicate the result.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	// Properties carries gruff-specific finding metadata.
	Properties map[string]any `json:"properties"`
	// BaselineState is the SARIF 2.1.0 baselineState ("new") set only when a
	// baseline was applied; omitted otherwise so non-baseline runs are unchanged.
	BaselineState string `json:"baselineState,omitempty"`
}

// sarifRunProperties carries gruff-go metadata at the SARIF run level.
type sarifRunProperties struct {
	// GruffSchemaVersion echoes the gruff-go report schema version.
	GruffSchemaVersion string `json:"gruffSchemaVersion"`
	// Score is the composite quality score for the run, null when nothing was evaluated.
	Score *float64 `json:"score"`
	// Grade is the letter grade derived from Score, null whenever Score is.
	Grade *string `json:"grade"`
}

// sarifLocation wraps a physical location reference for a SARIF result.
type sarifLocation struct {
	// PhysicalLocation describes the file and span the result points at.
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

// sarifPhysicalLocation captures the file artefact and optional region of a SARIF location.
type sarifPhysicalLocation struct {
	// ArtifactLocation references the source file URI.
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	// Region narrows the location to a span; nil when the result targets the whole file.
	Region *sarifRegion `json:"region,omitempty"`
}

// sarifArtifactLocation references the source artefact for a SARIF location.
type sarifArtifactLocation struct {
	// URI is the slash-normalised path of the referenced source file.
	URI string `json:"uri"`
}

// sarifRegion describes the line and column span associated with a SARIF result.
type sarifRegion struct {
	// StartLine is the 1-based start line of the span; zero when unknown.
	StartLine int `json:"startLine,omitempty"`
	// StartColumn is the 1-based start column within StartLine; zero when unknown.
	StartColumn int `json:"startColumn,omitempty"`
	// EndLine is the inclusive 1-based end line of the span; zero for single-line spans.
	EndLine int `json:"endLine,omitempty"`
}

// sarifRules converts gruff rule definitions into SARIF reportingDescriptor entries.
func sarifRules(definitions []rule.Definition) []sarifRule {
	out := make([]sarifRule, 0, len(definitions))
	for _, definition := range definitions {
		out = append(out, sarifRule{
			ID:               definition.ID,
			Name:             definition.Title,
			ShortDescription: sarifText{Text: definition.Title},
			FullDescription:  sarifText{Text: definition.Description},
			Help:             sarifText{Text: definition.Remediation},
			DefaultConfiguration: sarifDefaultConfiguration{
				Level: sarifLevel(definition.Severity),
			},
			Properties: sarifRuleProperty{
				Pillar:           definition.Pillar,
				SecondaryPillars: definition.SecondaryPillars,
				DefaultSeverity:  definition.Severity,
				Confidence:       definition.Confidence,
				Capability:       definition.Capability,
				DefaultEnabled:   definition.DefaultEnabled,
				Tags:             definition.Tags,
				Thresholds:       definition.Thresholds,
				Options:          definition.Options,
			},
		})
	}
	return out
}

// sarifPartialFingerprints projects one finding into the fingerprints GitHub code scanning groups alerts by.
//
// gruffFingerprint is the ratified durable identity and nothing else, so an alert survives a line move and a
// second declaration of one name opens its own alert. A sensitive finding has no identity at all and therefore
// contributes no fingerprints: publishing one would give a secret a stable name in a system gruff does not control.
func sarifPartialFingerprints(findingItem finding.Finding) map[string]string {
	identity, err := findingItem.ComputeBaselineIdentity()
	if err != nil {
		// A finding that cannot be named durably is published without a fingerprint rather than with a guessed one.
		return nil
	}
	return map[string]string{"gruffFingerprint": identity}
}

// sarifResults converts findings into SARIF results, indexing each entry into the driver rule list.
// When baselineApplied is true, a result the baseline classified as new carries baselineState "new";
// a collision or a sensitive finding does not, because neither was freshly introduced.
func sarifResults(findings []finding.Finding, definitions []rule.Definition, baselineApplied bool) []sarifResult {
	ruleIndices := map[string]int{}
	for index, definition := range definitions {
		ruleIndices[definition.ID] = index
	}
	// A direct API caller can hand over findings the analysis pipeline never ranked; ranking them here by
	// line keeps every ordinary result fingerprinted rather than silently publishing one without a name.
	findings = finding.EnsureSymbolOrdinals(findings)
	results := make([]sarifResult, 0, len(findings))
	for _, findingItem := range findings {
		results = append(results, sarifResultFor(findingItem, ruleIndices, baselineApplied))
	}
	return results
}

// sarifResultFor projects one finding into the SARIF result a code-scanning reader sees.
func sarifResultFor(findingItem finding.Finding, ruleIndices map[string]int, baselineApplied bool) sarifResult {
	result := sarifResult{
		RuleID:  findingItem.RuleID,
		Level:   sarifLevel(findingItem.Severity),
		Message: sarifText{Text: findingItem.Message},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: sarifURI(findingItem.File)},
				Region:           sarifRegionFromFinding(findingItem),
			},
		}},
		PartialFingerprints: sarifPartialFingerprints(findingItem),
		Properties:          sarifResultProperties(findingItem),
	}
	if ruleIndex, ok := ruleIndices[findingItem.RuleID]; ok {
		result.RuleIndex = &ruleIndex
	}
	// Only a finding the baseline classified as new is new relative to it. A collision and a sensitive
	// finding are permanently unsuppressable rather than freshly introduced, so neither carries the state;
	// a reader would otherwise see a long-standing secret as though it had just appeared. SARIF 2.1.0 §3.27.25.
	if baselineApplied && findingItem.BaselineStatus == "new" {
		result.BaselineState = "new"
	}
	return result
}

// sarifResultProperties carries the gruff-owned fields a reader needs beside the SARIF-standard ones.
func sarifResultProperties(findingItem finding.Finding) map[string]any {
	properties := map[string]any{
		"confidence":  findingItem.Confidence,
		"fingerprint": findingItem.Fingerprint,
		"pillar":      findingItem.Pillar,
		"severity":    findingItem.Severity,
	}
	if len(findingItem.SecondaryPillars) > 0 {
		properties["secondaryPillars"] = findingItem.SecondaryPillars
	}
	if findingItem.Symbol != "" {
		properties["symbol"] = findingItem.Symbol
	}
	if findingItem.Remediation != "" {
		properties["remediation"] = findingItem.Remediation
	}
	if len(findingItem.Metadata) > 0 {
		properties["metadata"] = findingItem.Metadata
	}
	return properties
}

// sarifRegionFromFinding produces a SARIF region from a finding location, or nil when the line is unknown.
func sarifRegionFromFinding(item finding.Finding) *sarifRegion {
	if item.Location == nil || item.Location.Line == 0 {
		return nil
	}
	region := sarifRegion{
		StartLine:   item.Location.Line,
		StartColumn: item.Location.Column,
		EndLine:     item.Location.EndLine,
	}
	return &region
}

// sarifURI normalises a report file path into a forward-slash, dot-stripped SARIF URI.
func sarifURI(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	for strings.HasPrefix(path, "./") {
		path = strings.TrimPrefix(path, "./")
	}
	return path
}

// sarifRunPropertiesFromReport copies gruff schema, score, and grade into SARIF run properties.
func sarifRunPropertiesFromReport(report analysis.Report) sarifRunProperties {
	return sarifRunProperties{
		GruffSchemaVersion: report.SchemaVersion,
		Score:              report.Score.Composite,
		Grade:              report.Score.Grade,
	}
}

// sarifLevel maps a gruff severity onto the matching SARIF level string.
func sarifLevel(severity finding.Severity) string {
	switch severity {
	case finding.SeverityError:
		return "error"
	case finding.SeverityWarning:
		return "warning"
	default:
		return "note"
	}
}

// githubLevel maps a gruff severity onto the corresponding GitHub annotation level.
func githubLevel(severity finding.Severity) string {
	switch severity {
	case finding.SeverityError:
		return "error"
	case finding.SeverityWarning:
		return "warning"
	default:
		return "notice"
	}
}

// githubLocation builds the comma-separated location parameters for a GitHub annotation command.
func githubLocation(item finding.Finding) string {
	parts := []string{"file=" + escapeGitHubProperty(item.File)}
	if item.Location != nil && item.Location.Line > 0 {
		parts = append(parts, fmt.Sprintf("line=%d", item.Location.Line))
		if item.Location.EndLine > item.Location.Line {
			parts = append(parts, fmt.Sprintf("endLine=%d", item.Location.EndLine))
		}
		if item.Location.Column > 0 {
			parts = append(parts, fmt.Sprintf("col=%d", item.Location.Column))
		}
	}
	return strings.Join(parts, ",") + ","
}

// escapeGitHubMessage percent-encodes characters that break GitHub workflow command parsing.
func escapeGitHubMessage(value string) string {
	value = strings.ReplaceAll(value, "%", "%25")
	value = strings.ReplaceAll(value, "\r", "%0D")
	value = strings.ReplaceAll(value, "\n", "%0A")
	return value
}

// escapeGitHubProperty extends escapeGitHubMessage with separator escapes for annotation property values.
func escapeGitHubProperty(value string) string {
	value = escapeGitHubMessage(value)
	value = strings.ReplaceAll(value, ":", "%3A")
	value = strings.ReplaceAll(value, ",", "%2C")
	return value
}
