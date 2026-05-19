// Package report renders gruff-go analysis results into output formats.
// This file holds the machine-readable reporters: summary JSON, SARIF, and GitHub annotations.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// WriteSummaryJSON writes a compact JSON envelope containing scoring and metadata but no per-finding rows.
func WriteSummaryJSON(writer io.Writer, report analysis.Report) error {
	payload := struct {
		SchemaVersion string                        `json:"schemaVersion"`
		Tool          analysis.Tool                 `json:"tool"`
		Run           analysis.RunMetadata          `json:"run"`
		Summary       analysis.Summary              `json:"summary"`
		Baseline      analysis.BaselineSummary      `json:"baseline"`
		Diff          analysis.DiffSummary          `json:"diff"`
		DisplayFilter analysis.DisplayFilterSummary `json:"displayFilter"`
		Score         any                           `json:"score"`
		Diagnostics   []analysis.Diagnostic         `json:"diagnostics"`
	}{
		SchemaVersion: report.SchemaVersion,
		Tool:          report.Tool,
		Run:           report.Run,
		Summary:       report.Summary,
		Baseline:      report.Baseline,
		Diff:          report.Diff,
		DisplayFilter: report.DisplayFilter,
		Score:         report.Score,
		Diagnostics:   report.Diagnostics,
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
			Results:    sarifResults(report.Findings, report.Rules),
			Properties: sarifRunPropertiesFromReport(report),
		}},
	}
	return WriteJSON(writer, payload)
}

// WriteGitHub writes each finding as a GitHub workflow annotation command on its own line.
func WriteGitHub(writer io.Writer, report analysis.Report) error {
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
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

// sarifRun captures a single analyser run within the SARIF log.
type sarifRun struct {
	Tool       sarifTool          `json:"tool"`
	Results    []sarifResult      `json:"results"`
	Properties sarifRunProperties `json:"properties"`
}

// sarifTool describes the analyser tool block in a SARIF run.
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

// sarifDriver names the analyser tool and lists the rules it can emit.
type sarifDriver struct {
	Name            string      `json:"name"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []sarifRule `json:"rules"`
}

// sarifRule mirrors the SARIF reportingDescriptor object for a single rule.
type sarifRule struct {
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name"`
	ShortDescription     sarifText                 `json:"shortDescription"`
	FullDescription      sarifText                 `json:"fullDescription"`
	Help                 sarifText                 `json:"help"`
	Properties           sarifRuleProperty         `json:"properties"`
	DefaultConfiguration sarifDefaultConfiguration `json:"defaultConfiguration"`
}

// sarifDefaultConfiguration mirrors the SARIF defaultConfiguration object on a rule.
type sarifDefaultConfiguration struct {
	Level string `json:"level"`
}

// sarifRuleProperty carries the gruff-specific rule metadata under SARIF properties.
type sarifRuleProperty struct {
	Pillar           finding.Pillar     `json:"pillar"`
	SecondaryPillars []finding.Pillar   `json:"secondaryPillars,omitempty"`
	DefaultSeverity  finding.Severity   `json:"defaultSeverity"`
	Confidence       finding.Confidence `json:"confidence"`
	Capability       rule.Capability    `json:"capability"`
	DefaultEnabled   bool               `json:"defaultEnabled"`
	Tags             []string           `json:"tags,omitempty"`
	Thresholds       map[string]float64 `json:"thresholds,omitempty"`
	Options          map[string]any     `json:"options,omitempty"`
}

// sarifText is the SARIF multi-format string container used for messages and descriptions.
type sarifText struct {
	Text string `json:"text"`
}

// sarifResult mirrors a single SARIF result entry corresponding to one finding.
type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           *int              `json:"ruleIndex,omitempty"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties"`
}

// sarifRunProperties carries gruff-go metadata at the SARIF run level.
type sarifRunProperties struct {
	GruffSchemaVersion string `json:"gruffSchemaVersion"`
	Score              int    `json:"score"`
	Grade              string `json:"grade"`
}

// sarifLocation wraps a physical location reference for a SARIF result.
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

// sarifPhysicalLocation captures the file artefact and optional region of a SARIF location.
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

// sarifArtifactLocation references the source artefact for a SARIF location.
type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// sarifRegion describes the line and column span associated with a SARIF result.
type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
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

// sarifResults converts findings into SARIF results, indexing each entry into the driver rule list.
func sarifResults(findings []finding.Finding, definitions []rule.Definition) []sarifResult {
	ruleIndices := map[string]int{}
	for index, definition := range definitions {
		ruleIndices[definition.ID] = index
	}
	out := make([]sarifResult, 0, len(findings))
	for _, findingItem := range findings {
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
			PartialFingerprints: map[string]string{"gruffFingerprint": findingItem.Fingerprint},
			Properties: map[string]any{
				"confidence":  findingItem.Confidence,
				"fingerprint": findingItem.Fingerprint,
				"pillar":      findingItem.Pillar,
				"severity":    findingItem.Severity,
			},
		}
		if ruleIndex, ok := ruleIndices[findingItem.RuleID]; ok {
			result.RuleIndex = &ruleIndex
		}
		if len(findingItem.SecondaryPillars) > 0 {
			result.Properties["secondaryPillars"] = findingItem.SecondaryPillars
		}
		if findingItem.Symbol != "" {
			result.Properties["symbol"] = findingItem.Symbol
		}
		if findingItem.Remediation != "" {
			result.Properties["remediation"] = findingItem.Remediation
		}
		if len(findingItem.Metadata) > 0 {
			result.Properties["metadata"] = findingItem.Metadata
		}
		out = append(out, result)
	}
	return out
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
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// githubLevel maps a gruff severity onto the corresponding GitHub annotation level.
func githubLevel(severity finding.Severity) string {
	switch severity {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
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
