package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

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

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool          `json:"tool"`
	Results    []sarifResult      `json:"results"`
	Properties sarifRunProperties `json:"properties"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name"`
	ShortDescription     sarifText                 `json:"shortDescription"`
	FullDescription      sarifText                 `json:"fullDescription"`
	Help                 sarifText                 `json:"help"`
	Properties           sarifRuleProperty         `json:"properties"`
	DefaultConfiguration sarifDefaultConfiguration `json:"defaultConfiguration"`
}

type sarifDefaultConfiguration struct {
	Level string `json:"level"`
}

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

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           *int              `json:"ruleIndex,omitempty"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties"`
}

type sarifRunProperties struct {
	GruffSchemaVersion string `json:"gruffSchemaVersion"`
	Score              int    `json:"score"`
	Grade              string `json:"grade"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
}

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

func sarifResults(findings []finding.Finding, definitions []rule.Definition) []sarifResult {
	ruleIndices := map[string]int{}
	for index, definition := range definitions {
		ruleIndices[definition.ID] = index
	}
	out := make([]sarifResult, 0, len(findings))
	for _, item := range findings {
		result := sarifResult{
			RuleID:  item.RuleID,
			Level:   sarifLevel(item.Severity),
			Message: sarifText{Text: item.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: sarifURI(item.File)},
					Region:           sarifRegionFromFinding(item),
				},
			}},
			PartialFingerprints: map[string]string{"gruffFingerprint": item.Fingerprint},
			Properties: map[string]any{
				"confidence":  item.Confidence,
				"fingerprint": item.Fingerprint,
				"pillar":      item.Pillar,
				"severity":    item.Severity,
			},
		}
		if ruleIndex, ok := ruleIndices[item.RuleID]; ok {
			result.RuleIndex = &ruleIndex
		}
		if len(item.SecondaryPillars) > 0 {
			result.Properties["secondaryPillars"] = item.SecondaryPillars
		}
		if item.Symbol != "" {
			result.Properties["symbol"] = item.Symbol
		}
		if item.Remediation != "" {
			result.Properties["remediation"] = item.Remediation
		}
		if len(item.Metadata) > 0 {
			result.Properties["metadata"] = item.Metadata
		}
		out = append(out, result)
	}
	return out
}

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

func sarifURI(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	for strings.HasPrefix(path, "./") {
		path = strings.TrimPrefix(path, "./")
	}
	return path
}

func sarifRunPropertiesFromReport(report analysis.Report) sarifRunProperties {
	return sarifRunProperties{
		GruffSchemaVersion: report.SchemaVersion,
		Score:              report.Score.Composite,
		Grade:              report.Score.Grade,
	}
}

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

func escapeGitHubMessage(value string) string {
	value = strings.ReplaceAll(value, "%", "%25")
	value = strings.ReplaceAll(value, "\r", "%0D")
	value = strings.ReplaceAll(value, "\n", "%0A")
	return value
}

func escapeGitHubProperty(value string) string {
	value = escapeGitHubMessage(value)
	value = strings.ReplaceAll(value, ":", "%3A")
	value = strings.ReplaceAll(value, ",", "%2C")
	return value
}
