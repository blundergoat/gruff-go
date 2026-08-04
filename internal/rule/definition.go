// Package rule defines scanner rule contracts, registries, and built-in rules.
// This file declares metadata that powers configuration and rule catalogues.
// Users see these values when deciding how to resolve or tune a finding.
package rule

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// ruleIDPattern validates rule IDs of the form pillar.kebab-case.
var ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+$`)

// Capability names the analyser layer a rule needs (parser, types, SSA, dataflow).
type Capability string

// Capability constants enumerate the supported analyser layers.
const (
	CapabilityParser   Capability = "parser"
	CapabilityType     Capability = "type"
	CapabilitySSA      Capability = "ssa"
	CapabilityDataflow Capability = "dataflow"
)

// FalsePositiveShape documents a known case where a rule can lack context.
// Shape tells users what can be mistaken for a defect.
// Mitigation gives a practical way to keep the scan actionable.
type FalsePositiveShape struct {
	// Shape describes the source pattern that can be misclassified.
	Shape string `json:"shape"`
	// Mitigation explains how a user can avoid or scope the finding.
	Mitigation string `json:"mitigation"`
}

// Definition is the static description of a registered scanner rule.
// Config validation and report findings share this source of truth.
// Catalogue-only guidance is excluded from analysis-report JSON.
type Definition struct {
	// ID is the kebab-case dotted rule identifier validated against ruleIDPattern (e.g. "naming.acronym-case").
	ID string `json:"id"`
	// Title is the short human-readable label shown in catalogues and reports.
	Title string `json:"title"`
	// Description is the one-paragraph explanation rendered for users that documents what the rule catches.
	Description string `json:"description"`
	// Pillar is the primary quality category (naming, size, complexity, etc.) this rule contributes findings to.
	Pillar finding.Pillar `json:"pillar"`
	// SecondaryPillars are additional categories a composite or cross-cutting rule also touches.
	SecondaryPillars []finding.Pillar `json:"secondaryPillars,omitempty"`
	// Severity is the default severity level emitted on findings, before any config override.
	Severity finding.Severity `json:"severity"`
	// Confidence reflects how reliably this rule flags a real issue versus a false positive.
	Confidence finding.Confidence `json:"confidence"`
	// Capability declares which analyser layer (parser, type, ssa, dataflow) the rule needs to run.
	Capability Capability `json:"capability"`
	// DefaultEnabled selects whether the rule fires under the default policy when no config overrides apply.
	DefaultEnabled bool `json:"defaultEnabled"`
	// Thresholds exposes named numeric knobs (line caps, counts) that callers may override via config.
	Thresholds map[string]float64 `json:"thresholds,omitempty"`
	// Options exposes named non-numeric knobs (lists, allow-lists, modes) that callers may override via config.
	Options map[string]any `json:"options,omitempty"`
	// Tags categorise the rule for documentation and filtering (e.g. "go-style", "secrets").
	Tags []string `json:"tags,omitempty"`
	// Remediation is the actionable guidance copied onto each finding to tell users how to fix it.
	Remediation string `json:"remediation,omitempty"`
	// FalsePositiveShapes lists known precision limits shown only by the rule catalogue.
	FalsePositiveShapes []FalsePositiveShape `json:"-"`
}

// Validate checks the definition fields are consistent and applies defaults.
func (d *Definition) Validate() error {
	if !ruleIDPattern.MatchString(d.ID) {
		return fmt.Errorf("invalid rule id %q", d.ID)
	}
	if d.Title == "" {
		return fmt.Errorf("rule %q has empty title", d.ID)
	}
	if !d.Pillar.Valid() {
		return fmt.Errorf("rule %q has invalid pillar %q", d.ID, d.Pillar)
	}
	for _, pillar := range d.SecondaryPillars {
		if !pillar.Valid() {
			return fmt.Errorf("rule %q has invalid secondary pillar %q", d.ID, pillar)
		}
	}
	if !d.Severity.Valid() {
		return fmt.Errorf("rule %q has invalid severity %q", d.ID, d.Severity)
	}
	if !d.Confidence.Valid() {
		return fmt.Errorf("rule %q has invalid confidence %q", d.ID, d.Confidence)
	}
	if d.Capability == "" {
		d.Capability = CapabilityParser
	}
	if !d.Capability.Valid() {
		return fmt.Errorf("rule %q has invalid capability %q", d.ID, d.Capability)
	}
	for name := range d.Thresholds {
		if name == "" {
			return fmt.Errorf("rule %q has empty threshold name", d.ID)
		}
	}
	for name := range d.Options {
		if name == "" {
			return fmt.Errorf("rule %q has empty option name", d.ID)
		}
	}
	// Blank catalogue guidance would leave users unable to recognise or mitigate the limitation.
	for shapeIndex, knownShape := range d.FalsePositiveShapes {
		// A missing shape gives the user no way to recognise the documented limitation.
		if strings.TrimSpace(knownShape.Shape) == "" {
			return fmt.Errorf("rule %q has empty false-positive shape at index %d", d.ID, shapeIndex)
		}
		// A missing mitigation leaves the user with no practical next action.
		if strings.TrimSpace(knownShape.Mitigation) == "" {
			return fmt.Errorf("rule %q has empty false-positive mitigation at index %d", d.ID, shapeIndex)
		}
	}
	slices.Sort(d.Tags)
	return nil
}

// Valid reports whether the capability is a known analyser layer.
func (c Capability) Valid() bool {
	switch c {
	case CapabilityParser, CapabilityType, CapabilitySSA, CapabilityDataflow:
		return true
	default:
		return false
	}
}
