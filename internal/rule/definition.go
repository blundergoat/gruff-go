// Package rule defines scanner rule contracts, registries, and built-in rules.
//
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
//
// Each dot-separated part starts with a lowercase letter, then lowercase letters, digits and single inner hyphens; two or more parts are needed.
// Validate rejects a definition whose ID fails it, and a registry holding that definition fails to build.
var ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+$`)

// Capability names the analyser layer a rule needs (parser, types, SSA, dataflow).
//
// Each Definition declares one, and it is serialised with the rule as capability.
// Validate treats an empty Capability as CapabilityParser and rejects any value outside the four constants below.
type Capability string

// Capability constants enumerate the supported analyser layers.
//
// Capability.Valid accepts exactly these four values; a definition naming any other layer fails Validate.
const (
	CapabilityParser   Capability = "parser"
	CapabilityType     Capability = "type"
	CapabilitySSA      Capability = "ssa"
	CapabilityDataflow Capability = "dataflow"
)

// FalsePositiveShape documents a known case where a rule can lack context.
//
// Shape tells users what can be mistaken for a defect.
// Mitigation gives a practical way to keep the scan actionable.
// Validate rejects an entry whose Shape or Mitigation is blank.
type FalsePositiveShape struct {
	// Shape describes the source pattern that can be misclassified.
	Shape string `json:"shape"`
	// Mitigation explains how a user can avoid or scope the finding.
	Mitigation string `json:"mitigation"`
}

// Definition is the static description of a registered scanner rule.
//
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
	// Options exposes named rule settings, such as lists, allow-lists, modes and some integer options, that callers may override via config.
	Options map[string]any `json:"options,omitempty"`
	// Tags categorise the rule for documentation and filtering (e.g. "go-style", "secrets").
	Tags []string `json:"tags,omitempty"`
	// Remediation is the default fix guidance copied onto a finding only when the rule left that finding's Remediation empty.
	Remediation string `json:"remediation,omitempty"`
	// FalsePositiveShapes lists known precision limits shown only by the rule catalogue.
	FalsePositiveShapes []FalsePositiveShape `json:"-"`
}

// Validate checks the definition fields are consistent and applies defaults.
//
// An empty Capability becomes CapabilityParser before the Capability check, and Tags are sorted in place only when every check passes.
//
// It returns an error quoting the rule ID when ID does not match ruleIDPattern, Title is empty, or Pillar or a SecondaryPillars entry is invalid.
// It also fails on an invalid Severity, Confidence or Capability, or on an empty Thresholds or Options key.
// A FalsePositiveShapes entry with a blank Shape or Mitigation also fails; otherwise Validate returns nil.
func (d *Definition) Validate() error {
	// An ID such as Size.FileLength, size_file_length or a lone word with no dot fails here, and registry construction stops with this error.
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

// Valid reports whether the capability is one of the four known analyser layers.
// It is false for any other value; Validate replaces an empty Capability with CapabilityParser first, so only an unknown name fails there.
func (c Capability) Valid() bool {
	switch c {
	case CapabilityParser, CapabilityType, CapabilitySSA, CapabilityDataflow:
		return true
	default:
		return false
	}
}
