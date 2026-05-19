// Package rule defines scanner rule contracts, registries, and built-in rules.
// This file declares the Definition value type and rule capability enum.
package rule

import (
	"fmt"
	"regexp"
	"slices"

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

// Definition is the static description of a rule registered with the scanner.
type Definition struct {
	ID               string             `json:"id"`
	Title            string             `json:"title"`
	Description      string             `json:"description"`
	Pillar           finding.Pillar     `json:"pillar"`
	SecondaryPillars []finding.Pillar   `json:"secondaryPillars,omitempty"`
	Severity         finding.Severity   `json:"severity"`
	Confidence       finding.Confidence `json:"confidence"`
	Capability       Capability         `json:"capability"`
	DefaultEnabled   bool               `json:"defaultEnabled"`
	Thresholds       map[string]float64 `json:"thresholds,omitempty"`
	Options          map[string]any     `json:"options,omitempty"`
	Tags             []string           `json:"tags,omitempty"`
	Remediation      string             `json:"remediation,omitempty"`
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
