// Package rule defines scanner rule contracts, registries, and built-in rules.
package rule

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/blundergoat/gruff-go/internal/finding"
)

var ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+$`)

type Definition struct {
	ID               string             `json:"id"`
	Title            string             `json:"title"`
	Description      string             `json:"description"`
	Pillar           finding.Pillar     `json:"pillar"`
	SecondaryPillars []finding.Pillar   `json:"secondaryPillars,omitempty"`
	Severity         finding.Severity   `json:"severity"`
	Confidence       finding.Confidence `json:"confidence"`
	DefaultEnabled   bool               `json:"defaultEnabled"`
	Thresholds       map[string]float64 `json:"thresholds,omitempty"`
	Options          map[string]any     `json:"options,omitempty"`
	Tags             []string           `json:"tags,omitempty"`
	Remediation      string             `json:"remediation,omitempty"`
}

func (d Definition) Validate() error {
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
