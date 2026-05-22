// Package rule defines gruff-go's rule registry and analysers.
// This file implements the sensitive-data.gcp-service-account detector that
// fires on the documented two-marker shape of a GCP service-account JSON key
// file. Coexists with sensitive-data.private-key per ADR-007: both rules
// emit independent findings on the same file.
package rule

import (
	"regexp"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// serviceAccountTypePattern matches the literal `"type": "service_account"`
// field present in every GCP service-account JSON key file. Used together
// with privateKeyPattern (declared in sensitive.go) as a co-occurrence
// signature.
var serviceAccountTypePattern = regexp.MustCompile(`"type"\s*:\s*"service_account"`)

// GCPServiceAccountRule flags GCP service-account JSON key files committed to source.
// It fires only when a file contains both a `"type": "service_account"` marker
// and a PEM private-key header on code-bearing lines, so neither marker alone
// triggers a finding. Coexists with sensitive-data.private-key per ADR-007.
type GCPServiceAccountRule struct{}

// Definition declares the sensitive-data.gcp-service-account rule that flags files containing both `"type": "service_account"` and a PEM private-key header with critical severity and high confidence.
func (GCPServiceAccountRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.gcp-service-account",
		Title:          "GCP service-account JSON key",
		Description:    "Flags files containing both a `\"type\": \"service_account\"` marker and a PEM private-key header — the documented shape of a GCP service-account JSON key file. Fires independently of sensitive-data.private-key, so a real key file produces two findings.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityCritical,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Rotate the service-account key, delete the JSON file from source-control history, and re-issue credentials through a secret manager or Workload Identity.",
	}
}

// AnalyzeUnit emits at most one finding when both the service-account type marker and a PEM private-key header appear on code-bearing lines in the same file.
func (GCPServiceAccountRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanUnitForCoOccurrence(unit, serviceAccountTypePattern, privateKeyPattern, "GCP service-account JSON key detected")
}
