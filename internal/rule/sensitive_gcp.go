// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements the sensitive-data.gcp-service-account detector for committed GCP service-account JSON key files.
// It fires on their documented two-marker shape and is off by default, so its finding appears only after the user enables the rule.
//
// Coexists with sensitive-data.private-key per ADR-007: both rules emit independent findings on the same file.
package rule

import (
	"regexp"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// serviceAccountTypePattern matches the literal "type": "service_account" field present in every GCP service-account JSON key file.
//
// It pairs with privateKeyPattern, declared in sensitive.go, as a co-occurrence signature.
// Whitespace around the colon is optional, so compact and pretty-printed key files both match.
var serviceAccountTypePattern = regexp.MustCompile(`"type"\s*:\s*"service_account"`)

// GCPServiceAccountRule flags GCP service-account JSON key files committed to source.
//
// It fires only when a file has both a "type": "service_account" marker and a PEM private-key header on code-bearing lines.
// Neither marker alone triggers a finding. Coexists with sensitive-data.private-key per ADR-007.
type GCPServiceAccountRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.gcp-service-account rule with warning severity and high confidence.
//
// The rule flags files containing both "type": "service_account" and a PEM private-key header.
// It returns the same fixed metadata on every call, with the secrets tag and DefaultEnabled false, so the rule is off unless enabled.
func (GCPServiceAccountRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.gcp-service-account",
		Title:          "GCP service-account JSON key",
		Description:    "Flags files containing both a `\"type\": \"service_account\"` marker and a PEM private-key header - the documented shape of a GCP service-account JSON key file. Fires independently of sensitive-data.private-key, so a real key file produces two findings.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: false,
		Tags:           []string{"secrets"},
		Remediation:    "Rotate the service-account key, delete the JSON file from source-control history, and re-issue credentials through a secret manager or Workload Identity.",
	}
}

// AnalyzeUnit emits at most one finding when both GCP key markers appear on code-bearing lines in the same file.
//
// The unit is the parsed file that scanUnitForCoOccurrence checks for the service-account type marker and a PEM private-key header.
// The spec carries the finding message "GCP service-account JSON key detected", and the scan also gets the rule's preview policy.
// It returns that scan's findings, which are empty when either marker is missing from the code-bearing lines.
func (r GCPServiceAccountRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	spec := coOccurrenceSecretSpec{
		primary: serviceAccountTypePattern, secondary: privateKeyPattern,
		message:         "GCP service-account JSON key detected",
		primaryCategory: previewGCPServiceAccount, secondaryCategory: previewPrivateKey,
	}
	return scanUnitForCoOccurrence(unit, spec, r.previews)
}
