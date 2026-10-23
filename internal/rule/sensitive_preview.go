// Package rule owns the marker vocabulary shared by every sensitive-data detector: the closed set of
// zero-payload markers FAMILY-CONTRACT.md section 5 ratifies, emitted unconditionally.
package rule

import (
	"strings"
)

// redactedPreview is the bare marker, emitted whenever the detector classifies nothing more specific.
const redactedPreview = "[redacted]"

// sensitivePreviewCategory is the closed formatter vocabulary; nothing outside it can reach a marker.
type sensitivePreviewCategory string

// previewGeneric is the fully masked generic-assignment category.
const previewGeneric sensitivePreviewCategory = "generic"

// previewEntropy is the fully masked entropy-secret category.
const previewEntropy sensitivePreviewCategory = "entropy"

// previewPrivateKey labels authorized output without exposing PEM material.
const previewPrivateKey sensitivePreviewCategory = "private-key"

// previewJWT is the JSON Web Token type marker.
const previewJWT sensitivePreviewCategory = "jwt"

// previewConnectionString authorizes only a validated connection scheme.
const previewConnectionString sensitivePreviewCategory = "connection-string"

// previewAWSAccessKey labels authorized output without exposing credential payloads.
const previewAWSAccessKey sensitivePreviewCategory = "aws-access-key"

// previewGitHubToken labels authorized output without exposing provider credentials.
const previewGitHubToken sensitivePreviewCategory = "github-token"

// previewSlackToken labels authorized output without exposing provider credentials.
const previewSlackToken sensitivePreviewCategory = "slack-token"

// previewStripeLiveKey labels authorized output without exposing payment credentials.
const previewStripeLiveKey sensitivePreviewCategory = "stripe-live-key"

// previewGoogleAPIKey labels authorized output without exposing provider credentials.
const previewGoogleAPIKey sensitivePreviewCategory = "google-api-key"

// previewAnthropicAPIKey labels authorized output without exposing provider credentials.
const previewAnthropicAPIKey sensitivePreviewCategory = "anthropic-api-key"

// previewNPMToken labels authorized output without exposing registry credentials.
const previewNPMToken sensitivePreviewCategory = "npm-token"

// previewGitLabToken labels authorized output without exposing provider credentials.
const previewGitLabToken sensitivePreviewCategory = "gitlab-token"

// previewGCPServiceAccount labels authorized output without exposing account credentials.
const previewGCPServiceAccount sensitivePreviewCategory = "gcp-service-account"

// previewEmail is the email PII category marker.
const previewEmail sensitivePreviewCategory = "email"

// previewPhone is the phone PII category marker.
const previewPhone sensitivePreviewCategory = "phone"

// previewPaymentCard is the payment-card PII category marker.
const previewPaymentCard sensitivePreviewCategory = "payment-card"

// previewSSN is the Social Security number PHI category marker.
const previewSSN sensitivePreviewCategory = "ssn"

// previewMedicare is the Medicare beneficiary PHI category marker.
const previewMedicare sensitivePreviewCategory = "medicare"

// previewMRN is the medical-record-number PHI category marker.
const previewMRN sensitivePreviewCategory = "mrn"

// personalDataPreviewCategory resolves the detector's closed PII/PHI category
// strings without allowing arbitrary finding data into a marker.
func personalDataPreviewCategory(category string) sensitivePreviewCategory {
	switch category {
	case "email":
		return previewEmail
	case "phone":
		return previewPhone
	case "payment-card":
		return previewPaymentCard
	case "ssn":
		return previewSSN
	case "medicare":
		return previewMedicare
	case "mrn":
		return previewMRN
	default:
		return previewGeneric
	}
}

// sensitivePreviewPolicy formats the marker for one classified match. It carries no state because section 5
// leaves nothing to configure: the most specific classified marker is emitted on every path.
type sensitivePreviewPolicy struct{}

// newSensitivePreviewPolicy returns the one policy every scan uses.
//
// It carries no state: FAMILY-CONTRACT.md section 5 makes markers unconditional, because every marker is zero-payload
// by construction, so gating one behind configuration bought no confidentiality and produced cross-port divergence.
func newSensitivePreviewPolicy() sensitivePreviewPolicy {
	return sensitivePreviewPolicy{}
}

// format returns the most specific marker the detector already classified, and a bare mask otherwise.
//
// The path is unused and kept in the signature because every caller has one, and a marker that varied by path is
// exactly what section 5 removed.
func (p sensitivePreviewPolicy) format(_ string, category sensitivePreviewCategory, raw string) string {
	// A generic or entropy match names no class the user can act on, so it stays the bare marker.
	if category == previewGeneric || category == previewEntropy {
		return redactedPreview
	}
	if category == previewConnectionString {
		return connectionStringPreview(raw)
	}
	if !isSensitivePreviewCategory(category) {
		return redactedPreview
	}
	return "[redacted:" + string(category) + "]"
}

// isSensitivePreviewCategory permits only the approved constant marker vocabulary.
func isSensitivePreviewCategory(category sensitivePreviewCategory) bool {
	switch category {
	case previewPrivateKey, previewJWT, previewAWSAccessKey, previewGitHubToken,
		previewSlackToken, previewStripeLiveKey, previewGoogleAPIKey,
		previewAnthropicAPIKey, previewNPMToken, previewGitLabToken,
		previewGCPServiceAccount, previewEmail, previewPhone,
		previewPaymentCard, previewSSN, previewMedicare, previewMRN:
		return true
	default:
		return false
	}
}

// connectionStringPreview reveals only a scheme already accepted by the
// connection-string detector; malformed or unknown input falls back to a full mask.
func connectionStringPreview(raw string) string {
	scheme, _, ok := strings.Cut(raw, "://")
	if !ok {
		return redactedPreview
	}
	scheme = strings.ToLower(scheme)
	switch scheme {
	case "postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "redis", "amqp", "amqps":
		return "[redacted:connection-string:" + scheme + "]"
	default:
		return redactedPreview
	}
}
