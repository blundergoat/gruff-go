// Package rule defines gruff-go's rule registry and analysers.
//
// This file adds vendor-prefixed token detectors that piggyback on the shared scanLinesForSecret plumbing in sensitive.go.
// They cover GitHub, Slack, Stripe, Google, Anthropic, npm and GitLab API key shapes, each under its own sensitive-data rule ID.
// GitHub and Google detection ships disabled by default; the other five rules are enabled by default.
package rule

import (
	"regexp"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// Vendor token patterns, one per rule below; none is anchored, so a token inside a URL, header value or longer string still matches.
var (
	// GitHub tokens use ghp_, gho_, ghu_, ghs_ or ghr_ followed by 36 to 255 alphanumeric characters.
	// One character class covers the PAT, OAuth, user-to-server, server-to-server and refresh variants in one expression.
	githubTokenPattern = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,255}`)
	// Slack tokens use xoxb-, xoxp-, xoxa- or xoxr- followed by two 10 to 13 digit segments and a 20-plus alphanumeric segment.
	// Together the prefixes cover bot, user, app and refresh tokens.
	slackTokenPattern = regexp.MustCompile(`xox[bpar]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,}`)
	// Stripe live keys: secret (sk_), publishable (pk_) and restricted (rk_) keys for the live environment; test-mode keys do not match.
	// The non-capturing group keeps the regex engine from materialising subgroup state per match.
	stripeLiveKeyPattern = regexp.MustCompile(`(?:sk|pk|rk)_live_[A-Za-z0-9]{24,}`)
	// Google API keys: documented 39-char fixed-width format.
	googleAPIKeyPattern = regexp.MustCompile(`AIza[A-Za-z0-9_\-]{35}`)
	// Anthropic key matches use sk-ant- followed by at least 20 letters, digits, underscores or hyphens.
	anthropicAPIKeyPattern = regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`)
	// npm tokens: legacy npm_ and granular npm_pat_ prefixes followed by at least 20 alphanumeric characters.
	npmTokenPattern = regexp.MustCompile(`npm_(?:pat_)?[A-Za-z0-9]{20,}`)
	// GitLab tokens: personal, trigger, runner, and OAuth/application secret prefixes.
	gitLabTokenPattern = regexp.MustCompile(`(?:glpat|glptt|glrt|gloas)-[A-Za-z0-9_\-]{20,}`)
)

// GitHubTokenRule flags GitHub personal-access, OAuth, user-to-server, server-to-server, and refresh tokens embedded in source.
type GitHubTokenRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.github-token rule that flags GitHub tokens prefixed ghp_, gho_, ghu_, ghs_ or ghr_.
// It returns the rule metadata at warning severity and high confidence, tagged secrets and disabled by default.
func (GitHubTokenRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.github-token",
		Title:          "GitHub token literal",
		Description:    "Flags GitHub personal-access, OAuth, user-to-server, server-to-server, and refresh tokens (gh[pousr]_ prefix) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: false,
		Tags:           []string{"secrets"},
		Remediation:    "Revoke the token, then load credentials from a secret manager or environment-specific runtime configuration.",
	}
}

// AnalyzeUnit scans the unit's source for GitHub token literals.
//
// It returns one finding per githubTokenPattern match in unit, skipping vendor-documented samples and lines lineIsCodeBearing rejects.
// The result is an empty, non-nil slice when no eligible match remains.
func (r GitHubTokenRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, githubTokenPattern, "GitHub token literal detected", r.previews, previewGitHubToken)
}

// SlackTokenRule flags Slack bot, user, app, and refresh token literals embedded in source.
type SlackTokenRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.slack-token rule that flags Slack tokens prefixed xoxb-, xoxp-, xoxa- or xoxr-.
// It returns the rule metadata at warning severity and high confidence, tagged secrets and enabled by default.
func (SlackTokenRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.slack-token",
		Title:          "Slack token literal",
		Description:    "Flags Slack bot, user, app, and refresh tokens (xox[bpar]- prefix) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Revoke the token in Slack's app management console, then load credentials from a secret manager.",
	}
}

// AnalyzeUnit scans the unit's source for Slack token literals.
//
// It returns one finding per slackTokenPattern match in unit, skipping vendor-documented samples and lines lineIsCodeBearing rejects.
// The result is an empty, non-nil slice when no eligible match remains.
func (r SlackTokenRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, slackTokenPattern, "Slack token literal detected", r.previews, previewSlackToken)
}

// StripeLiveKeyRule flags Stripe secret, publishable, and restricted live-environment keys embedded in source.
type StripeLiveKeyRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.stripe-key rule that flags (sk|pk|rk)_live_-prefixed Stripe keys.
// It returns the rule metadata at warning severity and high confidence, tagged secrets and enabled by default.
func (StripeLiveKeyRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.stripe-key",
		Title:          "Stripe live key literal",
		Description:    "Flags Stripe secret, publishable, and restricted live-environment keys ((sk|pk|rk)_live_ prefix) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Roll the key in the Stripe dashboard, then load credentials from a secret manager.",
	}
}

// AnalyzeUnit scans the unit's source for Stripe live key literals.
//
// It returns one finding per stripeLiveKeyPattern match in unit, skipping vendor-documented samples and lines lineIsCodeBearing rejects.
// The result is an empty, non-nil slice when no eligible match remains.
func (r StripeLiveKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, stripeLiveKeyPattern, "Stripe live key literal detected", r.previews, previewStripeLiveKey)
}

// GoogleAPIKeyRule flags Google API key literals embedded in source.
type GoogleAPIKeyRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.google-api-key rule that flags AIza-prefixed Google API keys.
// It returns the rule metadata at warning severity and high confidence, tagged secrets and disabled by default.
func (GoogleAPIKeyRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.google-api-key",
		Title:          "Google API key literal",
		Description:    "Flags Google API keys (AIza prefix plus 35 base64url characters) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: false,
		Tags:           []string{"secrets"},
		Remediation:    "Delete or restrict the key in the Google Cloud console, then load credentials from a secret manager.",
	}
}

// AnalyzeUnit scans the unit's source for Google API key literals.
//
// It returns one finding per googleAPIKeyPattern match in unit, skipping vendor-documented samples and lines lineIsCodeBearing rejects.
// The result is an empty, non-nil slice when no eligible match remains.
func (r GoogleAPIKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, googleAPIKeyPattern, "Google API key literal detected", r.previews, previewGoogleAPIKey)
}

// AnthropicAPIKeyRule flags Anthropic API key literals embedded in source.
type AnthropicAPIKeyRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.anthropic-api-key rule that flags sk-ant--prefixed Anthropic API keys.
// It returns the rule metadata at warning severity and high confidence, tagged secrets and enabled by default.
func (AnthropicAPIKeyRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.anthropic-api-key",
		Title:          "Anthropic API key literal",
		Description:    "Flags Anthropic API keys (sk-ant- prefix) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Revoke the key in the Anthropic console, then load credentials from a secret manager.",
	}
}

// AnalyzeUnit scans the unit's source for Anthropic API key literals.
//
// It returns one finding per anthropicAPIKeyPattern match in unit, skipping vendor-documented samples and lines lineIsCodeBearing rejects.
// The result is an empty, non-nil slice when no eligible match remains.
func (r AnthropicAPIKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, anthropicAPIKeyPattern, "Anthropic API key literal detected", r.previews, previewAnthropicAPIKey)
}

// NPMTokenRule flags npm access token literals embedded in source.
type NPMTokenRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.npm-token rule that flags npm_-prefixed npm tokens.
// It returns the rule metadata at warning severity and high confidence, tagged secrets and enabled by default.
func (NPMTokenRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.npm-token",
		Title:          "npm token literal",
		Description:    "Flags npm access tokens (npm_ and npm_pat_ prefixes) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Revoke the token in npm, then load credentials from a secret manager or environment-specific runtime configuration.",
	}
}

// AnalyzeUnit scans the unit's source for npm token literals.
//
// It returns one finding per npmTokenPattern match in unit, skipping vendor-documented samples and lines lineIsCodeBearing rejects.
// The result is an empty, non-nil slice when no eligible match remains.
func (r NPMTokenRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, npmTokenPattern, "npm token literal detected", r.previews, previewNPMToken)
}

// GitLabTokenRule flags GitLab access token literals embedded in source.
type GitLabTokenRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.gitlab-token rule that flags GitLab provider token prefixes.
// It returns the rule metadata at warning severity and high confidence, tagged secrets and enabled by default.
func (GitLabTokenRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.gitlab-token",
		Title:          "GitLab token literal",
		Description:    "Flags GitLab personal, trigger, runner, and application tokens (glpat-, glptt-, glrt-, gloas-) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Revoke the token in GitLab, then load credentials from a secret manager or environment-specific runtime configuration.",
	}
}

// AnalyzeUnit scans the unit's source for GitLab token literals.
//
// It returns one finding per gitLabTokenPattern match in unit, skipping vendor-documented samples and lines lineIsCodeBearing rejects.
// The result is an empty, non-nil slice when no eligible match remains.
func (r GitLabTokenRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, gitLabTokenPattern, "GitLab token literal detected", r.previews, previewGitLabToken)
}
