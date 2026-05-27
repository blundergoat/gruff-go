// Package rule defines gruff-go's rule registry and analysers.
// This file implements vendor-prefixed token detectors that piggyback on the
// shared scanLinesForSecret plumbing in sensitive.go: GitHub, Slack, Stripe,
// Google, Anthropic, npm, and GitLab API key shapes.
package rule

import (
	"regexp"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

var (
	// GitHub tokens: gh[a-z]_ + 36-255 alphanumerics. The single character class
	// covers PAT (ghp_), OAuth (gho_), user-to-server (ghu_), server-to-server
	// (ghs_), and refresh (ghr_) variants in one expression.
	githubTokenPattern = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,255}`)
	// Slack tokens: three segments after the xox[bpar]- prefix covering bot,
	// user, app, and refresh tokens.
	slackTokenPattern = regexp.MustCompile(`xox[bpar]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,}`)
	// Stripe live keys: secret (sk_), publishable (pk_), and restricted (rk_)
	// against the live environment. Non-capturing group keeps the regex engine
	// from materialising subgroup state per match.
	stripeLiveKeyPattern = regexp.MustCompile(`(?:sk|pk|rk)_live_[A-Za-z0-9]{24,}`)
	// Google API keys: documented 39-char fixed-width format.
	googleAPIKeyPattern = regexp.MustCompile(`AIza[A-Za-z0-9_\-]{35}`)
	// Anthropic API keys: sk-ant- prefix plus an alphanumeric body.
	anthropicAPIKeyPattern = regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`)
	// npm tokens: legacy npm_ and granular npm_pat_ prefixes with provider-style
	// alphanumeric bodies.
	npmTokenPattern = regexp.MustCompile(`npm_(?:pat_)?[A-Za-z0-9]{20,}`)
	// GitLab tokens: personal, trigger, runner, and OAuth/application secret prefixes.
	gitLabTokenPattern = regexp.MustCompile(`(?:glpat|glptt|glrt|gloas)-[A-Za-z0-9_\-]{20,}`)
)

// GitHubTokenRule flags GitHub personal-access, OAuth, user-to-server, server-to-server, and refresh tokens embedded in source.
type GitHubTokenRule struct{}

// Definition declares the sensitive-data.github-token rule that flags gh[pousr]_-prefixed GitHub tokens with high severity and high confidence.
func (GitHubTokenRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.github-token",
		Title:          "GitHub token literal",
		Description:    "Flags GitHub personal-access, OAuth, user-to-server, server-to-server, and refresh tokens (gh[pousr]_ prefix) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityError,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Revoke the token, then load credentials from a secret manager or environment-specific runtime configuration.",
	}
}

// AnalyzeUnit scans the unit's source for GitHub token literals.
func (GitHubTokenRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, githubTokenPattern, "GitHub token literal detected")
}

// SlackTokenRule flags Slack bot, user, app, and refresh token literals embedded in source.
type SlackTokenRule struct{}

// Definition declares the sensitive-data.slack-token rule that flags xox[bpar]--prefixed Slack tokens with high severity and high confidence.
func (SlackTokenRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.slack-token",
		Title:          "Slack token literal",
		Description:    "Flags Slack bot, user, app, and refresh tokens (xox[bpar]- prefix) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityError,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Revoke the token in Slack's app management console, then load credentials from a secret manager.",
	}
}

// AnalyzeUnit scans the unit's source for Slack token literals.
func (SlackTokenRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, slackTokenPattern, "Slack token literal detected")
}

// StripeLiveKeyRule flags Stripe secret, publishable, and restricted live-environment keys embedded in source.
type StripeLiveKeyRule struct{}

// Definition declares the sensitive-data.stripe-key rule that flags (sk|pk|rk)_live_-prefixed Stripe keys with high severity and high confidence.
func (StripeLiveKeyRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.stripe-key",
		Title:          "Stripe live key literal",
		Description:    "Flags Stripe secret, publishable, and restricted live-environment keys ((sk|pk|rk)_live_ prefix) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityError,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Roll the key in the Stripe dashboard, then load credentials from a secret manager.",
	}
}

// AnalyzeUnit scans the unit's source for Stripe live key literals.
func (StripeLiveKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, stripeLiveKeyPattern, "Stripe live key literal detected")
}

// GoogleAPIKeyRule flags Google API key literals embedded in source.
type GoogleAPIKeyRule struct{}

// Definition declares the sensitive-data.google-api-key rule that flags AIza-prefixed Google API keys with high severity and high confidence.
func (GoogleAPIKeyRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.google-api-key",
		Title:          "Google API key literal",
		Description:    "Flags Google API keys (AIza prefix plus 35 base64url characters) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityError,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Delete or restrict the key in the Google Cloud console, then load credentials from a secret manager.",
	}
}

// AnalyzeUnit scans the unit's source for Google API key literals.
func (GoogleAPIKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, googleAPIKeyPattern, "Google API key literal detected")
}

// AnthropicAPIKeyRule flags Anthropic API key literals embedded in source.
type AnthropicAPIKeyRule struct{}

// Definition declares the sensitive-data.anthropic-api-key rule that flags sk-ant--prefixed Anthropic API keys with high severity and high confidence.
func (AnthropicAPIKeyRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.anthropic-api-key",
		Title:          "Anthropic API key literal",
		Description:    "Flags Anthropic API keys (sk-ant- prefix) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityError,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Revoke the key in the Anthropic console, then load credentials from a secret manager.",
	}
}

// AnalyzeUnit scans the unit's source for Anthropic API key literals.
func (AnthropicAPIKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, anthropicAPIKeyPattern, "Anthropic API key literal detected")
}

// NPMTokenRule flags npm access token literals embedded in source.
type NPMTokenRule struct{}

// Definition declares the sensitive-data.npm-token rule that flags npm_-prefixed npm tokens with high severity and high confidence.
func (NPMTokenRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.npm-token",
		Title:          "npm token literal",
		Description:    "Flags npm access tokens (npm_ and npm_pat_ prefixes) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityError,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Revoke the token in npm, then load credentials from a secret manager or environment-specific runtime configuration.",
	}
}

// AnalyzeUnit scans the unit's source for npm token literals.
func (NPMTokenRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, npmTokenPattern, "npm token literal detected")
}

// GitLabTokenRule flags GitLab access token literals embedded in source.
type GitLabTokenRule struct{}

// Definition declares the sensitive-data.gitlab-token rule that flags GitLab provider token prefixes with high severity and high confidence.
func (GitLabTokenRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.gitlab-token",
		Title:          "GitLab token literal",
		Description:    "Flags GitLab personal, trigger, runner, and application tokens (glpat-, glptt-, glrt-, gloas-) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityError,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Revoke the token in GitLab, then load credentials from a secret manager or environment-specific runtime configuration.",
	}
}

// AnalyzeUnit scans the unit's source for GitLab token literals.
func (GitLabTokenRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, gitLabTokenPattern, "GitLab token literal detected")
}
