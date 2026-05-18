package rule

import (
	"regexp"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

var (
	privateKeyPattern = regexp.MustCompile(`-----BEGIN[ A-Z]*PRIVATE KEY-----`)
	awsAccessPattern  = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	// JWT: three base64url segments separated by dots; first starts with `eyJ`
	// (the literal base64 prefix for `{"`).
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`)
	// Database URLs with embedded passwords: scheme://user:password@host
	connectionPattern = regexp.MustCompile(`(?i)\b(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp|amqps)://[^:\s/@]+:[^@\s/]+@[^\s]+`)
)

type PrivateKeyRule struct{}

func (PrivateKeyRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.private-key",
		Title:          "Embedded private key",
		Description:    "Flags PEM-encoded private keys embedded directly in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityCritical,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"opt-in", "secrets"},
		Remediation:    "Remove the key and load it from a secret manager or environment-specific runtime configuration.",
	}
}

func (PrivateKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, privateKeyPattern, "private key literal detected")
}

type AWSAccessKeyRule struct{}

func (AWSAccessKeyRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.aws-access-key",
		Title:          "AWS access key id",
		Description:    "Flags AWS access key identifiers (AKIA...) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityHigh,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"opt-in", "secrets"},
		Remediation:    "Rotate the key, then load credentials from the AWS SDK default provider chain rather than embedding them.",
	}
}

func (AWSAccessKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, awsAccessPattern, "AWS access key id detected")
}

type JWTTokenRule struct{}

func (JWTTokenRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.jwt-token",
		Title:          "JWT token literal",
		Description:    "Flags JWT-shaped literals (three base64url segments separated by dots) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityHigh,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"opt-in", "secrets"},
		Remediation:    "Move the token to a secret manager or runtime-only configuration; never check signed tokens into source control.",
	}
}

func (JWTTokenRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, jwtPattern, "JWT-like token literal detected")
}

type ConnectionStringRule struct{}

func (ConnectionStringRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.connection-string",
		Title:          "Connection string with embedded password",
		Description:    "Flags database/queue connection URLs that embed a username and password in the URI.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityHigh,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"opt-in", "secrets"},
		Remediation:    "Pull the password from environment-specific runtime configuration; keep only the scheme and host in source-controlled strings.",
	}
}

func (ConnectionStringRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, connectionPattern, "connection string with embedded password detected")
}

func scanLinesForSecret(unit parser.Unit, pattern *regexp.Regexp, message string) []finding.Finding {
	if unit.Source == "" {
		return nil
	}
	findings := []finding.Finding{}
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		match := pattern.FindString(line)
		if match == "" {
			continue
		}
		findings = append(findings, finding.Finding{
			Message:  message,
			File:     unit.File.Path,
			Location: &finding.Location{Line: lineNumber + 1},
			Metadata: map[string]any{"preview": redact(match)},
		})
	}
	return findings
}
