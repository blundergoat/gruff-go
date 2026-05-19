// Package rule defines gruff-go's rule registry and analysers.
// This file implements the sensitive-data.* rules that scan for embedded secrets.
package rule

import (
	"regexp"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// Regular expressions used by the sensitive-data rules to detect embedded secrets in source.
var (
	privateKeyPattern = regexp.MustCompile(`-----BEGIN[ A-Z]*PRIVATE KEY-----`)
	awsAccessPattern  = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	// JWT: three base64url segments separated by dots; first starts with `eyJ`
	// (the literal base64 prefix for `{"`).
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`)
	// Database URLs with embedded passwords: scheme://user:password@host
	connectionPattern = regexp.MustCompile(`(?i)\b(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp|amqps)://[^:\s/@]+:[^@\s/]+@[^\s]+`)
)

// PrivateKeyRule flags PEM-encoded private keys embedded in source or text files.
type PrivateKeyRule struct{}

// Definition declares the sensitive-data.private-key rule that flags PEM-formatted private key headers as critical sensitive-data findings.
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

// AnalyzeUnit scans the unit's source for PEM private-key headers.
func (PrivateKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, privateKeyPattern, "private key literal detected")
}

// AWSAccessKeyRule flags AWS access key identifiers (AKIA...) embedded in source.
type AWSAccessKeyRule struct{}

// Definition declares the sensitive-data.aws-access-key rule that flags AKIA-prefixed access key identifiers with high severity and high confidence.
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

// AnalyzeUnit scans the unit's source for AWS access key identifiers.
func (AWSAccessKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, awsAccessPattern, "AWS access key id detected")
}

// JWTTokenRule flags JWT-shaped literals embedded in source files.
type JWTTokenRule struct{}

// Definition declares the sensitive-data.jwt-token rule that flags base64url three-segment JWT literals with high severity and medium confidence.
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

// AnalyzeUnit scans the unit's source for JWT-like token literals.
func (JWTTokenRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, jwtPattern, "JWT-like token literal detected")
}

// ConnectionStringRule flags database or queue connection URIs that embed credentials.
type ConnectionStringRule struct{}

// Definition declares the sensitive-data.connection-string rule that flags database/queue URIs whose user:password credentials are embedded in the URL.
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

// AnalyzeUnit scans the unit's source for connection URIs containing embedded passwords.
func (ConnectionStringRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, connectionPattern, "connection string with embedded password detected")
}

// scanLinesForSecret walks the unit source line by line, emitting a finding for each pattern match.
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
