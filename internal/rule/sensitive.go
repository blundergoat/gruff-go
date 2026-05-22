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

// connectionPlaceholderPasswords are common dev/test password tokens we treat as
// non-secrets when the connection's host is a local-development hostname.
// Match is case-insensitive substring of the password component. Including
// short tokens like "pass" / "invalid" is intentional: localhost-targeted
// passwords containing these substrings are nearly always fixtures, and the
// host co-condition limits the false-positive surface.
var connectionPlaceholderPasswords = []string{
	"change_me", "changeme", "your_password", "your-password", "your-secret",
	"placeholder", "example", "dummy", "fake", "invalid", "pass",
	"dev_password", "test_password", "dev-password", "test-password",
	"localpass", "localpassword",
}

// connectionLocalHosts are hostnames we consider "obviously local development"
// for the purpose of skipping placeholder credentials.
var connectionLocalHosts = []string{
	"localhost", "127.0.0.1", "::1", "0.0.0.0", "db", "database", "postgres",
}

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
		Tags:           []string{"secrets"},
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
		Tags:           []string{"secrets"},
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
		Tags:           []string{"secrets"},
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
		Tags:           []string{"secrets"},
		Remediation:    "Pull the password from environment-specific runtime configuration; keep only the scheme and host in source-controlled strings.",
	}
}

// AnalyzeUnit scans the unit's source for connection URIs containing embedded passwords.
// Skips obvious dev/test placeholder credentials targeting localhost-like hosts.
func (ConnectionStringRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	raw := scanLinesForSecret(unit, connectionPattern, "connection string with embedded password detected")
	if len(raw) == 0 {
		return raw
	}
	lines := strings.Split(unit.Source, "\n")
	out := make([]finding.Finding, 0, len(raw))
	for _, item := range raw {
		if item.Location == nil || item.Location.Line < 1 || item.Location.Line > len(lines) {
			out = append(out, item)
			continue
		}
		match := connectionPattern.FindString(lines[item.Location.Line-1])
		if match != "" && isPlaceholderConnectionString(match) {
			continue
		}
		out = append(out, item)
	}
	return out
}

// scanLinesForSecret walks the unit source line by line, emitting a finding for each pattern match.
// Lines that are entirely Go comments, or that carry a suppression annotation
// (`#nosec`, `//nolint:gosec`, `//nolint:all`), are skipped to keep noise down
// in dev/test fixtures and inline documentation.
func scanLinesForSecret(unit parser.Unit, pattern *regexp.Regexp, message string) []finding.Finding {
	if unit.Source == "" {
		return nil
	}
	findings := []finding.Finding{}
	inBlockComment := false
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		if !lineIsCodeBearing(line, &inBlockComment) {
			continue
		}
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

// scanUnitForCoOccurrence emits one finding per file when both primary and secondary patterns each match on a code-bearing line.
// The finding is located at the primary marker's line. Both matches are
// redacted into the preview metadata so the underlying secret never reaches
// any output format.
func scanUnitForCoOccurrence(unit parser.Unit, primary, secondary *regexp.Regexp, message string) []finding.Finding {
	if unit.Source == "" {
		return nil
	}
	primaryLine, primaryMatch := firstCodeMatch(unit.Source, primary)
	if primaryLine == 0 {
		return nil
	}
	secondaryLine, secondaryMatch := firstCodeMatch(unit.Source, secondary)
	if secondaryLine == 0 {
		return nil
	}
	return []finding.Finding{{
		Message:  message,
		File:     unit.File.Path,
		Location: &finding.Location{Line: primaryLine},
		Metadata: map[string]any{
			"preview":          redact(primaryMatch),
			"secondaryLine":    secondaryLine,
			"secondaryPreview": redact(secondaryMatch),
		},
	}}
}

// firstCodeMatch returns the 1-indexed line and matched substring of the first pattern hit on a code-bearing line; returns (0, "") when none exists.
func firstCodeMatch(source string, pattern *regexp.Regexp) (int, string) {
	inBlockComment := false
	for lineNumber, line := range strings.Split(source, "\n") {
		if !lineIsCodeBearing(line, &inBlockComment) {
			continue
		}
		if match := pattern.FindString(line); match != "" {
			return lineNumber + 1, match
		}
	}
	return 0, ""
}

// lineIsCodeBearing reports whether a line should be examined for secret patterns,
// advancing the block-comment state machine and honoring inline suppression annotations.
// Returns false for comment-only lines, lines inside an unclosed /* */ block, and
// lines carrying #nosec or //nolint:{gosec,all}. The block-comment state mutates
// through the pointer so the caller can walk a file with a single shared boolean.
func lineIsCodeBearing(line string, inBlockComment *bool) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if *inBlockComment {
		if idx := strings.Index(line, "*/"); idx >= 0 {
			*inBlockComment = false
			after := strings.TrimSpace(line[idx+2:])
			if after == "" {
				return false
			}
		} else {
			return false
		}
	}
	if strings.HasPrefix(trimmed, "/*") {
		closeIdx := strings.Index(trimmed[2:], "*/")
		if closeIdx < 0 {
			*inBlockComment = true
			return false
		}
		after := strings.TrimSpace(trimmed[closeIdx+4:])
		if after == "" {
			return false
		}
	}
	if strings.HasPrefix(trimmed, "//") {
		return false
	}
	if hasSecretSuppressionAnnotation(line) {
		return false
	}
	return true
}

// hasSecretSuppressionAnnotation reports whether a source line carries an
// inline suppression marker. gruff-go honors both gosec's `#nosec` form and
// golangci-lint's `//nolint:gosec` / `//nolint:all` forms so authors don't have
// to add a tool-specific annotation just for this scanner.
func hasSecretSuppressionAnnotation(line string) bool {
	if strings.Contains(line, "#nosec") {
		return true
	}
	if !strings.Contains(line, "//nolint") {
		return false
	}
	idx := strings.Index(line, "//nolint")
	rest := line[idx+len("//nolint"):]
	if rest == "" || rest[0] != ':' {
		return false
	}
	rest = rest[1:]
	if i := strings.IndexAny(rest, " \t/"); i >= 0 {
		rest = rest[:i]
	}
	for _, name := range strings.Split(rest, ",") {
		name = strings.TrimSpace(name)
		if name == "gosec" || name == "all" {
			return true
		}
	}
	return false
}

// isPlaceholderConnectionString returns true when the URL embeds an obvious
// dev/test placeholder password AND points at a localhost-style host. Both
// halves are required so we don't silently swallow a real production secret
// that happens to mention a placeholder word.
func isPlaceholderConnectionString(connStr string) bool {
	password, host, ok := splitConnectionURL(connStr)
	if !ok {
		return false
	}
	if !stringEqualsAny(host, connectionLocalHosts) {
		return false
	}
	lowerPass := strings.ToLower(password)
	for _, marker := range connectionPlaceholderPasswords {
		if strings.Contains(lowerPass, marker) {
			return true
		}
	}
	return false
}

// splitConnectionURL extracts the password and bare host out of
// scheme://user:password@host[:port][/path][?query], returning ok=false when
// the URL is malformed.
func splitConnectionURL(connStr string) (password, host string, ok bool) {
	schemeEnd := strings.Index(connStr, "://")
	if schemeEnd < 0 {
		return "", "", false
	}
	rest := connStr[schemeEnd+3:]
	atIdx := strings.LastIndex(rest, "@")
	if atIdx < 0 {
		return "", "", false
	}
	userPass := rest[:atIdx]
	hostPart := rest[atIdx+1:]
	colonIdx := strings.LastIndex(userPass, ":")
	if colonIdx < 0 {
		return "", "", false
	}
	password = userPass[colonIdx+1:]
	host = hostPart
	for _, sep := range []string{":", "/", "?"} {
		if idx := strings.Index(host, sep); idx >= 0 {
			host = host[:idx]
			break
		}
	}
	return password, host, true
}

// stringEqualsAny reports whether value matches any element of options.
func stringEqualsAny(value string, options []string) bool {
	for _, opt := range options {
		if value == opt {
			return true
		}
	}
	return false
}
