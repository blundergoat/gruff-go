// Package rule defines gruff-go's rule registry and analysers.
//
// This file scans source for embedded credentials before a developer commits or reviews the code.
// Findings use redacted previews so reports and hooks never echo the matched secret.
// Narrow source-proven exceptions keep documented samples and local placeholders out of a developer's warning list.
package rule

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// Regular expressions used by the sensitive-data rules to detect embedded secrets in source.
var (
	privateKeyPattern = regexp.MustCompile(`-----BEGIN[ A-Z]*PRIVATE KEY-----`)
	// ASIA is AWS's prefix for temporary session credentials, and the body is the same fixed shape. Missing it
	// left a live credential unnamed, which is the worse direction for this pillar.
	awsAccessPattern = regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`)
	// A masked key is one whose whole body is a run of X, written to show where a key goes (FAMILY-CONTRACT.md section 5).
	//
	// Only the whole body counts: a real key may contain a run of X, and hiding it would hide a live credential.
	awsMaskedAccessPattern = regexp.MustCompile(`^(?:AKIA|ASIA)X{16}$`)
	// JWT: three base64url segments separated by dots, the first starting with eyJ, the base64 prefix for an opening {".
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`)
	// Database and queue URLs with a raw credential separator; the match keeps any later raw @ up to the next space or quote.
	// splitConnectionCredentials, not this pattern, chooses which @ ends the credential.
	connectionPattern = regexp.MustCompile(`(?i)\b(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp|amqps)://[^\s@"'\x60]+@[^\s"'\x60]+`)
)

// connectionPlaceholderPasswords are common dev/test password tokens treated as non-secrets when the host is a local-development hostname.
//
// Matching is case-insensitive equality against the whole path-unescaped password.
// Mixed credentials that merely contain one of these words remain findings.
//
// password and secret are exact placeholder words, so they are exempt only as whole passwords on local-development hosts.
// A bare placeholder URL such as postgresql://user:password@localhost/dbname is therefore exempt.
// The local-host co-condition still bounds the exemption, so a production DSN whose password happens to be the word stays reported.
var connectionPlaceholderPasswords = []string{
	"change_me", "changeme", "your_password", "your-password", "your-secret",
	"placeholder", "example", "dummy", "fake", "invalid", "pass",
	"password", "secret",
	"dev_password", "test_password", "dev-password", "test-password",
	"dev_password_change_me", "localpass", "localpassword",
}

// connectionPasswordState distinguishes malformed or absent credentials from
// an explicitly empty password and a non-empty embedded password.
type connectionPasswordState uint8

const (
	// connectionPasswordEmpty means the candidate has a username and an explicit empty password.
	// The zero value intentionally represents a missing or malformed tuple.
	connectionPasswordEmpty connectionPasswordState = iota + 1
	// connectionPasswordPresent means the candidate has a username and a non-empty password.
	connectionPasswordPresent
)

// connectionURLParts is the bounded credential and authority result used by the connection-string detector.
//
// host is canonical: lowercase, without brackets, port, or a trailing DNS root dot.
// An empty host, as for a replica-set URI, means the local-development exemption cannot apply.
type connectionURLParts struct {
	password      string
	host          string
	passwordState connectionPasswordState
}

// connectionLocalHosts are hostnames we consider "obviously local development" for the purpose of skipping placeholder credentials.
//
// A placeholder password on any other host, such as a staging name or a private 10.x address, still reports.
var connectionLocalHosts = []string{
	"localhost", "127.0.0.1", "::1", "0.0.0.0", "db", "database", "postgres",
}

// PrivateKeyRule flags PEM-encoded private keys that a developer may have embedded in source or text.
//
// Use it in a scan before review or commit to locate a key that needs removal and rotation.
// Parsed Go marker definitions are checked separately so naming a format does not look like a leak.
type PrivateKeyRule struct{ previews sensitivePreviewPolicy }

// Definition describes the warning and remediation shown when a scan finds a possible embedded private key.
// It returns the sensitive-data.private-key definition at warning severity and high confidence, enabled by default.
func (PrivateKeyRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.private-key",
		Title:          "Embedded private key",
		Description:    "Flags PEM-encoded private keys embedded directly in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Remove the key and load it from a secret manager or environment-specific runtime configuration.",
	}
}

// AnalyzeUnit scans a file for private-key headers and returns redacted warnings for headers that may contain authored key material.
//
// A parser definition or delimiter use is exempt only when the matched Go literal and its native operation can be proven.
// Each header on a code-bearing line of unit that survives the Go syntax and prose exemptions yields a finding with a redacted preview.
func (r PrivateKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, privateKeyPattern, "private key literal detected", r.previews, previewPrivateKey)
}

// AWSAccessKeyRule flags AWS access key identifiers (AKIA... long-term, ASIA... session) embedded in source.
//
// It ships disabled by default, so a user sees these findings only after turning sensitive-data.aws-access-key on.
type AWSAccessKeyRule struct{ previews sensitivePreviewPolicy }

// Definition describes the AWS access-key warning, including both long-term and temporary key prefixes.
// It returns the sensitive-data.aws-access-key definition at warning severity and high confidence, disabled by default.
func (AWSAccessKeyRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.aws-access-key",
		Title:          "AWS access key id",
		Description:    "Flags AWS access key identifiers (AKIA... long-term, ASIA... session) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: false,
		Tags:           []string{"secrets"},
		Remediation:    "Rotate the key, then load credentials from the AWS SDK default provider chain rather than embedding them.",
	}
}

// AnalyzeUnit scans the unit's source for AWS access key identifiers.
//
// It returns one finding per AKIA or ASIA key on a code-bearing line of unit, each carrying a redacted preview instead of the key.
// Keys whose body is all X and vendor-documented samples are skipped, so an empty slice means no live-looking key was found.
func (r AWSAccessKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, awsAccessPattern, "AWS access key id detected", r.previews, previewAWSAccessKey)
}

// JWTTokenRule flags JWT-shaped literals embedded in source files.
//
// It is enabled by default and warns on JWT-shaped literals outside the documented-sample and comment-line exclusions.
type JWTTokenRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.jwt-token rule that flags base64url three-segment JWT literals with warning severity and medium confidence.
// It returns that definition enabled by default, with remediation that moves the token to a secret manager or runtime-only configuration.
func (JWTTokenRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.jwt-token",
		Title:          "JWT token literal",
		Description:    "Flags JWT-shaped literals (three base64url segments separated by dots) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Move the token to a secret manager or runtime-only configuration; never check signed tokens into source control.",
	}
}

// AnalyzeUnit scans the unit's source for JWT-like token literals.
//
// It returns one finding per JWT-shaped match on a code-bearing line of unit, each with a redacted preview, skipping vendor-documented samples.
// An empty slice means no such token was found.
func (r JWTTokenRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, jwtPattern, "JWT-like token literal detected", r.previews, previewJWT)
}

// ConnectionStringRule flags database or queue connection URIs that embed credentials.
//
// It ships disabled; once on, it warns on non-empty passwords in parseable URLs, except local-host placeholders and substitution spellings.
type ConnectionStringRule struct{ previews sensitivePreviewPolicy }

// Definition describes the warning for a database or queue URL with an embedded password.
// It returns the sensitive-data.connection-string definition at warning severity and medium confidence, disabled by default.
func (ConnectionStringRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.connection-string",
		Title:          "Connection string with embedded password",
		Description:    "Flags database/queue connection URLs that embed a username and password in the URI.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: false,
		Tags:           []string{"secrets"},
		Remediation:    "Pull the password from environment-specific runtime configuration; keep only the scheme and host in source-controlled strings.",
	}
}

// AnalyzeUnit scans the unit's source for connection URIs containing embedded passwords.
//
// It skips obvious dev/test placeholder credentials targeting localhost-like hosts, and a runtime substitution such as a format verb.
//
// It returns one finding per URL on a code-bearing line of unit that splitConnectionURL reads as holding a non-empty password.
// Each finding carries only a redacted preview of the URL.
func (r ConnectionStringRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	matches := secretMatchesOnCodeLines(unit, connectionPattern)
	out := make([]finding.Finding, 0, len(matches))
	for _, candidate := range matches {
		parts := splitConnectionURL(candidate.value)
		// A URL with no user:password pair, an empty password such as postgres://app:@db, or an authority that fails to parse is skipped.
		// So a literal password behind an invalid port, such as db:54x2, goes unreported.
		if parts.passwordState != connectionPasswordPresent {
			continue
		}
		// A password spelled as a substitution is skipped whatever the host, so this check sits beside the local-development exemption.
		if isSubstitutionPassword(parts.password) {
			continue
		}
		// A placeholder password on a local host, such as postgres://app:changeme@localhost/db, is sample config rather than a leak.
		if isPlaceholderConnection(parts) {
			continue
		}
		out = append(out, finding.Finding{
			Message:  "connection string with embedded password detected",
			File:     unit.File.Path,
			Location: &finding.Location{Line: candidate.line},
			Metadata: map[string]any{"preview": r.previews.format(unit.File.Path, previewConnectionString, candidate.value)},
		})
	}
	return out
}

// scanLinesForSecret walks the unit source line by line, emitting a finding for each pattern match with preview metadata from the shared policy.
//
// Lines rejected by lineIsCodeBearing are skipped; a closed block comment followed by a line comment remains eligible.
// A suppression comment such as `#nosec` is honoured, and counted, after the rules run (analysis.ApplyInlineSuppressions).
//
// Each finding carries message at its line in unit, and previews formats the matched text for category as the finding's preview.
// It returns an empty, non-nil slice when no eligible line matches pattern.
func scanLinesForSecret(unit parser.Unit, pattern *regexp.Regexp, message string, previews sensitivePreviewPolicy, category sensitivePreviewCategory) []finding.Finding {
	matches := secretMatchesOnCodeLines(unit, pattern)
	findings := make([]finding.Finding, 0, len(matches))
	for _, candidate := range matches {
		findings = append(findings, finding.Finding{
			Message:  message,
			File:     unit.File.Path,
			Location: &finding.Location{Line: candidate.line},
			Metadata: map[string]any{"preview": previews.format(unit.File.Path, category, candidate.value)},
		})
	}
	return findings
}

// secretLineMatch keeps the raw candidate in-memory only while a rule decides
// whether to emit a redacted finding. It is never copied into finding metadata.
type secretLineMatch struct {
	line  int
	value string
}

// secretMatchesOnCodeLines returns every pattern candidate on eligible lines.
//
// Multiple credentials commonly share one config line, so first-match-only scanning can let an innocuous candidate hide a later real secret.
//
// Code-bearing lines of unit are searched for every pattern match; private-key mentions, masked AWS keys, and documented samples are dropped.
// Each kept match records its 1-based line, and the result is nil for an empty source and empty when nothing survives.
func secretMatchesOnCodeLines(unit parser.Unit, pattern *regexp.Regexp) []secretLineMatch {
	if unit.Source == "" {
		return nil
	}
	matches := []secretLineMatch{}
	inBlockComment := false
	sourceOffset := 0
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		lineStart := sourceOffset
		sourceOffset += len(line) + 1
		// Leading // comments and tracked block-only lines are skipped; trailing comment text on an eligible line can still produce findings.
		if !lineIsCodeBearing(line, &inBlockComment) {
			continue
		}
		for _, matchRange := range pattern.FindAllStringIndex(line, -1) {
			match := line[matchRange[0]:matchRange[1]]
			// Recognized non-secret key mentions, fully masked AWS keys, and exact documented samples are excluded from findings.
			if isNonSecretPrivateKeyMention(unit, line, match, lineStart+matchRange[0], lineStart+matchRange[1]) ||
				(pattern == awsAccessPattern && awsMaskedAccessPattern.MatchString(match)) || isDocumentedSample(match) {
				continue
			}
			matches = append(matches, secretLineMatch{line: lineNumber + 1, value: match})
		}
	}
	return matches
}

// documentedSampleDigests are SHA-256 digests of the 20 values vendors publish as documentation samples, so code that pastes one never reports.
//
// They cover AWS and jwt.io examples, fourteen published test cards and Google's reCAPTCHA v2 test site key.
// Digests keep the literals out of this source (FAMILY-CONTRACT.md section 5).
var documentedSampleDigests = map[string]bool{
	"03b970ed8171d73b58bbc9a5c72e3e4eec28503b56b3bb400a0801857dd45614": true,
	"19ff47cc8024c133d5845d3f8938caca289929031e7d508c3adf7adff177f0c2": true,
	"1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3": true,
	"1c9d38ed26cd808fa3b02b9b3b988a7caf474e2e42d95789c0fe07e267c80d8f": true,
	"2f725bbd1f405a1ed0336abaf85ddfeb6902a9984a76fd877c3b5cc3b5085a82": true,
	"304945e91de3deff52a61d08733141d72dd42ec9d47972f1060534d54c0c7f90": true,
	"3a134ef77d4e2e4cdad2d2945ff1f76c1a23296c93c851f6244220a8cedea130": true,
	"477bba133c182267fe5f086924abdc5db71f77bfc27f01f2843f2cdc69d89f05": true,
	"51a4ae4c6ae999146474a67cbcb3b05fbcf4c17ab683043a066459da95513ea8": true,
	"53a8fc816e63b7a5ccd17aaff93f28bcf13abbf418209dcd93947722d7c326ba": true,
	"576c15a8072461c216efb9bd7306a6fc6039b43a6763c4c1a05930a2dd7b788f": true,
	"78314b11be2e581549ac1c4f616563fad3fdf0c3b71678f6e2299182080e0598": true,
	"7f75367e7881255134e1375e723d1dea8ad5f6a4fdb79d938df1f1754a830606": true,
	"9bbef19476623ca56c17da75fd57734dbf82530686043a6e491c6d71befe8f6e": true,
	"c6ea27c534f993d31f0aef882e3d200e7b87470c379ae79c8f9b19d3bd363dc9": true,
	"d79449f462cec9af0d857c3e1af888d4fa8bbdaa511b9eaaafcd2805c4ea6471": true,
	"d8086d483c15c711ebba19f966b97d3c2adcba74025ff8d7e07c3698c9531deb": true,
	"dd13cdf9af9dd3baf46ce96aecd7163cabf381ccb21e63f15f0fa10b1c663fa9": true,
	"e21b597ba6b9cafa59d9ebc4d65c0385f5eb3fa56abab2607fa76589ad849a33": true,
	"f41e7ca4a3d71c4f047581f2ae2d6a8dbb8c58e51a020fa227edc724474aab6e": true,
}

// isDocumentedSample reports whether a matched value is, exactly and whole, a vendor-documented sample such as AWS's example key.
//
// A value that merely contains one is compared whole, so it still reports.
// It hashes matchedValue with SHA-256 and reports true only when the hex digest is in documentedSampleDigests, otherwise false.
func isDocumentedSample(matchedValue string) bool {
	digest := sha256.Sum256([]byte(matchedValue))
	return documentedSampleDigests[hex.EncodeToString(digest[:])]
}

// isNonSecretPrivateKeyMention exempts a matched PEM header used as a recognized prose mention or a supported Go parser marker.
//
// A developer can define a parser pattern without embedding a credential; an unmatched header still needs review.
//
// It reports false unless match is a private-key header.
// When unit is a Go file, the verdict comes from isGoPrivateKeyParserMarker, given the source offsets matchStart and matchEnd.
// Otherwise it reports true only when the trimmed line does not begin with match and a phrase like starts with leads into match.
func isNonSecretPrivateKeyMention(unit parser.Unit, line string, match string, matchStart int, matchEnd int) bool {
	if !privateKeyPattern.MatchString(match) {
		return false
	}
	if unit.File.Type == source.FileTypeGo {
		return isGoPrivateKeyParserMarker(unit, match, matchStart, matchEnd)
	}
	trimmed := strings.TrimSpace(line)
	// A leading header may begin pasted key material, so it keeps its warning even if prose follows.
	if strings.HasPrefix(trimmed, match) {
		return false
	}
	lowerLine := strings.ToLower(trimmed)
	lowerMatch := strings.ToLower(match)
	for _, phrase := range []string{"begins with", "starts with", "starting with"} {
		index := strings.Index(lowerLine, phrase)
		if index < 0 {
			continue
		}
		rest := strings.TrimLeft(lowerLine[index+len(phrase):], " \t`\"'(:")
		if strings.HasPrefix(rest, lowerMatch) {
			return true
		}
	}
	return false
}

// coOccurrenceSecretSpec groups a two-pattern detector and its preview categories.
type coOccurrenceSecretSpec struct {
	primary           *regexp.Regexp
	secondary         *regexp.Regexp
	message           string
	primaryCategory   sensitivePreviewCategory
	secondaryCategory sensitivePreviewCategory
}

// scanUnitForCoOccurrence emits one finding per file when both configured patterns match on code-bearing lines.
//
// The finding is located at the primary marker's line.
// Both matches are formatted independently by the shared preview policy so neither matched value reaches any output format.
//
// The patterns, message, and preview categories come from spec, the source from unit, and previews formats both matches.
// It returns a single finding when both patterns match somewhere on code-bearing lines, and nil when the source is empty or either never matches.
func scanUnitForCoOccurrence(unit parser.Unit, spec coOccurrenceSecretSpec, previews sensitivePreviewPolicy) []finding.Finding {
	if unit.Source == "" {
		return nil
	}
	primaryLine, primaryMatch := firstCodeMatch(unit.Source, spec.primary)
	if primaryLine == 0 {
		return nil
	}
	secondaryLine, secondaryMatch := firstCodeMatch(unit.Source, spec.secondary)
	if secondaryLine == 0 {
		return nil
	}
	return []finding.Finding{{
		Message:  spec.message,
		File:     unit.File.Path,
		Location: &finding.Location{Line: primaryLine},
		Metadata: map[string]any{
			"preview":          previews.format(unit.File.Path, spec.primaryCategory, primaryMatch),
			"secondaryLine":    secondaryLine,
			"secondaryPreview": previews.format(unit.File.Path, spec.secondaryCategory, secondaryMatch),
		},
	}}
}

// firstCodeMatch returns the 1-indexed line and matched substring of the first pattern hit on a code-bearing line; returns (0, "") when none exists.
// Lines of source go through lineIsCodeBearing with one shared block-comment state, and the leftmost pattern hit on the earliest such line wins.
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

// lineIsCodeBearing reports whether a line should be examined for secret patterns, advancing the block-comment state machine.
//
// It skips leading // comments, block-only lines with no trailing text, and lines inside an open block without a closing marker.
// A block opened after code on the same line is not tracked, so the lines inside it are still scanned.
// The block-comment state mutates through the pointer so the caller can walk a file with a single shared boolean.
//
// Callers start with inBlockComment pointing at false; a line starting with /* that does not close it sets it true, and a closing */ resets it.
// A line that closes the block with more text after the marker is not skipped outright; it then gets the same /* and // checks as any line.
// A line that is one closed /* */ comment returns false, but a closed comment followed by a // comment returns true.
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
	return !strings.HasPrefix(trimmed, "//")
}

// isPlaceholderConnection reports true when the URL embeds an obvious dev/test placeholder password and points at a localhost-style host.
//
// Both halves are required so a real production secret that happens to use a placeholder word is not silently swallowed.
//
// The host in parts must equal one of connectionLocalHosts, and its present password, path-unescaped and lowercased, must equal a placeholder.
// Anything else reports false, including a password that fails to unescape or a replica-set URL with no canonical host.
func isPlaceholderConnection(parts connectionURLParts) bool {
	if parts.passwordState != connectionPasswordPresent {
		return false
	}
	if !stringEqualsAny(parts.host, connectionLocalHosts) {
		return false
	}
	password, err := url.PathUnescape(parts.password)
	if err != nil {
		return false
	}
	return stringEqualsAny(strings.ToLower(password), connectionPlaceholderPasswords)
}

// splitConnectionURL extracts a password state and canonical bare host from scheme://user:password@host, with optional port, path, and query.
//
// It deliberately splits at the credential @ chosen by splitConnectionCredentials and at the first credential colon.
// net/url is never asked to reinterpret reserved bytes in the raw password.
//
// It returns the zero value when connStr lacks a scheme separator, a user:password pair with a non-empty user, or a host that net/url can parse.
// Otherwise the result holds the raw password, an empty or present state, and the lowercased host without port or trailing dot.
// A comma-separated replica-set authority that still parses keeps the password and state but leaves host empty, so no local-host exemption applies.
func splitConnectionURL(connStr string) connectionURLParts {
	schemeEnd := strings.Index(connStr, "://")
	if schemeEnd < 0 {
		return connectionURLParts{}
	}
	rest := connStr[schemeEnd+3:]
	credentials, hostSuffix, hasCredentialBoundary := splitConnectionCredentials(rest)
	if !hasCredentialBoundary {
		return connectionURLParts{}
	}
	colonIdx := strings.Index(credentials, ":")
	if colonIdx < 0 {
		return connectionURLParts{}
	}
	if credentials[:colonIdx] == "" {
		return connectionURLParts{}
	}

	password := credentials[colonIdx+1:]
	state := connectionPasswordEmpty
	if password != "" {
		state = connectionPasswordPresent
	}

	authority := connectionAuthority(hostSuffix)
	if authority == "" {
		return connectionURLParts{}
	}
	parsed, err := url.Parse("//" + authority)
	// An authority that does not parse yields no credential at all.
	//
	// Some replica-set URIs land here, because a member written without its own port leaves text after the final colon that is not a valid port.
	// A typo in the port, such as db:54x2, lands here too, and the URL is not reported.
	// Accepting more URI shapes would change which credentials produce warnings, so it needs calibration for this warning-severity rule.
	if err != nil || parsed.User != nil || parsed.Host == "" {
		return connectionURLParts{}
	}
	// A comma-separated authority, such as a replica-set URI listing several hosts, has no single canonical host.
	//
	// net/url folds that into a hostname that is not any of them ("h1:27017,h2:27017" becomes "h1:27017,h2").
	// So the local-development exemption must decline rather than reason about a value that names nothing.
	// Password and state are kept, so this withholds the exemption without changing whether the URI is reported.
	if strings.Contains(authority, ",") {
		return connectionURLParts{password: password, passwordState: state}
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return connectionURLParts{}
	}
	return connectionURLParts{password: password, host: host, passwordState: state}
}

// substitutionPasswordPattern matches a password that is wholly a substitution or documentation placeholder rather than a literal credential.
//
// It covers the four spellings that reach a connection string in practice.
//   - A Go format verb such as %s or %-10s.
//   - A Go or Vault template action such as {{password}}.
//   - A shell or environment expansion such as ${DB_PASS} or $DB_PASS.
//   - A documentation placeholder such as <password>.
//
// The whole component must match. A password that merely contains a brace, such as s3cret{9}, is a real credential and stays reported.
var substitutionPasswordPattern = regexp.MustCompile(
	`^(?:%[-+ #0-9.*]*[a-zA-Z]|\{\{[^{}]*\}\}|\$\{[^{}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^<>]+>)$`)

// isSubstitutionPassword reports whether password matches a supported substitution or documentation placeholder spelling.
//
// A template credential such as postgres://{{username}}:{{password}}@host/db embeds no secret.
// Neither does a DSN built with fmt.Sprintf("postgres://%s:%s@%s", ...).
//
// Matching spellings are skipped even when used literally, such as $ActualPassword; any other password reports false and stays eligible.
func isSubstitutionPassword(password string) bool {
	return substitutionPasswordPattern.MatchString(password)
}

// splitConnectionCredentials picks the @ that ends the credential in scheme-less connection text, without validating it as user information.
//
// Real DSNs embed a raw @ in the password despite RFC 3986, so the split advances while the remaining authority still holds an @, as net/url does.
// Stopping at the first @ would read app:p@ssw0rd@db.prod.example.com/orders as host ssw0rd@db.prod..., dropping a credential that needs review.
//
// Advancing stops at the authority, so a query @ such as ?opts=a@b never replaces an earlier credential separator.
// Without an earlier @, a query @ is still chosen, so postgres://db:5432/orders?opts=a@b reads as user db with a password.
//
// It returns the text of rest before the chosen @ as the credential, the text after it as the host suffix, and true.
// When rest holds no @, it returns two empty strings and false.
func splitConnectionCredentials(rest string) (string, string, bool) {
	for searchOffset := 0; searchOffset <= len(rest); {
		relativeAt := strings.Index(rest[searchOffset:], "@")
		// No separator left means this text carries no embedded credential.
		if relativeAt < 0 {
			return "", "", false
		}
		boundary := searchOffset + relativeAt
		hostSuffix := rest[boundary+1:]
		// A further @ in the authority keeps this earlier @ inside the credential, so a raw @ in the credential does not make the URL unreportable.
		if strings.Contains(connectionAuthority(hostSuffix), "@") {
			searchOffset = boundary + 1
			continue
		}
		return rest[:boundary], hostSuffix, true
	}
	return "", "", false
}

// connectionAuthority trims path, query, and fragment from a host suffix so only the host and optional port remain.
//
// It returns hostSuffix cut before its first slash, question mark, or hash, or hostSuffix unchanged when it has none, so empty input stays empty.
func connectionAuthority(hostSuffix string) string {
	if end := strings.IndexAny(hostSuffix, "/?#"); end >= 0 {
		return hostSuffix[:end]
	}
	return hostSuffix
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
