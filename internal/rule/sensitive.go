// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements the `sensitive-data.*` rules: the ones that tell a user
// a real credential is sitting in a file they are about to commit. They ship at
// error severity, so a false positive fails the grade and blocks the user's CI
// or agent gate - precision matters more here than anywhere else in the scanner.
//
// Two judgements do most of the work. A finding is redacted before it is shown,
// so no report, dashboard, or JSON payload ever echoes the secret back. And an
// obvious local-development placeholder on an obviously local host is exempted,
// because `postgres://app:placeholder@localhost/dev` in a sample config is not
// a leak. Both halves are required: a placeholder word pointed at a production
// host is still reported.
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
	// A masked key is one whose whole body is a run of X, written to show where a key goes (FAMILY-CONTRACT.md
	// section 5). Only the whole body counts: a real key may contain a run of X, and hiding it would hide a live
	// credential.
	awsMaskedAccessPattern = regexp.MustCompile(`^(?:AKIA|ASIA)X{16}$`)
	// JWT: three base64url segments separated by dots; first starts with `eyJ`
	// (the literal base64 prefix for `{"`).
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`)
	// Database URLs with a raw credential separator. The credential candidate is
	// bounded by the first raw @ so reserved password bytes such as / remain in
	// the candidate without allowing a second raw @ to be reinterpreted.
	connectionPattern = regexp.MustCompile(`(?i)\b(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp|amqps)://[^\s@"'\x60]+@[^\s"'\x60]+`)
)

// connectionPlaceholderPasswords are common dev/test password tokens we treat as
// non-secrets when the connection's host is a local-development hostname.
// Match is case-insensitive equality against the path-unescaped whole password;
// mixed credentials that merely contain one of these words remain findings.
// `password` and `secret` are the bare words themselves, not a prefix test:
// `postgresql://user:password@localhost/dbname` is a fixture in every database
// driver's test suite, and the exact-match switch stopped exempting it. The
// local-host co-condition still bounds the exemption, so a production DSN whose
// password happens to be the word stays reported.
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

// connectionURLParts is the bounded credential/authority result used by the
// connection-string detector. host is canonical: lowercase, without brackets,
// port, or a trailing DNS root dot.
type connectionURLParts struct {
	password      string
	host          string
	passwordState connectionPasswordState
}

// connectionLocalHosts are hostnames we consider "obviously local development"
// for the purpose of skipping placeholder credentials.
var connectionLocalHosts = []string{
	"localhost", "127.0.0.1", "::1", "0.0.0.0", "db", "database", "postgres",
}

// PrivateKeyRule flags PEM-encoded private keys embedded in source or text files.
type PrivateKeyRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.private-key rule that flags PEM-formatted private key headers as critical sensitive-data findings.
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

// AnalyzeUnit scans the unit's source for PEM private-key headers.
func (r PrivateKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, privateKeyPattern, "private key literal detected", r.previews, previewPrivateKey)
}

// AWSAccessKeyRule flags AWS access key identifiers (AKIA... long-term, ASIA... session) embedded in source.
type AWSAccessKeyRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.aws-access-key rule that flags AKIA- and ASIA-prefixed access key identifiers with high severity and high confidence.
func (AWSAccessKeyRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.aws-access-key",
		Title:          "AWS access key id",
		Description:    "Flags AWS access key identifiers (AKIA... long-term, ASIA... session) embedded in source or text files.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Rotate the key, then load credentials from the AWS SDK default provider chain rather than embedding them.",
	}
}

// AnalyzeUnit scans the unit's source for AWS access key identifiers.
func (r AWSAccessKeyRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, awsAccessPattern, "AWS access key id detected", r.previews, previewAWSAccessKey)
}

// JWTTokenRule flags JWT-shaped literals embedded in source files.
type JWTTokenRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.jwt-token rule that flags base64url three-segment JWT literals with high severity and medium confidence.
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
func (r JWTTokenRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return scanLinesForSecret(unit, jwtPattern, "JWT-like token literal detected", r.previews, previewJWT)
}

// ConnectionStringRule flags database or queue connection URIs that embed credentials.
type ConnectionStringRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.connection-string rule that flags database/queue URIs whose user:password credentials are embedded in the URL.
func (ConnectionStringRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.connection-string",
		Title:          "Connection string with embedded password",
		Description:    "Flags database/queue connection URLs that embed a username and password in the URI.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"secrets"},
		Remediation:    "Pull the password from environment-specific runtime configuration; keep only the scheme and host in source-controlled strings.",
	}
}

// AnalyzeUnit scans the unit's source for connection URIs containing embedded passwords.
// Skips obvious dev/test placeholder credentials targeting localhost-like hosts.
func (r ConnectionStringRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	matches := secretMatchesOnCodeLines(unit, connectionPattern)
	out := make([]finding.Finding, 0, len(matches))
	for _, candidate := range matches {
		parts := splitConnectionURL(candidate.value)
		if parts.passwordState != connectionPasswordPresent {
			continue
		}
		// A password supplied at runtime is not an embedded credential, whatever
		// the host is, so this sits alongside the local-development exemption
		// rather than inside it.
		if isSubstitutionPassword(parts.password) {
			continue
		}
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

// scanLinesForSecret walks the unit source line by line, emitting a finding for
// each pattern match with preview metadata supplied by the shared policy.
// Lines that are entirely Go comments, or that carry a suppression annotation
// (`#nosec`, `//nolint:gosec`, `//nolint:all`), are skipped to keep noise down
// in dev/test fixtures and inline documentation.
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
// Multiple credentials commonly share one config line, so first-match-only
// scanning can let an innocuous candidate hide a later real secret.
func secretMatchesOnCodeLines(unit parser.Unit, pattern *regexp.Regexp) []secretLineMatch {
	if unit.Source == "" {
		return nil
	}
	matches := []secretLineMatch{}
	inBlockComment := false
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		if !lineIsCodeBearing(line, &inBlockComment) {
			continue
		}
		for _, match := range pattern.FindAllString(line, -1) {
			// A key header named in prose, a masked AWS key or a vendor-documented sample is not a live credential, so none reports.
			if isNonSecretPrivateKeyMention(unit, line, match) || (pattern == awsAccessPattern && awsMaskedAccessPattern.MatchString(match)) || isDocumentedSample(match) {
				continue
			}
			matches = append(matches, secretLineMatch{line: lineNumber + 1, value: match})
		}
	}
	return matches
}

// documentedSampleDigests are SHA-256 digests of the 19 values vendors publish as documentation samples, so code that pastes one never reports.
//
// They are AWS's example access key ids and secret keys, the jwt.io sample token and fourteen published test card numbers.
// Digests keep the literals out of this source (FAMILY-CONTRACT.md section 5).
var documentedSampleDigests = map[string]bool{
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
// A value that merely contains one is compared whole, so it still reports.
func isDocumentedSample(matchedValue string) bool {
	digest := sha256.Sum256([]byte(matchedValue))
	return documentedSampleDigests[hex.EncodeToString(digest[:])]
}

// isNonSecretPrivateKeyMention accepts narrow documentation prose and delimiter
// manipulation that name a private-key header without embedding key material.
func isNonSecretPrivateKeyMention(unit parser.Unit, line string, match string) bool {
	if !privateKeyPattern.MatchString(match) {
		return false
	}
	if unit.File.Type == source.FileTypeGo {
		return isGoPrivateKeyDelimiterUse(line, match)
	}
	trimmed := strings.TrimSpace(line)
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

// pemKeyBodyPattern matches a run of base64 characters long enough to be real
// PEM key material, distinguishing an embedded key literal from a line that
// merely names the delimiter for stripping (a bare `-----BEGIN ...-----` string
// has no such run).
var pemKeyBodyPattern = regexp.MustCompile(`[A-Za-z0-9+/]{40,}`)

// isGoPrivateKeyDelimiterUse reports common code paths that strip or re-wrap a
// caller-provided PEM key using header/footer delimiter strings. These lines
// name the delimiter but do not contain a private key. A line that also carries
// inline key material (a long base64 run) is a real embedded key and is never
// suppressed here, so committed single-line PEM literals still flag.
func isGoPrivateKeyDelimiterUse(line string, match string) bool {
	if index := strings.Index(line, match); index >= 0 {
		before, after := line[:index], line[index+len(match):]
		// Delimiter that opens an unclosed raw-string literal: the key body runs
		// onto following lines, so this is a real multiline embedded key, not a
		// delimiter passed to a strip helper.
		if strings.Count(before, "`")%2 == 1 && !strings.Contains(after, "`") {
			return false
		}
	}
	// Inline key body on the same line is a real single-line embedded key.
	if pemKeyBodyPattern.MatchString(line) {
		return false
	}
	if strings.Contains(line, "ReplaceAll(") || strings.Contains(line, "TrimPrefix(") || strings.Contains(line, "TrimSuffix(") {
		return true
	}
	return strings.Contains(line, match+`\\n" +`) || strings.Contains(line, match+`\n" +`)
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
// The finding is located at the primary marker's line. Both matches are
// formatted independently by the shared preview policy so neither matched value
// reaches any output format.
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

// isPlaceholderConnection returns true when the URL embeds an obvious
// dev/test placeholder password AND points at a localhost-style host. Both
// halves are required so we don't silently swallow a real production secret
// that happens to mention a placeholder word.
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

// splitConnectionURL extracts a password state and canonical bare host from
// scheme://user:password@host[:port][/path][?query]. It deliberately splits at
// the first raw @ and first credential colon instead of asking net/url to
// reinterpret reserved bytes in the raw password.
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
	// An authority that does not parse yields no credential at all. Some
	// replica-set URIs land here, because a member written without its own port
	// leaves text after the final colon that is not a valid port. Widening this
	// is deliberately out of scope: which URIs get reported is a calibration
	// decision for an error-severity rule, not a side effect of the host fix.
	if err != nil || parsed.User != nil || parsed.Host == "" {
		return connectionURLParts{}
	}
	// The user pasted a MongoDB replica-set URI, whose authority lists several
	// hosts separated by commas. net/url folds that into a hostname that is not
	// any of them ("h1:27017,h2:27017" becomes "h1:27017,h2"). No host is
	// canonical, so the local-development exemption must decline rather than
	// reason about a value that names nothing. Password and state are kept, so
	// this withholds the exemption without changing whether the URI is reported.
	if strings.Contains(authority, ",") {
		return connectionURLParts{password: password, passwordState: state}
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return connectionURLParts{}
	}
	return connectionURLParts{password: password, host: host, passwordState: state}
}

// substitutionPasswordPattern matches a password component that is entirely a
// runtime substitution rather than a literal credential. It covers the four
// spellings that reach a connection string in practice: a Go format verb
// (`%s`, `%-10s`), a Go or Vault template action (`{{password}}`), a shell or
// environment expansion (`${DB_PASS}`, `$DB_PASS`), and a documentation
// placeholder (`<password>`).
//
// The whole component must match. A password that merely contains a brace, such
// as `s3cret{9}`, is a real credential and stays reported.
var substitutionPasswordPattern = regexp.MustCompile(
	`^(?:%[-+ #0-9.*]*[a-zA-Z]|\{\{[^{}]*\}\}|\$\{[^{}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^<>]+>)$`)

// isSubstitutionPassword reports whether the password is a placeholder the
// program fills in at run time.
//
// Vault and every database-secrets engine spell their dynamic credentials
// `postgres://{{username}}:{{password}}@host/db`, and Go code builds DSNs with
// `fmt.Sprintf("postgres://%s:%s@%s", ...)`. Neither embeds a secret. Reporting
// them put an error-severity finding on the most common connection-string idiom
// in the ecosystem, which fails a default CI gate on correct code.
func isSubstitutionPassword(password string) bool {
	return substitutionPasswordPattern.MatchString(password)
}

// splitConnectionCredentials divides scheme-less connection text at the `@` that
// really separates the credential from the host.
//
// RFC 3986 reserves `@` for that boundary and requires a password to encode its
// own, but real DSNs embed a raw one anyway. Stopping at the first `@` reads
// `app:p@ssw0rd@db.prod.example.com/orders` as the host `ssw0rd@db.prod...`,
// which is not a host at all - the whole URI was then dropped and a live
// production credential went unreported by an error-severity rule. So the split
// advances while the remaining authority still holds an `@`, which is the same
// direction net/url resolves the ambiguity.
//
// Advancing stops at the authority rather than running to the last `@` in the
// string: a query such as `?opts=a@b` must not be mistaken for the boundary and
// hand the caller a host of `b`, which would silently void the local-development
// exemption for a legitimate localhost DSN.
func splitConnectionCredentials(rest string) (string, string, bool) {
	for searchOffset := 0; searchOffset <= len(rest); {
		relativeAt := strings.Index(rest[searchOffset:], "@")
		// No separator left means this text carries no embedded credential.
		if relativeAt < 0 {
			return "", "", false
		}
		boundary := searchOffset + relativeAt
		hostSuffix := rest[boundary+1:]
		// A further `@` inside the authority proves this one belonged to the
		// password, so keep walking instead of declaring the URI malformed.
		if strings.Contains(connectionAuthority(hostSuffix), "@") {
			searchOffset = boundary + 1
			continue
		}
		return rest[:boundary], hostSuffix, true
	}
	return "", "", false
}

// connectionAuthority trims path, query, and fragment from a host suffix so only
// the host and optional port remain.
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
