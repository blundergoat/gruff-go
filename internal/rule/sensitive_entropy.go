// Package rule defines gruff-go's rule registry and analysers.
// This file implements the entropy-based secret detector: it flags long, random-
// looking string tokens that no provider-specific rule already covers.
package rule

import (
	"math"
	"regexp"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// Default thresholds for the high-entropy detector. minLength keeps short tokens
// (which can clear the entropy bar by chance) out, and 4.5 bits/char sits above
// random hex (max 4.0 bits/char, so hex never trips it) and ordinary prose
// (~1-3 bits/char) while still catching random base64/base64url secrets
// (~5-6 bits/char). Both are tunable via rules.sensitive-data.high-entropy-string.
const (
	highEntropyMinLength      = 20
	highEntropyMinBitsPerChar = 4.5
)

// entropyTokenPattern extracts maximal runs of secret-charset characters
// (base64url + base64 + hex alphabet) from a line. Spaces, quotes, and most
// punctuation break a run, so a token here is a single unbroken candidate rather
// than a whole sentence - that is what lets the entropy bar mean something.
var entropyTokenPattern = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{12,}`)

// entropyHexPattern matches an all-hex token. Hex tops out at 4.0 bits/char so it
// cannot reach the default cutoff, but we exclude it explicitly so a lowered
// `entropy` threshold can never turn a checksum or hex id into a "secret".
var entropyHexPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// entropyUUIDPattern matches the canonical 8-4-4-4-12 UUID shape. UUIDs look
// random but are identifiers, not secrets; the dashes survive token extraction
// only when the run includes `-`, so this catches the dashed form.
var entropyUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// entropySRIPattern matches a Subresource-Integrity / digest prefix. These are
// published integrity hashes, not credentials, and appear in lockfiles and HTML.
var entropySRIPattern = regexp.MustCompile(`^sha(256|384|512)-`)

// entropyProviderPatterns are the specific detectors that own their token shape.
// The entropy rule defers to them so one embedded AWS key or JWT is reported once
// by its precise rule, not a second time as a generic high-entropy string - the
// deterministic precedence M30 requires. connectionPattern is omitted: it matches
// a whole URL (broken up by `:`/`@`/`/`) that never survives as one entropy token.
var entropyProviderPatterns = []*regexp.Regexp{
	awsAccessPattern, jwtPattern,
	githubTokenPattern, slackTokenPattern, stripeLiveKeyPattern,
	googleAPIKeyPattern, anthropicAPIKeyPattern, npmTokenPattern, gitLabTokenPattern,
}

// HighEntropyStringRule flags long, high-entropy string tokens that look like
// secrets but match no provider-specific pattern. It is the catch-all for
// rotated, custom, or vendor-less credentials the exact-prefix rules miss.
type HighEntropyStringRule struct {
	// MinLength is the shortest token the rule will score; shorter runs are skipped.
	MinLength int
	// Entropy is the minimum Shannon entropy in bits per character a token must reach to be flagged.
	Entropy float64
}

// minLength returns the effective minimum-length threshold, defaulting when unset.
func (r HighEntropyStringRule) minLength() int {
	if r.MinLength <= 0 {
		return highEntropyMinLength
	}
	return r.MinLength
}

// minEntropy returns the effective bits-per-character threshold, defaulting when unset.
func (r HighEntropyStringRule) minEntropy() float64 {
	if r.Entropy <= 0 {
		return highEntropyMinBitsPerChar
	}
	return r.Entropy
}

// Definition declares the sensitive-data.high-entropy-string rule. It ships
// opt-in (DefaultEnabled:false) and at warning/medium because entropy is a
// heuristic - it cannot prove a token is a live secret the way an exact provider
// prefix can - so it stays out of default scans and below the error tier the
// confirmed-token rules use.
func (r HighEntropyStringRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.high-entropy-string",
		Title:          "High-entropy string",
		Description:    "Flags long, high-entropy string tokens that resemble secrets but match no provider-specific pattern. Opt-in; tune minLength and entropy. Emits only a redacted preview.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Thresholds: map[string]float64{
			"minLength": float64(r.minLength()),
			"entropy":   r.minEntropy(),
		},
		Tags:        []string{"secrets"},
		Remediation: "Confirm whether the value is a secret; if so move it to a secret manager and rotate it. If it is a legitimate constant, raise the entropy/minLength thresholds or add an inline suppression.",
	}
}

// AnalyzeUnit scans code-bearing lines for high-entropy tokens, skipping shapes a
// reviewer would never rotate (hex ids, UUIDs, SRI digests, paths/URLs) and tokens
// a provider-specific rule already owns, then emits a redacted preview for each hit.
func (r HighEntropyStringRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.Source == "" {
		return nil
	}
	minLength := r.minLength()
	minEntropy := r.minEntropy()
	findings := []finding.Finding{}
	inBlockComment := false
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		if !lineIsCodeBearing(line, &inBlockComment) {
			continue
		}
		for _, token := range entropyTokenPattern.FindAllString(line, -1) {
			if !isHighEntropySecretCandidate(token, minLength, minEntropy) {
				continue
			}
			findings = append(findings, finding.Finding{
				Message:  "high-entropy string literal detected",
				File:     unit.File.Path,
				Location: &finding.Location{Line: lineNumber + 1},
				Metadata: map[string]any{
					"preview": redact(token),
					"entropy": math.Round(shannonEntropy(token)*100) / 100,
				},
			})
		}
	}
	return findings
}

// isHighEntropySecretCandidate reports whether a token should be flagged: long
// enough, not an excluded identifier/path/digest shape, not already owned by a
// provider rule, and at or above the entropy bar. The order is cheapest-check-
// first so the entropy computation only runs on tokens that survive the filters.
func isHighEntropySecretCandidate(token string, minLength int, minEntropy float64) bool {
	if len(token) < minLength {
		return false
	}
	if isExcludedEntropyShape(token) {
		return false
	}
	for _, pattern := range entropyProviderPatterns {
		if pattern.MatchString(token) {
			return false
		}
	}
	return shannonEntropy(token) >= minEntropy
}

// isExcludedEntropyShape reports whether a token is a known non-secret shape that
// happens to look random: an all-hex id, a UUID, an SRI/digest, or a path/URL
// fragment. Path and URL fragments are excluded because the base64 alphabet
// overlaps path characters (`/`, `-`, `_`), so a long route or import path would
// otherwise read as high entropy.
func isExcludedEntropyShape(token string) bool {
	if entropyHexPattern.MatchString(token) {
		return true
	}
	if entropyUUIDPattern.MatchString(token) {
		return true
	}
	if entropySRIPattern.MatchString(token) {
		return true
	}
	// A `/` inside the run signals a path or URL fragment rather than a token;
	// real credentials overwhelmingly use the base64url alphabet (`-`,`_`).
	if strings.Contains(token, "/") {
		return true
	}
	return false
}

// shannonEntropy returns the Shannon entropy of s in bits per character: the
// average number of bits needed to encode one character given its frequency
// distribution. A uniformly random base64 string approaches log2(64)=6; repetitive
// or low-alphabet text scores far lower. Empty input is defined as 0.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range counts {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}
