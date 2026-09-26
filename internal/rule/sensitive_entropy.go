// Package rule defines gruff-go's rule registry and analysers.
// This file implements the entropy-based secret detector: it flags long, random-
// looking string tokens that no provider-specific rule already covers.
package rule

import (
	"go/ast"
	"go/token"
	"math"
	"path"
	"regexp"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// Default thresholds for the high-entropy detector. minLength keeps short tokens
// (which can clear the entropy bar by chance) out, and 4.2 bits/char sits above
// random hex (max 4.0 bits/char, so hex never trips it) and ordinary prose
// (~1-3 bits/char) while still catching random base64/base64url secrets
// (~5-6 bits/char). Both are tunable via rules.sensitive-data.high-entropy-string.
const (
	// Ratified by the operator on 2026-09-02 as one contract for all five ports: 32 characters
	// and 4.2 bits per character. go shipped 20 and 4.5, which meant the same rule id carried a
	// different bar in every port. 4.2 still sits above random hex, which caps at 4.0.
	highEntropyMinLength      = 32
	highEntropyMinBitsPerChar = 4.2
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
	Entropy  float64
	previews sensitivePreviewPolicy
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

// Definition declares the sensitive-data.high-entropy-string rule.
//
// It ships enabled at warning severity and medium confidence, the contract the operator
// ratified on 2026-09-02 for all five ports. Entropy is a heuristic and cannot prove a token is
// a live secret the way an exact provider prefix can, so it stays below the error tier the
// confirmed-token rules use; but a secret scanner that is off by default finds no secrets, which
// is why it is no longer opt-in.
func (r HighEntropyStringRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.high-entropy-string",
		Title:          "High-entropy string",
		Description:    "Flags long, high-entropy string tokens that resemble secrets but match no provider-specific pattern. Tune minLength and entropy. Emits only a redacted preview.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Thresholds: map[string]float64{
			"minLength": float64(r.minLength()),
			"entropy":   r.minEntropy(),
		},
		Tags:        []string{"secrets"},
		Remediation: "Confirm whether the value is a secret; if so move it to a secret manager and rotate it. If it is a legitimate constant, raise the entropy/minLength thresholds or add an inline suppression.",
	}
}

// AnalyzeProject scores every reportable unit. It is package-scoped because a comment token is
// skipped when the Go code in its directory uses the same name as an identifier: a doc comment
// opens with the name it documents, and a long test name is as random-looking as a key.
func (r HighEntropyStringRule) AnalyzeProject(units []parser.Unit, context Context) []finding.Finding {
	identifiers := goIdentifiersByDirectory(units)
	findings := []finding.Finding{}
	for _, unit := range units {
		if context.isReportable(unit.File.Path) {
			findings = append(findings, r.analyzeUnit(unit, identifiers[path.Dir(unit.File.Path)])...)
		}
	}
	return findings
}

// analyzeUnit scores one unit's candidate tokens for high entropy, skipping shapes a reviewer
// would never rotate (hex ids, UUIDs, SRI digests, paths/URLs) and tokens a
// provider-specific rule already owns, then emits a policy-masked preview for each hit.
func (r HighEntropyStringRule) analyzeUnit(unit parser.Unit, packageIdentifiers map[string]bool) []finding.Finding {
	if unit.Source == "" {
		return nil
	}
	minLength := r.minLength()
	minEntropy := r.minEntropy()
	findings := []finding.Finding{}
	armoured := publicArmourSpans(unit.Source)
	for _, candidate := range entropyCandidates(unit, packageIdentifiers) {
		if insideSpan(candidate.offset, armoured) || !isHighEntropySecretCandidate(candidate.token, minLength, minEntropy) {
			continue
		}
		findings = append(findings, finding.Finding{
			Message:  "high-entropy string literal detected",
			File:     unit.File.Path,
			Location: &finding.Location{Line: candidate.line},
			// The configured thresholds already tell a reviewer why this fired; the token's own
			// entropy is a statistic computed from the matched characters and is forbidden in
			// serialized output by FAMILY-CONTRACT section 5.
			Metadata: map[string]any{
				"preview": r.previews.format(unit.File.Path, previewEntropy, candidate.token),
			},
		})
	}
	return findings
}

// pemArmourOpening matches the opening marker of a PEM block and captures its label.
var pemArmourOpening = regexp.MustCompile(`-----BEGIN ([A-Z0-9 ]+)-----`)

// pemArmourMarker matches any opening or closing marker, so a block can end only at the next one.
var pemArmourMarker = regexp.MustCompile(`-----(BEGIN|END) ([A-Z0-9 ]+)-----`)

// A PEM body's lines break at real line breaks and at the escaped ones a string literal spells. Each line then
// loses its concatenation operators, and its quotes, commas, brackets, comment stars and ASCII whitespace, before
// pemBodyLine judges what is left.
var (
	pemBodyLineBreaks = regexp.MustCompile(`\n|\\[nrt]`)
	pemBodyOperators  = regexp.MustCompile(`[ \t\r\f\x0B]+[+.]|[+.][ \t\r\f\x0B]+`)
	pemBodyQuoting    = regexp.MustCompile("[ \\t\\r\\f\\x0B\"'`,;()\\[\\]{}#*\\\\]")
	pemBodyLine       = regexp.MustCompile(`^(?:[A-Za-z0-9+/]+={0,2}|=[A-Za-z0-9+/]{4}|(?:Version|Comment|Hash|Charset|MessageID|Proc-Type|DEK-Info):.*)$`)
)

// publicArmourSpans returns the byte spans of the PEM blocks whose label names no private key. A certificate,
// public key, certificate request, PKCS7 bundle or CRL is public by construction, so its body is never a secret.
// A block ends at the next marker, which must close the same label, and its body must be PEM-shaped. Anything
// else means the markers are not a block, so nothing between them is exempted and a private key there stays
// scannable (FAMILY-CONTRACT section 12).
func publicArmourSpans(source string) [][2]int {
	spans := [][2]int{}
	for _, opening := range pemArmourOpening.FindAllStringSubmatchIndex(source, -1) {
		label := source[opening[2]:opening[3]]
		if strings.Contains(label, "PRIVATE") {
			continue
		}
		rest := source[opening[1]:]
		closing := pemArmourMarker.FindStringSubmatchIndex(rest)
		if closing == nil || rest[closing[2]:closing[3]] != "END" || rest[closing[4]:closing[5]] != label {
			continue
		}
		if isPEMShapedBody(rest[:closing[0]]) {
			spans = append(spans, [2]int{opening[0], opening[1] + closing[1]})
		}
	}
	return spans
}

// isPEMShapedBody reports whether every line between two markers, once its string quoting is stripped, is
// base64, a PGP checksum, an armour header or empty. Code, a placeholder or prose between the markers is not.
// Splitting at escaped line breaks too keeps a one-line block's header from vouching for the rest of the line.
func isPEMShapedBody(body string) bool {
	for _, line := range pemBodyLineBreaks.Split(body, -1) {
		stripped := pemBodyQuoting.ReplaceAllString(pemBodyOperators.ReplaceAllString(line, ""), "")
		if stripped != "" && !pemBodyLine.MatchString(stripped) {
			return false
		}
	}
	return true
}

// insideSpan reports whether a byte offset falls inside any of the half-open spans.
func insideSpan(offset int, spans [][2]int) bool {
	for _, span := range spans {
		if offset >= span[0] && offset < span[1] {
			return true
		}
	}
	return false
}

// entropyCandidate is one token the rule may score: the 1-based line it is reported on, and its byte offset in
// the unit's source, which places it against a PEM block's markers.
type entropyCandidate struct {
	token  string
	line   int
	offset int
}

// entropyCandidates returns the tokens worth scoring in a unit.
//
// In parsed Go source only a string literal or a comment can hold a secret, so identifiers are
// never scored: a long test or function name is as random-looking as a key and is not one. A file
// with no syntax tree, such as a .env or YAML file whose values are unquoted, keeps the line scan.
func entropyCandidates(unit parser.Unit, packageIdentifiers map[string]bool) []entropyCandidate {
	if unit.AST != nil && unit.FileSet != nil {
		lineStarts := sourceLineStarts(unit.Source)
		return append(goLiteralEntropyCandidates(unit.AST, unit.FileSet, lineStarts), goCommentEntropyCandidates(unit.AST, unit.FileSet, packageIdentifiers, lineStarts)...)
	}
	return lineEntropyCandidates(unit.Source)
}

// goLiteralEntropyCandidates tokenises every string literal in a Go file, interpreted or raw.
func goLiteralEntropyCandidates(file *ast.File, fileSet *token.FileSet, lineStarts []int) []entropyCandidate {
	candidates := []entropyCandidate{}
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		candidates = append(candidates, spanEntropyCandidates(literal.Value, fileSet, literal.Pos(), lineStarts)...)
		return true
	})
	return candidates
}

// goCommentEntropyCandidates tokenises every comment in a Go file, line and block alike, and drops
// a token the package's code uses as an identifier. Punctuation the token pattern admits, such as
// the = of `-run=TestName`, is trimmed from its ends before the lookup.
func goCommentEntropyCandidates(file *ast.File, fileSet *token.FileSet, packageIdentifiers map[string]bool, lineStarts []int) []entropyCandidate {
	candidates := []entropyCandidate{}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			for _, candidate := range spanEntropyCandidates(comment.Text, fileSet, comment.Slash, lineStarts) {
				if !packageIdentifiers[strings.Trim(candidate.token, "_-=+")] {
					candidates = append(candidates, candidate)
				}
			}
		}
	}
	return candidates
}

// goIdentifiersByDirectory collects every identifier the Go code in each directory uses. A package's
// files share a directory, and an external _test package beside them documents the same names.
func goIdentifiersByDirectory(units []parser.Unit) map[string]map[string]bool {
	byDirectory := map[string]map[string]bool{}
	for _, unit := range units {
		if unit.AST == nil {
			continue
		}
		directory := path.Dir(unit.File.Path)
		if byDirectory[directory] == nil {
			byDirectory[directory] = map[string]bool{}
		}
		ast.Inspect(unit.AST, func(node ast.Node) bool {
			if identifier, ok := node.(*ast.Ident); ok {
				byDirectory[directory][identifier.Name] = true
			}
			return true
		})
	}
	return byDirectory
}

// spanEntropyCandidates tokenises one literal or comment that begins at pos. Either can span lines, so each
// token is placed on the line it actually occupies. A token past the first line takes its offset from that
// line's start in the source, because go/scanner drops a CRLF raw string's or block comment's carriage returns
// from the text, and the unadjusted position keeps a //line directive out of the arithmetic.
func spanEntropyCandidates(text string, fileSet *token.FileSet, pos token.Pos, lineStarts []int) []entropyCandidate {
	reported := fileSet.Position(pos)
	actual := fileSet.PositionFor(pos, false)
	candidates := []entropyCandidate{}
	for _, span := range entropyTokenPattern.FindAllStringIndex(text, -1) {
		newlines := strings.Count(text[:span[0]], "\n")
		offset := actual.Offset + span[0]
		if sourceLine := actual.Line - 1 + newlines; newlines > 0 && sourceLine < len(lineStarts) {
			offset = lineStarts[sourceLine] + span[0] - strings.LastIndex(text[:span[0]], "\n") - 1
		}
		candidates = append(candidates, entropyCandidate{
			token:  text[span[0]:span[1]],
			line:   reported.Line + newlines,
			offset: offset,
		})
	}
	return candidates
}

// sourceLineStarts returns the byte offset at which each line of source begins.
func sourceLineStarts(source string) []int {
	starts := []int{0}
	for index := 0; index < len(source); index++ {
		if source[index] == '\n' {
			starts = append(starts, index+1)
		}
	}
	return starts
}

// lineEntropyCandidates tokenises every code-bearing line of a file that has no syntax tree.
func lineEntropyCandidates(source string) []entropyCandidate {
	candidates := []entropyCandidate{}
	inBlockComment := false
	lineStart := 0
	for lineNumber, line := range strings.Split(source, "\n") {
		if lineIsCodeBearing(line, &inBlockComment) {
			for _, span := range entropyTokenPattern.FindAllStringIndex(line, -1) {
				candidates = append(candidates, entropyCandidate{token: line[span[0]:span[1]], line: lineNumber + 1, offset: lineStart + span[0]})
			}
		}
		lineStart += len(line) + 1
	}
	return candidates
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
	if !hasLetterAndDigit(token) {
		return false
	}
	for _, pattern := range entropyProviderPatterns {
		if pattern.MatchString(token) {
			return false
		}
	}
	return shannonEntropy(token) >= minEntropy
}

// hasLetterAndDigit reports whether a token carries at least one letter and one digit, the floor FAMILY-CONTRACT
// section 12 sets. Without both it is not credential-shaped: a run of one character class clears the entropy bar by
// construction (prometheus's random-letter series test data alone raised 36,962 findings, and MIME types read the
// same way), and a digit-free mix of cases is an identifier.
func hasLetterAndDigit(token string) bool {
	hasLetter, hasDigit := false, false
	for _, character := range token {
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z':
			hasLetter = true
		case character >= '0' && character <= '9':
			hasDigit = true
		}
	}
	return hasLetter && hasDigit
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
