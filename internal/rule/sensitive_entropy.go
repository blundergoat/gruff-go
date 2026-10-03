// Package rule defines gruff-go's rule registry and analysers.
//
// The entropy detector reports long, random-looking values that no provider-specific rule covers.
// Users review each warning at its source location; previews never reveal the matched value.
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

// The defaults keep short values and ordinary prose out of entropy warnings while retaining random-looking base64 values.
// Users can tune both thresholds through rules.sensitive-data.high-entropy-string.
const (
	// All five ports share these defaults; hex stays below the entropy threshold because it cannot exceed 4.0 bits per character.
	highEntropyMinLength      = 32
	highEntropyMinBitsPerChar = 4.2
)

// entropyTokenPattern extracts unbroken base64, base64url or hex values before entropy scoring.
// Spaces, quotes and most punctuation separate candidates so ordinary sentences do not become one possible secret.
var entropyTokenPattern = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{12,}`)

// entropyQuotedCandidatePattern keeps dots inside complete quoted values. Unquoted tokens retain their
// established boundaries, so sentence punctuation and URL fragments do not become larger synthetic values.
var entropyQuotedCandidatePattern = regexp.MustCompile("\"[A-Za-z0-9+/=_.-]{12,}\"|'[A-Za-z0-9+/=_.-]{12,}'|`[A-Za-z0-9+/=_.-]{12,}`|[A-Za-z0-9+/=_-]{12,}")

// entropyHexPattern keeps checksums and hex identifiers quiet even when the user lowers the entropy threshold.
var entropyHexPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// entropyUUIDPattern recognizes complete dashed UUIDs so ordinary object identifiers do not become possible-secret warnings.
var entropyUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// entropySRIPattern matches a Subresource-Integrity / digest prefix. These are
// published integrity hashes, not credentials, and appear in lockfiles and HTML.
var entropySRIPattern = regexp.MustCompile(`^sha(256|384|512)-`)

// entropyProviderPatterns let dedicated detectors report recognized credentials without a duplicate entropy warning.
//
// Connection URLs are excluded from this list because their punctuation breaks them into separate entropy candidates.
var entropyProviderPatterns = []*regexp.Regexp{
	awsAccessPattern, jwtPattern,
	githubTokenPattern, slackTokenPattern, stripeLiveKeyPattern,
	googleAPIKeyPattern, anthropicAPIKeyPattern, npmTokenPattern, gitLabTokenPattern,
}

// HighEntropyStringRule finds possible credentials that provider-specific detectors do not recognize.
//
// Use it to review long, random-looking values in supported source files.
// Warnings remain heuristic, so users confirm the value before rotating or moving it.
type HighEntropyStringRule struct {
	// MinLength is the shortest token the rule will score; shorter runs are skipped.
	MinLength int
	// Entropy is the minimum Shannon entropy in bits per character a token must reach to be flagged.
	Entropy  float64
	previews sensitivePreviewPolicy
}

// minLength returns the effective minimum-length threshold, defaulting when unset.
func (r HighEntropyStringRule) minLength() int {
	// An unset threshold uses the family default rather than making every short literal reportable.
	if r.MinLength <= 0 {
		return highEntropyMinLength
	}
	return r.MinLength
}

// minEntropy returns the effective bits-per-character threshold, defaulting when unset.
func (r HighEntropyStringRule) minEntropy() float64 {
	// An unset threshold uses the family default so ordinary text does not become a secret warning.
	if r.Entropy <= 0 {
		return highEntropyMinBitsPerChar
	}
	return r.Entropy
}

// Definition declares the sensitive-data.high-entropy-string rule.
//
// The enabled rule reports warnings at medium confidence and exposes both thresholds for project tuning.
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

// AnalyzeProject checks reportable files and returns their entropy warnings; an empty result means no candidate qualified.
// Names used in the same Go package stay quiet in doc comments, so a documented function is not mistaken for a credential.
func (r HighEntropyStringRule) AnalyzeProject(units []parser.Unit, context Context) []finding.Finding {
	identifiers := goIdentifiersByDirectory(units)
	findings := []finding.Finding{}
	// Review each selected file while preserving the package context needed to recognize documented identifiers.
	for _, unit := range units {
		// Files withheld by scan policy must not add user-visible findings.
		if context.isReportable(unit.File.Path) {
			findings = append(findings, r.analyzeUnit(unit, identifiers[path.Dir(unit.File.Path)])...)
		}
	}
	return findings
}

// analyzeUnit checks one file after public-shape and provider exclusions, then returns warnings with fixed redaction markers.
// Empty source returns no findings because there is no value for the user to review.
func (r HighEntropyStringRule) analyzeUnit(unit parser.Unit, packageIdentifiers map[string]bool) []finding.Finding {
	// An empty file contains no possible credential to review.
	if unit.Source == "" {
		return nil
	}
	minLength := r.minLength()
	minEntropy := r.minEntropy()
	findings := []finding.Finding{}
	armoured := publicArmourSpans(unit.Source)
	// Each eligible occurrence becomes its own warning so users can locate repeated values independently.
	for _, candidate := range entropyCandidates(unit, packageIdentifiers) {
		// Public armour, a vendor-documented sample and a literal below the entropy bar are not secrets to report.
		if insideSpan(candidate.offset, armoured) || isDocumentedSample(candidate.token) || !isHighEntropySecretCandidate(candidate.token, minLength, minEntropy) {
			continue
		}
		findings = append(findings, finding.Finding{
			Message:  "high-entropy string literal detected",
			File:     unit.File.Path,
			Location: &finding.Location{Line: candidate.line},
			// Reports expose a fixed redaction marker; the value's measured entropy could disclose information about its characters.
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

// Public PEM contents may appear as multiline text or escaped string fragments; normalize their syntax before checking each body line.
var (
	pemBodyLineBreaks = regexp.MustCompile(`\n|\\[nrt]`)
	pemBodyOperators  = regexp.MustCompile(`[ \t\r\f\x0B]+[+.]|[+.][ \t\r\f\x0B]+`)
	pemBodyQuoting    = regexp.MustCompile("[ \\t\\r\\f\\x0B\"'`,;()\\[\\]{}#*\\\\]")
	pemBodyLine       = regexp.MustCompile(`^(?:[A-Za-z0-9+/]+={0,2}|=[A-Za-z0-9+/]{4}|(?:Version|Comment|Hash|Charset|MessageID|Proc-Type|DEK-Info):.*)$`)
)

// publicArmourSpans locates public PEM material that users need not review as an entropy warning.
//
// Only a matching next closing marker and a PEM-shaped body grant the exception; an empty result leaves all source scannable.
func publicArmourSpans(source string) [][2]int {
	spans := [][2]int{}
	// Check each possible block so public certificates can stay quiet without concealing nearby credentials.
	for _, opening := range pemArmourOpening.FindAllStringSubmatchIndex(source, -1) {
		label := source[opening[2]:opening[3]]
		// Private-key material always remains available to the normal secret checks.
		if strings.Contains(label, "PRIVATE") {
			continue
		}
		rest := source[opening[1]:]
		closing := pemArmourMarker.FindStringSubmatchIndex(rest)
		// An absent or mismatched closing marker cannot establish a public block.
		if closing == nil || rest[closing[2]:closing[3]] != "END" || rest[closing[4]:closing[5]] != label {
			continue
		}
		// Marker constants around ordinary code grant no exception; only PEM-shaped contents may skip scanning.
		if isPEMShapedBody(rest[:closing[0]]) {
			spans = append(spans, [2]int{opening[0], opening[1] + closing[1]})
		}
	}
	return spans
}

// isPEMShapedBody accepts only base64, PGP checksums, armour headers or empty lines after stripping string syntax.
// Real and escaped line breaks keep a public header from excusing unrelated code or prose later in the same literal.
func isPEMShapedBody(body string) bool {
	// Each real or escaped body line must qualify; a header cannot vouch for later content in the same literal.
	for _, line := range pemBodyLineBreaks.Split(body, -1) {
		stripped := pemBodyQuoting.ReplaceAllString(pemBodyOperators.ReplaceAllString(line, ""), "")
		// Empty lines carry no value, but any non-PEM text keeps the whole region scannable.
		if stripped != "" && !pemBodyLine.MatchString(stripped) {
			return false
		}
	}
	return true
}

// insideSpan reports whether a byte offset falls inside any of the half-open spans.
func insideSpan(offset int, spans [][2]int) bool {
	// Only positions inside an established public block can skip the normal secret checks.
	for _, span := range spans {
		// The closing boundary is exclusive, preserving a possible secret immediately after the block.
		if offset >= span[0] && offset < span[1] {
			return true
		}
	}
	return false
}

// entropyCandidate carries a value and the source position needed for a possible warning.
//
// Its line tells the user where to review the value.
// Its byte offset lets the detector exclude public PEM material before creating a finding.
type entropyCandidate struct {
	token  string
	line   int
	offset int
}

// entropyCandidates finds values for entropy scoring without mistaking Go identifiers for credentials.
// Files without Go syntax, such as YAML, keep the text scan; no candidates means no possible entropy findings.
func entropyCandidates(unit parser.Unit, packageIdentifiers map[string]bool) []entropyCandidate {
	// Parsed Go syntax separates values from identifiers; files without it retain the text scan.
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
		// Only string literals carry values here; other syntax must not create a possible-secret warning.
		if !ok || literal.Kind != token.STRING {
			return true
		}
		candidates = append(candidates, spanEntropyCandidates(literal.Value, fileSet, literal.Pos(), lineStarts, true)...)
		return true
	})
	return candidates
}

// goCommentEntropyCandidates checks line and block comments while excluding names used by the package's code.
// Trimming token punctuation lets a command example such as -run=TestName document an existing identifier without warning.
func goCommentEntropyCandidates(file *ast.File, fileSet *token.FileSet, packageIdentifiers map[string]bool, lineStarts []int) []entropyCandidate {
	candidates := []entropyCandidate{}
	// Comments can contain committed credentials, so inspect each group alongside the code's literals.
	for _, group := range file.Comments {
		// Each line or block comment has its own source position for an actionable warning.
		for _, comment := range group.List {
			// Check every token; documenting one known identifier cannot hide unrelated text beside it.
			for _, candidate := range spanEntropyCandidates(comment.Text, fileSet, comment.Slash, lineStarts, false) {
				// A name used by the package is documentation context; unknown text remains eligible for scoring.
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
	// Sibling files share the names a user may mention in package documentation.
	for _, unit := range units {
		// A file without Go syntax provides no reliable identifier evidence, but still receives the text scan.
		if unit.AST == nil {
			continue
		}
		directory := path.Dir(unit.File.Path)
		// The first parsed file creates this directory's identifier set; other directories keep separate evidence.
		if byDirectory[directory] == nil {
			byDirectory[directory] = map[string]bool{}
		}
		ast.Inspect(unit.AST, func(node ast.Node) bool {
			// Only actual identifier syntax may excuse an equal token in a doc comment.
			if identifier, ok := node.(*ast.Ident); ok {
				byDirectory[directory][identifier.Name] = true
			}
			return true
		})
	}
	return byDirectory
}

// spanEntropyCandidates locates values within a literal or comment so warnings point to their actual lines.
//
// Source-line offsets account for carriage returns removed by Go parsing; //line directives affect display locations only.
func spanEntropyCandidates(text string, fileSet *token.FileSet, pos token.Pos, lineStarts []int, quotedValues bool) []entropyCandidate {
	reported := fileSet.Position(pos)
	actual := fileSet.PositionFor(pos, false)
	candidates := []entropyCandidate{}
	// Preserve every occurrence's location, including literals and comments spanning multiple lines.
	for _, span := range entropyCandidateSpans(text, quotedValues) {
		newlines := strings.Count(text[:span[0]], "\n")
		offset := actual.Offset + span[0]
		// Later lines need source offsets because Go parsing may have removed carriage returns from the supplied text.
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

// entropyQuotedLiteral consumes each whole string so inner quotes cannot invent a separate public endpoint.
var entropyQuotedLiteral = regexp.MustCompile("\"(?:\\\\[^\\r\\n]|[^\"\\\\\\r\\n])*\"|'(?:\\\\[^\\r\\n]|[^'\\\\\\r\\n])*'|`[^`]*`")

// entropyBareURL consumes a complete reference so trailing URL components cannot hide behind a valid commit prefix.
var entropyBareURL = regexp.MustCompile("(?:^|[\\s(<])(https://[^\\s\\\"'`<>]+)")

// publicEntropyURLSpans locates complete public endpoints and bare commit references before punctuation splitting.
// Empty, escaped or unrecognized values provide no spans and keep their normal entropy checks.
func publicEntropyURLSpans(source string) [][2]int {
	spans := [][2]int{}
	quotedSpans := [][2]int{}
	// Keep enclosing strings separate: a link inside a larger quoted value cannot excuse any of its tokens.
	for _, span := range entropyQuotedLiteral.FindAllStringIndex(source, -1) {
		quotedSpans = append(quotedSpans, [2]int{span[0], span[1]})
		// An escaped quote belongs to an enclosing value and cannot prove a new complete literal.
		if span[0] > 0 && source[span[0]-1] == '\\' {
			continue
		}
		// Only a whole bounded endpoint may keep its exact source tokens out of the user's warnings.
		if isPublicEntropyURL(source[span[0]+1 : span[1]-1]) {
			spans = append(spans, [2]int{span[0], span[1]})
		}
	}
	// For example, a source comment may link to a public commit or the application's portal settings.
	for _, span := range entropyBareURL.FindAllStringSubmatchIndex(source, -1) {
		// Bare references qualify only outside strings and only when every component matches a bounded public route.
		if !insideSpan(span[2], quotedSpans) && (entropyGitHubCommitURL.MatchString(source[span[2]:span[3]]) || entropyEntraApplicationURL.MatchString(source[span[2]:span[3]])) {
			spans = append(spans, [2]int{span[2], span[3]})
		}
	}
	return spans
}

// entropyCandidateSpans preserves complete quoted values so a public prefix cannot hide an opaque suffix.
// Comments retain their token boundaries; only complete proven public references may skip their tokens.
func entropyCandidateSpans(text string, quotedValues bool) [][]int {
	spans := entropyTokenPattern.FindAllStringIndex(text, -1)
	// String-bearing source needs its complete values; prose retains the established punctuation boundaries.
	if quotedValues {
		spans = entropyQuotedCandidatePattern.FindAllStringIndex(text, -1)
	}
	publicURLs := publicEntropyURLSpans(text)
	candidates := make([][]int, 0, len(spans))
	// Remove quote positions while retaining every character that belongs to the scanned value.
	for _, span := range spans {
		// A complete proven URL can contain public identifiers; unrelated tokens still need review.
		if insideSpan(span[0], publicURLs) {
			continue
		}
		// A quoted match includes delimiters that must not affect the value's entropy or source position.
		if quotedValues && strings.ContainsRune("\"'`", rune(text[span[0]])) {
			span[0]++
			span[1]--
		}
		candidates = append(candidates, span)
	}
	return candidates
}

// sourceLineStarts returns the byte offset at which each line of source begins.
func sourceLineStarts(source string) []int {
	starts := []int{0}
	// Track source boundaries so multiline values keep accurate warning locations after parsing.
	for index := 0; index < len(source); index++ {
		// The next character starts a new source line and may hold another part of a reported value.
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
	// Files without Go syntax still receive secret checks on every code-bearing line.
	for lineNumber, line := range strings.Split(source, "\n") {
		// Text comments follow the existing scan policy; executable or data lines remain eligible for findings.
		if lineIsCodeBearing(line, &inBlockComment) {
			// Keep each value separate so a public-looking neighbour cannot affect its warning decision.
			for _, span := range entropyCandidateSpans(line, true) {
				candidates = append(candidates, entropyCandidate{token: line[span[0]:span[1]], line: lineNumber + 1, offset: lineStart + span[0]})
			}
		}
		lineStart += len(line) + 1
	}
	return candidates
}

// isHighEntropySecretCandidate decides whether a value warrants a generic warning after the user's thresholds and public-shape checks.
// Provider-owned values keep their dedicated findings instead of receiving a duplicate entropy warning.
func isHighEntropySecretCandidate(token string, minLength int, minEntropy float64) bool {
	// A value below the user's length threshold does not justify an entropy warning.
	if len(token) < minLength {
		return false
	}
	// Recognizable public values stay quiet so reviewers can focus on unexplained opaque constants.
	if isExcludedEntropyShape(token) {
		return false
	}
	// The family floor keeps digit-free identifiers out of possible-credential warnings.
	if !hasLetterAndDigit(token) {
		return false
	}
	// Dedicated detectors own recognized provider values and can give users more specific remediation.
	for _, pattern := range entropyProviderPatterns {
		// Matching a provider shape prevents a duplicate generic warning without silencing its dedicated rule.
		if pattern.MatchString(token) {
			return false
		}
	}
	return shannonEntropy(token) >= minEntropy
}

// hasLetterAndDigit applies the family floor before a value can become an entropy warning.
// Digit-free identifiers stay quiet even when their varied characters would clear the entropy threshold.
func hasLetterAndDigit(token string) bool {
	hasLetter, hasDigit := false, false
	// Check the complete value; both character classes must occur before the user receives a possible-secret warning.
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

// isExcludedEntropyShape recognizes checksums, UUIDs and complete public formats before they become entropy warnings.
// Names and paths must pass the bounded whole-value checks; a slash or a readable prefix alone grants no exception.
func isExcludedEntropyShape(token string) bool {
	// Hex cannot be distinguished from a checksum here, so it remains quiet at lowered entropy thresholds too.
	if entropyHexPattern.MatchString(token) {
		return true
	}
	// A complete UUID identifies an object rather than establishing credential evidence.
	if entropyUUIDPattern.MatchString(token) {
		return true
	}
	// Published integrity hashes are normal committed metadata, so users need not rotate them as credentials.
	if entropySRIPattern.MatchString(token) {
		return true
	}
	return isPublicEntropyShape(token)
}

// shannonEntropy measures character variation for comparison with the user's entropy threshold.
// Empty text scores zero; repetitive text scores lower than a varied value of the same length.
func shannonEntropy(value string) float64 {
	// Empty text contains no credential material and must not reach the scoring calculation.
	if value == "" {
		return 0
	}
	characterCounts := map[rune]int{}
	// Count each character's frequency so repeated text does not look as random as a varied credential.
	for _, character := range value {
		characterCounts[character]++
	}
	length := float64(len([]rune(value)))
	entropy := 0.0
	// Combine the frequencies into the score used to decide whether the value warrants review.
	for _, count := range characterCounts {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}
