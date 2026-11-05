// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds the sensitive-data.pii-pattern detector: emails, phone numbers and Luhn-valid payment card numbers in source or text files.
// The rule is opt-in, so a scan reports these findings only once the user enables it.
package rule

import (
	"regexp"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// PII candidate patterns, each deliberately shape-specific so the detector keys on structure, not context.
//
// The redacted preview marker each finding carries keeps the raw matched value out of every output path.
var (
	// piiEmailPattern matches a conventional addr-spec. The TLD floor of 2 keeps
	// it from firing on `a@b` style fragments.
	piiEmailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	// piiPhonePattern matches NANP or E.164-style numbers whose groups are split by spaces, dots or dashes, with an optional + country code.
	//
	// The area code may also sit in parens.
	// Requiring separators is the false-positive guard: a bare 10-digit run is far more often an id, timestamp or amount than a phone number.
	piiPhonePattern = regexp.MustCompile(`(?:\+\d{1,3}[ .\-]?)?(?:\(\d{3}\)[ .\-]?|\d{3}[ .\-])\d{3}[ .\-]\d{4}\b`)
	// piiCardPattern matches a 13-19 digit run with an optional space or dash after each digit, the shape of a payment card.
	//
	// Luhn validation in isLuhnValid is what makes a match high-signal rather than any long number.
	piiCardPattern = regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)
)

// piiExampleEmailDomains are documentation and test domains, reserved by RFC 2606 or common in fixtures.
//
// An address at one of these is treated as a placeholder and never becomes an email finding.
var piiExampleEmailDomains = []string{
	"example.com", "example.org", "example.net", "example.edu",
	"test.com", "test", "localhost", "invalid", "email.com", "domain.com",
}

// piiExampleEmailLocals are local parts that signal a placeholder whatever the domain, such as you@your-company.com or noreply@ addresses.
//
// The whole lowercased local part must match, so user@ is skipped while users@ at a real domain still reports.
var piiExampleEmailLocals = []string{
	"you", "your", "user", "username", "example", "test", "noreply", "no-reply",
	"someone", "name", "email", "foo", "bar",
}

// PIIPatternRule flags personally identifiable information in source or text: email addresses, phone numbers and payment card numbers.
//
// It is the PII half of the PII/PHI split.
// Government and health identifiers such as SSN, MRN and Medicare belong to PHIPatternRule, so an SSN is never counted by both.
type PIIPatternRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.pii-pattern rule.
//
// It is opt-in and warning/medium because emails and phone-shaped numbers are common in legitimate code, like author contacts and sample data.
// Once enabled, its findings are warnings, below the error tier kept for confirmed credentials, unless config overrides the severity.
//
// It returns a fully populated Definition: ID sensitive-data.pii-pattern, warning severity, medium confidence, and DefaultEnabled false.
func (PIIPatternRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.pii-pattern",
		Title:          "PII pattern",
		Description:    "Flags personally identifiable information (email addresses, phone numbers, and Luhn-valid payment card numbers) embedded in source or text files. Opt-in; emits only a redacted preview. Government/health identifiers are covered by sensitive-data.phi-pattern.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Tags:           []string{"secrets", "pii"},
		Remediation:    "Remove the identifier from source; use synthetic fixture data or load real values from runtime configuration. Mask or tokenise PII before it reaches logs or reports.",
	}
}

// AnalyzeUnit scans one file's code-bearing lines for email, phone and payment-card shapes once a user enables sensitive-data.pii-pattern.
//
// It skips placeholder addresses, documented sample cards and card-shaped numbers that fail Luhn.
// It emits at most one policy-masked finding per category on each line.
//
// It numbers lines of the unit from 1 and labels every finding with the unit file path.
// It returns the findings in line order, nil when the unit has no source, and an empty slice when no code-bearing line holds a reportable match.
func (r PIIPatternRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.Source == "" {
		return nil
	}
	findings := []finding.Finding{}
	inBlockComment := false
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		if !lineIsCodeBearing(line, &inBlockComment) {
			continue
		}
		findings = append(findings, piiLineFindings(unit.File.Path, line, lineNumber+1, r.previews)...)
	}
	return findings
}

// piiLineFindings returns the PII findings for a single line, at most one per category.
//
// Categories are checked independently, so an email and a phone on the same line both surface.
// Each finding records its category and redacted preview marker, never the raw value.
//
// Here path and lineNumber locate each finding, line is the text scanned, and previews formats each preview marker.
// A line with no reportable match gives an empty non-nil slice.
//
// Only the leftmost email and phone matches are checked, so a placeholder address hides a later real one on the same line.
// Card candidates skip documented samples; the first remaining one decides, so a Luhn-invalid candidate hides any later valid card.
func piiLineFindings(path, line string, lineNumber int, previews sensitivePreviewPolicy) []finding.Finding {
	out := []finding.Finding{}
	if email := piiEmailPattern.FindString(line); email != "" && !isPlaceholderEmail(email) {
		out = append(out, piiFinding(path, lineNumber, "email", email, previews))
	}
	if phone := piiPhonePattern.FindString(line); phone != "" {
		out = append(out, piiFinding(path, lineNumber, "phone", strings.TrimSpace(phone), previews))
	}
	// After documented samples are skipped, the first remaining card-shaped number decides whether the line reports a payment-card finding.
	// A card network's published test number is a documented sample, compared as digits so `4111-...` and `4111 ...` match.
	for _, card := range piiCardPattern.FindAllString(line, -1) {
		// A documented test card is stepped over, so it never hides the real card after it.
		if isDocumentedSample(cardDigits(card)) {
			continue
		}
		// Only a Luhn-valid number reports; either way this number decides the line.
		if isLuhnValid(card) {
			out = append(out, piiFinding(path, lineNumber, "payment-card", card, previews))
		}
		break
	}
	return out
}

// piiFinding builds one redacted PII finding tagged with its category.
//
// It returns a Finding at path and lineNumber with RuleID unset, a message naming category, and Metadata holding category and the preview marker.
// The raw matched value and path go to previews, but neither affects the marker, which depends only on the preview class mapped from category.
func piiFinding(path string, lineNumber int, category, raw string, previews sensitivePreviewPolicy) finding.Finding {
	return finding.Finding{
		Message:  category + " PII detected",
		File:     path,
		Location: &finding.Location{Line: lineNumber},
		Metadata: map[string]any{
			"preview":  previews.format(path, personalDataPreviewCategory(category), raw),
			"category": category,
		},
	}
}

// isPlaceholderEmail reports whether an address is an obvious documentation or fixture placeholder that should never become an email finding.
//
// An RFC 2606 example domain or a generic local part qualifies, so you@example.com in a README or test never reads as exposed PII.
//
// The email splits at its last @, and both halves are lowercased before matching; an email with no @ reports false.
// A domain in piiExampleEmailDomains or ending .example, .test, .invalid or .local, or a local part in piiExampleEmailLocals, reports true.
func isPlaceholderEmail(email string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	local := strings.ToLower(email[:at])
	domain := strings.ToLower(email[at+1:])
	if stringEqualsAny(domain, piiExampleEmailDomains) {
		return true
	}
	for _, suffix := range []string{".example", ".test", ".invalid", ".local"} {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return stringEqualsAny(local, piiExampleEmailLocals)
}

// isLuhnValid reports whether card holds 13-19 digits that pass the Luhn checksum, ignoring non-digits; false means no payment-card finding.
//
// Length and checksum filter most arbitrary digit runs without proving that a card was issued: a random id passes Luhn about 1 time in 10.
// The common fixture card numbers are themselves Luhn-valid by design, which is why the negative fixtures use Luhn-invalid digit runs.
func isLuhnValid(card string) bool {
	digits := make([]int, 0, len(card))
	for _, r := range card {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	// Luhn doubles every second digit from the right, so walk back-to-front.
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// cardDigits drops a card candidate's spaces and dashes, so a card is compared as the digits its network publishes.
// It returns only the ASCII digits of card, in order, and an empty string when card holds no digit.
func cardDigits(card string) string {
	return strings.Map(func(character rune) rune {
		// Keep digits; returning -1 drops a separator.
		if character >= '0' && character <= '9' {
			return character
		}
		return -1
	}, card)
}
