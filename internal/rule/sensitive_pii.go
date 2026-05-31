// Package rule defines gruff-go's rule registry and analysers.
// This file implements the PII detector: emails, phone numbers, and Luhn-valid
// payment card numbers embedded in source or text.
package rule

import (
	"regexp"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// PII candidate patterns. Each is deliberately shape-specific so the detector
// keys on structure, not context; the redacted preview keeps raw values out of
// every output path.
var (
	// piiEmailPattern matches a conventional addr-spec. The TLD floor of 2 keeps
	// it from firing on `a@b` style fragments.
	piiEmailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	// piiPhonePattern matches NANP / E.164-ish numbers that carry phone
	// punctuation (a leading +, or parens/spaces/dashes between groups). Requiring
	// punctuation is the FP guard: a bare 10-digit run is far more often an id,
	// timestamp, or amount than a phone number.
	piiPhonePattern = regexp.MustCompile(`(?:\+\d{1,3}[ .\-]?)?(?:\(\d{3}\)[ .\-]?|\d{3}[ .\-])\d{3}[ .\-]\d{4}\b`)
	// piiCardPattern matches a 13-19 digit run grouped by optional spaces/dashes -
	// the shape of a payment card. Luhn validation (see isLuhnValid) is what makes
	// this high-signal rather than "any long number".
	piiCardPattern = regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)
)

// piiExampleEmailDomains are documentation/test domains reserved by RFC 2606 and
// common fixtures. An address at one of these is a placeholder, never real PII.
var piiExampleEmailDomains = []string{
	"example.com", "example.org", "example.net", "example.edu",
	"test.com", "test", "localhost", "invalid", "email.com", "domain.com",
}

// piiExampleEmailLocals are local-parts that signal a placeholder regardless of
// domain (`you@your-company.com`, `noreply@...`, `user@...`).
var piiExampleEmailLocals = []string{
	"you", "your", "user", "username", "example", "test", "noreply", "no-reply",
	"someone", "name", "email", "foo", "bar",
}

// PIIPatternRule flags personally identifiable information - email addresses,
// phone numbers, and payment card numbers - embedded in source or text. It is the
// PII half of the M30 PII/PHI split; government/health identifiers (SSN, MRN,
// Medicare) belong to PHIPatternRule so an SSN is never counted by both.
type PIIPatternRule struct{}

// Definition declares the sensitive-data.pii-pattern rule. Opt-in and
// warning/medium: emails and phone-shaped numbers are common in legitimate code
// (author contacts, sample data), so the rule stays out of default scans and
// below the error tier reserved for confirmed credentials.
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

// AnalyzeUnit scans code-bearing lines for email, phone, and payment-card shapes,
// skipping documentation/placeholder addresses and card-shaped numbers that fail
// Luhn, and emits a redacted preview for each real-looking hit.
func (PIIPatternRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.Source == "" {
		return nil
	}
	findings := []finding.Finding{}
	inBlockComment := false
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		if !lineIsCodeBearing(line, &inBlockComment) {
			continue
		}
		findings = append(findings, piiLineFindings(unit.File.Path, line, lineNumber+1)...)
	}
	return findings
}

// piiLineFindings returns the PII findings for a single line, one per category
// that matches. Categories are checked independently so an email and a phone on
// the same line both surface; each finding records its category and redacted
// preview, never the raw value.
func piiLineFindings(path, line string, lineNumber int) []finding.Finding {
	out := []finding.Finding{}
	if email := piiEmailPattern.FindString(line); email != "" && !isPlaceholderEmail(email) {
		out = append(out, piiFinding(path, lineNumber, "email", email))
	}
	if phone := piiPhonePattern.FindString(line); phone != "" {
		out = append(out, piiFinding(path, lineNumber, "phone", strings.TrimSpace(phone)))
	}
	if card := piiCardPattern.FindString(line); card != "" && isLuhnValid(card) {
		out = append(out, piiFinding(path, lineNumber, "payment-card", card))
	}
	return out
}

// piiFinding builds one redacted PII finding tagged with its category.
func piiFinding(path string, lineNumber int, category, raw string) finding.Finding {
	return finding.Finding{
		Message:  category + " PII detected",
		File:     path,
		Location: &finding.Location{Line: lineNumber},
		Metadata: map[string]any{
			"preview":  redact(raw),
			"category": category,
		},
	}
}

// isPlaceholderEmail reports whether an address is an obvious documentation or
// fixture placeholder - an RFC 2606 example domain or a generic local-part - so
// `you@example.com` in a README or test never reads as exposed PII.
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

// isLuhnValid reports whether a card-shaped string passes the Luhn checksum.
// Separators are ignored. This is the guard that turns "any 13-19 digit run" into
// "a real payment card number": a random id of that length passes Luhn only ~1 in
// 10 times, and the common fixture card numbers are themselves Luhn-valid by
// design, which is why the negative fixtures use Luhn-invalid digit runs.
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
