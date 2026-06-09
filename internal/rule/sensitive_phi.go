// Package rule defines gruff-go's rule registry and analysers.
// This file implements the PHI detector: US Social Security numbers, Medicare
// beneficiary identifiers, and label-anchored medical record numbers.
package rule

import (
	"regexp"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// PHI candidate patterns.
var (
	// phiSSNPattern matches the dashed US SSN shape AAA-GG-SSSS. Requiring the
	// dashes (rather than a bare 9-digit run) is the first FP guard; structural
	// validity (see isStructurallyValidSSN) is the second.
	phiSSNPattern = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	// phiMedicarePattern matches a Medicare Beneficiary Identifier (MBI). The
	// alphabetic positions exclude S, L, O, I, B, and Z per the CMS format, which
	// makes the 11-character shape specific enough to be high-signal on its own.
	// Optional dashes allow the commonly written 4-3-4 grouping.
	phiMedicarePattern = regexp.MustCompile(`\b[1-9][ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY0-9]\d-?[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY0-9]\d-?[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY]\d\d\b`)
	// phiMRNPattern matches a 6-10 digit medical record number ONLY when a nearby
	// label (mrn, medical record, patient id) anchors it. MRNs have no universal
	// format, so the label is what separates a record number from any other
	// integer; the digits are captured in group 1 for redaction.
	phiMRNPattern = regexp.MustCompile(`(?i)(?:mrn|medical[ _\-]?record(?:[ _\-]?(?:number|no|num|#))?|patient[ _\-]?id)\b\D{0,12}(\d{6,10})\b`)
)

// phiPlaceholderSSNs are SSNs that are structurally valid yet are reserved or
// notorious fixtures (the 1938 wallet-card number, the SSA advertising number,
// and common docs filler), so they signal sample data rather than real PHI.
var phiPlaceholderSSNs = map[string]struct{}{
	"078-05-1120": {}, // Woolworth wallet-card SSN
	"219-09-9999": {}, // SSA pamphlet number
	"123-45-6789": {}, // ubiquitous docs/test placeholder
	"111-11-1111": {},
	"000-00-0000": {},
}

// PHIPatternRule flags protected health information identifiers - US SSNs,
// Medicare beneficiary identifiers, and labelled medical record numbers - in
// source or text. It owns the government/health identifier shapes so they are
// reported once here rather than also by PIIPatternRule.
type PHIPatternRule struct{}

// Definition declares the sensitive-data.phi-pattern rule. Opt-in and
// warning/medium: SSN-shaped and MBI-shaped strings can occur in fixtures and
// the match is heuristic, so it stays out of default scans and below the error
// tier reserved for confirmed credentials.
func (PHIPatternRule) Definition() Definition {
	return Definition{
		ID:             "sensitive-data.phi-pattern",
		Title:          "PHI pattern",
		Description:    "Flags protected health information identifiers (US Social Security numbers, Medicare beneficiary identifiers, and label-anchored medical record numbers) embedded in source or text files. Opt-in; emits only a redacted preview.",
		Pillar:         finding.PillarSensitiveData,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Tags:           []string{"secrets", "phi"},
		Remediation:    "Remove the identifier from source; use synthetic fixture data and load or store real PHI only in HIPAA-compliant systems. Mask or tokenise PHI before it reaches logs or reports.",
	}
}

// AnalyzeUnit scans code-bearing lines for SSN, Medicare, and labelled-MRN shapes,
// skipping structurally invalid or placeholder SSNs, and emits a redacted preview
// for each real-looking hit.
func (PHIPatternRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.Source == "" {
		return nil
	}
	findings := []finding.Finding{}
	inBlockComment := false
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		if !lineIsCodeBearing(line, &inBlockComment) {
			continue
		}
		findings = append(findings, phiLineFindings(unit.File.Path, line, lineNumber+1)...)
	}
	return findings
}

// phiLineFindings returns the PHI findings for a single line, one per category
// that matches. Each records its category and a redacted preview, never the raw
// identifier.
func phiLineFindings(path, line string, lineNumber int) []finding.Finding {
	out := []finding.Finding{}
	if ssn := phiSSNPattern.FindString(line); ssn != "" && isStructurallyValidSSN(ssn) && !isPlaceholderSSN(ssn) {
		out = append(out, phiFinding(path, lineNumber, "ssn", ssn))
	}
	if mbi := phiMedicarePattern.FindString(line); mbi != "" {
		out = append(out, phiFinding(path, lineNumber, "medicare", mbi))
	}
	if match := phiMRNPattern.FindStringSubmatch(line); match != nil {
		out = append(out, phiFinding(path, lineNumber, "mrn", match[1]))
	}
	return out
}

// phiFinding builds one redacted PHI finding tagged with its category.
func phiFinding(path string, lineNumber int, category, raw string) finding.Finding {
	return finding.Finding{
		Message:  category + " PHI identifier detected",
		File:     path,
		Location: &finding.Location{Line: lineNumber},
		Metadata: map[string]any{
			"preview":  redact(raw),
			"category": category,
		},
	}
}

// isStructurallyValidSSN reports whether a dashed SSN uses an issuable number
// space. The SSA never issues area 000, 666, or 900-999, group 00, or serial
// 0000, so excluding them drops a large class of random 3-2-4 digit runs (dates,
// ids) before they can be mistaken for a real SSN.
func isStructurallyValidSSN(ssn string) bool {
	parts := strings.Split(ssn, "-")
	if len(parts) != 3 {
		return false
	}
	area, group, serial := parts[0], parts[1], parts[2]
	if area == "000" || area == "666" || area >= "900" {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// isPlaceholderSSN reports whether an SSN is a well-known reserved or fixture
// number that signals sample data rather than exposed PHI.
func isPlaceholderSSN(ssn string) bool {
	_, ok := phiPlaceholderSSNs[ssn]
	return ok
}
