// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements the PHI detector: US Social Security numbers, Medicare beneficiary identifiers, and label-anchored medical record numbers.
// The rule is opt-in, so its findings appear only after enabling sensitive-data.phi-pattern, and each carries a redacted preview in its metadata.
package rule

import (
	"regexp"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// PHI candidate patterns, matched against each code-bearing line by phiLineFindings.
//
// Only the first match of each pattern on a line is examined, so a second SSN on the same line is never reported.
var (
	// phiSSNPattern matches the dashed US SSN shape AAA-GG-SSSS.
	//
	// Requiring the dashes rather than a bare 9-digit run is the first false-positive guard, so 123456789 is never reported as an SSN.
	// Structural validity, checked by isStructurallyValidSSN, is the second.
	phiSSNPattern = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	// phiMedicarePattern matches a Medicare Beneficiary Identifier (MBI).
	//
	// The alphabetic positions exclude S, L, O, I, B, and Z per the CMS format.
	// That makes the 11-character shape specific enough to be high-signal on its own, so no nearby label is required.
	// Optional dashes allow the commonly written 4-3-4 grouping.
	phiMedicarePattern = regexp.MustCompile(`\b[1-9][ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY0-9]\d-?[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY0-9]\d-?[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY]\d\d\b`)
	// phiMRNPattern matches a 6-10 digit medical record number only when a nearby label such as mrn, medical record or patient id anchors it.
	//
	// MRNs have no universal format, so the label is what separates a record number from any other integer.
	// The match ignores case and allows up to 12 non-digit characters between label and digits, which group 1 captures for redaction.
	phiMRNPattern = regexp.MustCompile(`(?i)(?:mrn|medical[ _\-]?record(?:[ _\-]?(?:number|no|num|#))?|patient[ _\-]?id)\b\D{0,12}(\d{6,10})\b`)
)

// phiPlaceholderSSNs lists reserved or well-known fixture SSNs that signal sample data rather than real PHI.
//
// They include the 1938 wallet-card number, the SSA advertising number and common docs filler.
// A line whose first SSN is one of these gives no SSN finding, and 000-00-0000 is already rejected as structurally invalid.
var phiPlaceholderSSNs = map[string]struct{}{
	"078-05-1120": {}, // Woolworth wallet-card SSN
	"219-09-9999": {}, // SSA pamphlet number
	"123-45-6789": {}, // ubiquitous docs/test placeholder
	"111-11-1111": {},
	"000-00-0000": {},
}

// PHIPatternRule flags protected health information identifiers in source or text files.
//
// It covers US SSNs, Medicare beneficiary identifiers and labelled medical record numbers.
// It owns these government and health identifier shapes so they are reported once here rather than also by PIIPatternRule.
//
// The rule is opt-in, and previews is the policy that formats each finding's redacted preview.
type PHIPatternRule struct{ previews sensitivePreviewPolicy }

// Definition declares the sensitive-data.phi-pattern rule.
//
// It is opt-in and only a warning, because SSN-shaped and MBI-shaped strings can occur in fixtures and the match is heuristic.
// So it stays out of default scans and below the error tier reserved for confirmed credentials.
//
// It returns the same fixed Definition on every call, with DefaultEnabled false, warning severity and medium confidence.
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

// AnalyzeUnit scans code-bearing lines for the first SSN, Medicare and labelled-MRN candidate per line.
//
// It emits a policy-masked finding for each candidate except a structurally invalid or placeholder SSN.
// Lines lineIsCodeBearing rejects are skipped, with block-comment state carried from one line to the next.
//
// unit supplies the source text, split on newlines with lines numbered from 1, and the file path recorded on each finding.
// It returns nil when the unit's source is empty, otherwise the findings in line order, which is an empty slice when nothing matches.
func (r PHIPatternRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.Source == "" {
		return nil
	}
	findings := []finding.Finding{}
	inBlockComment := false
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		if !lineIsCodeBearing(line, &inBlockComment) {
			continue
		}
		findings = append(findings, phiLineFindings(unit.File.Path, line, lineNumber+1, r.previews)...)
	}
	return findings
}

// phiLineFindings returns the PHI findings for a single line, at most one per category.
//
// Each records its category and a policy marker, never the raw identifier.
//
// path and lineNumber locate each finding, line is the text scanned, and previews is the policy that formats each finding's preview.
// Only the first candidate per category is examined; a structurally invalid or placeholder SSN is skipped without examining later SSNs.
// The result is an empty slice when no candidate is reportable.
func phiLineFindings(path, line string, lineNumber int, previews sensitivePreviewPolicy) []finding.Finding {
	out := []finding.Finding{}
	// Only the first dashed SSN is checked, so a placeholder such as 123-45-6789 earlier on the line hides a real SSN after it.
	if ssn := phiSSNPattern.FindString(line); ssn != "" && isStructurallyValidSSN(ssn) && !isPlaceholderSSN(ssn) {
		out = append(out, phiFinding(path, lineNumber, "ssn", ssn, previews))
	}
	// Only the first MBI-shaped match is checked and it has no placeholder exemption, so a sample MBI in a fixture is flagged too.
	if mbi := phiMedicarePattern.FindString(line); mbi != "" {
		out = append(out, phiFinding(path, lineNumber, "medicare", mbi, previews))
	}
	if match := phiMRNPattern.FindStringSubmatch(line); match != nil {
		out = append(out, phiFinding(path, lineNumber, "mrn", match[1], previews))
	}
	return out
}

// phiFinding builds one redacted PHI finding tagged with its category.
//
// path and lineNumber set the finding's file and line, and category is used in the message and the category metadata.
// raw is the matched identifier text, which previews formats into the preview metadata rather than storing it directly.
// It returns a finding carrying only the message, file, line and those two metadata entries.
func phiFinding(path string, lineNumber int, category, raw string, previews sensitivePreviewPolicy) finding.Finding {
	return finding.Finding{
		Message:  category + " PHI identifier detected",
		File:     path,
		Location: &finding.Location{Line: lineNumber},
		Metadata: map[string]any{
			"preview":  previews.format(path, personalDataPreviewCategory(category), raw),
			"category": category,
		},
	}
}

// isStructurallyValidSSN reports whether a dashed SSN uses an issuable number space.
//
// The SSA never issues area 000, 666, or 900-999, group 00, or serial 0000.
// Excluding them drops a large class of random 3-2-4 digit runs, such as dates and ids, before they can be mistaken for a real SSN.
//
// ssn is the dashed match from phiSSNPattern; it reports false when ssn does not split into three parts or falls in a never-issued range.
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

// isPlaceholderSSN reports whether ssn is a well-known reserved or fixture number that signals sample data rather than exposed PHI.
//
// It reports false for any SSN missing from phiPlaceholderSSNs, so a structurally valid one is then reported as a finding.
func isPlaceholderSSN(ssn string) bool {
	_, ok := phiPlaceholderSSNs[ssn]
	return ok
}
