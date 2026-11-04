package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// BaselineToolLanguage is the token gruff-go contributes to every baseline identity.
//
// A project can hold two ports' findings; without it the same rule name on the same path would collide across ports.
// Changing it changes every identity, so no stored baseline entry would match a current finding any more.
const BaselineToolLanguage = "go"

// baselineOrdinalSeparator joins a symbol to its declaration ordinal.
// A symbol containing it could forge another symbol's ordinal, so such a symbol gets no identity rather than an ambiguous one.
const baselineOrdinalSeparator = "#"

// IsBaselineEligible reports whether a finding may ever receive a baseline identity.
//
// A sensitive finding never does: a stored identity is what would let a review hide a secret.
// Baseline application never suppresses sensitive findings; exit gates determine whether a visible finding blocks the run.
// It returns false when the pillar is PillarSensitiveData or the rule ID starts with "sensitive-data.", and true otherwise.
func (f Finding) IsBaselineEligible() bool {
	return f.Pillar != PillarSensitiveData && !strings.HasPrefix(f.RuleID, "sensitive-data.")
}

// HasBaselineIdentity reports whether a finding can be named durably at all.
//
// A sensitive finding never is, and neither is one whose symbol carries the ordinal separator, which could pose as another symbol's ordinal.
// Such a finding is never stored as a baseline occurrence or suppressed by baseline matching; SARIF omits its partial fingerprint.
// It returns true only when IsBaselineEligible is true and the symbol has no "#", and false otherwise.
func (f Finding) HasBaselineIdentity() bool {
	return f.IsBaselineEligible() && !strings.Contains(f.Symbol, baselineOrdinalSeparator)
}

// measuredValuePattern matches every number a message can state: a length, a count, a percentage, or a version such as 1,234 or 12.5.
var measuredValuePattern = regexp.MustCompile(`[0-9]+(?:[.,][0-9]+)*`)

// measuredValuePlaceholder is what every number becomes in a subject, so a file that grew from 1010 to 1200 lines keeps its reviewed identity.
const measuredValuePlaceholder = "#"

// NormaliseMeasuredValues replaces every number in a message with "#".
//
// Only a symbol-less finding is named by its message, and its measurement is the one part of that name expected to change between runs.
// It returns message with each number, such as 1,234 or 12.5, replaced by one "#"; a message without digits is returned unchanged.
func NormaliseMeasuredValues(message string) string {
	return measuredValuePattern.ReplaceAllString(message, measuredValuePlaceholder)
}

// BaselineSubject returns the identity subject: the symbol plus its declaration ordinal, or the normalised message when no symbol is named.
//
// The ordinal keeps two same-named functions apart; without it, reviewing one silently baselines the other.
// An error is returned when the finding has neither symbol nor message, its symbol contains "#", or it names a symbol with an ordinal below 1.
func (f Finding) BaselineSubject() (string, error) {
	if f.Symbol == "" {
		if f.Message == "" {
			return "", fmt.Errorf("finding %s in %s names neither a symbol nor a message", f.RuleID, f.File)
		}
		// A file-level message states a measurement; stripping it keeps a grown file behind its reviewed entry.
		return NormaliseMeasuredValues(f.Message), nil
	}
	if strings.Contains(f.Symbol, baselineOrdinalSeparator) {
		return "", fmt.Errorf("finding %s in %s has symbol %q containing %q", f.RuleID, f.File, f.Symbol, baselineOrdinalSeparator)
	}
	// Defaulting a missing ordinal to 1 would merge namesakes back together, the collision the identity exists to prevent.
	if f.SymbolOrdinal < 1 {
		return "", fmt.Errorf("finding %s in %s has symbol %q without a declaration ordinal", f.RuleID, f.File, f.Symbol)
	}
	return f.Symbol + baselineOrdinalSeparator + fmt.Sprint(f.SymbolOrdinal), nil
}

// ComputeBaselineIdentity returns the identity a baseline stores for this finding.
//
// It is sha256 over the NUL-separated tool language, rule id, project-relative path, and subject, truncated to sixteen hex characters.
// Line, column, severity and tier are excluded; a changed declaration ordinal or normalised message still changes the identity.
// An error is returned, with an empty identity, when the rule id or path is empty or BaselineSubject fails.
func (f Finding) ComputeBaselineIdentity() (string, error) {
	return f.ComputeBaselineIdentityFor(BaselineToolLanguage)
}

// ComputeBaselineIdentityFor hashes the identity under an explicit tool language.
//
// Conformance checks compare its output with identities pinned for other language ports, so every port hashes the same way.
//
// toolLanguage takes the place of BaselineToolLanguage as the first of the four NUL-separated fields that are hashed.
// It returns the first sixteen hex characters of the sha256 digest, as ComputeBaselineIdentity describes.
// An error is returned, with an empty string, when the rule id or path is empty or BaselineSubject fails.
func (f Finding) ComputeBaselineIdentityFor(toolLanguage string) (string, error) {
	if f.RuleID == "" || f.File == "" {
		return "", fmt.Errorf("finding %q in %q needs both a rule id and a path for a baseline identity", f.RuleID, f.File)
	}
	subject, err := f.BaselineSubject()
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	for index, field := range []string{toolLanguage, f.RuleID, f.File, subject} {
		if index > 0 {
			hasher.Write([]byte{0})
		}
		hasher.Write([]byte(field))
	}
	return hex.EncodeToString(hasher.Sum(nil))[:16], nil
}

// AssignSymbolOrdinals ranks each symbol-bearing finding's declaration among same-named declarations in its file.
//
// declarationPosition names the line a finding's declaration begins on.
// Two findings on one declaration share a position and therefore an ordinal, while a second declaration of the same name takes the next.
// Ordinals count declarations rather than lines, so inserting code above a function moves its line and not its ordinal.
//
// It returns a copy of findings in which every symbol-bearing finding carries its DeclarationPosition and SymbolOrdinal.
// A finding without a symbol is copied unchanged, the input slice is not modified, and a position below 1 is ranked as line 1.
func AssignSymbolOrdinals(findings []Finding, declarationPosition func(Finding) int) []Finding {
	return AssignSymbolOrdinalsFromInventory(findings, declarationPosition, nil)
}

// AssignSymbolOrdinalsFromInventory ranks like AssignSymbolOrdinals, but also gives every declaration sameNamedPositions lists a slot.
//
// A listed declaration takes its slot whether or not it has a finding this run.
// Without the inventory a clean earlier declaration takes no slot, so when it first warns it takes the later one's ordinal and stored review.
//
// sameNamedPositions gives every same-named declaration line for a finding; lines below 1 are ignored, and nil ranks findings alone.
// declarationPosition gives the line each finding's declaration begins on, and a position below 1 counts as line 1.
// It returns a copy of findings with DeclarationPosition and SymbolOrdinal set on each symbol-bearing finding.
func AssignSymbolOrdinalsFromInventory(findings []Finding, declarationPosition func(Finding) int, sameNamedPositions func(Finding) []int) []Finding {
	type symbolKey struct {
		file   string
		symbol string
	}
	positionsByKey := map[symbolKey][]int{}
	positions := make([]int, len(findings))
	for index, symbolFinding := range findings {
		if symbolFinding.Symbol == "" {
			continue
		}
		position := declarationPosition(symbolFinding)
		// An unknown position still needs a deterministic rank; the first line keeps every such finding on one declaration.
		if position < 1 {
			position = 1
		}
		positions[index] = position
		key := symbolKey{file: symbolFinding.File, symbol: symbolFinding.Symbol}
		if !slices.Contains(positionsByKey[key], position) {
			positionsByKey[key] = append(positionsByKey[key], position)
		}
		if sameNamedPositions == nil {
			continue
		}
		for _, declared := range sameNamedPositions(symbolFinding) {
			if declared >= 1 && !slices.Contains(positionsByKey[key], declared) {
				positionsByKey[key] = append(positionsByKey[key], declared)
			}
		}
	}
	for key := range positionsByKey {
		slices.Sort(positionsByKey[key])
	}
	assigned := make([]Finding, len(findings))
	copy(assigned, findings)
	for index := range assigned {
		if assigned[index].Symbol == "" {
			continue
		}
		key := symbolKey{file: assigned[index].File, symbol: assigned[index].Symbol}
		assigned[index].DeclarationPosition = positions[index]
		assigned[index].SymbolOrdinal = slices.Index(positionsByKey[key], positions[index]) + 1
	}
	return assigned
}

// EnsureSymbolOrdinals ranks any (file, symbol) group the analysis pipeline has not ranked, using each finding's own line.
//
// Groups the pipeline already ranked are left alone, so a mixed slice never carries two different ordinal rules for one symbol.
// A group counts as ranked when any of its findings has an ordinal above zero; its unranked members keep zero, which BaselineSubject rejects.
//
// findings may mix ranked and unranked groups; a finding with no Location is ranked as if declared on line 1.
// It returns a copy of findings where each unranked group gets line-based ordinals and positions, and ranked groups keep their stored values.
func EnsureSymbolOrdinals(findings []Finding) []Finding {
	type symbolKey struct {
		file   string
		symbol string
	}
	ranked := map[symbolKey]bool{}
	for _, item := range findings {
		if item.Symbol != "" && item.SymbolOrdinal > 0 {
			ranked[symbolKey{file: item.File, symbol: item.Symbol}] = true
		}
	}
	fallback := AssignSymbolOrdinals(findings, func(item Finding) int {
		if item.Location == nil {
			return 1
		}
		return item.Location.Line
	})
	for index := range fallback {
		if ranked[symbolKey{file: fallback[index].File, symbol: fallback[index].Symbol}] {
			fallback[index].SymbolOrdinal = findings[index].SymbolOrdinal
			fallback[index].DeclarationPosition = findings[index].DeclarationPosition
		}
	}
	return fallback
}
