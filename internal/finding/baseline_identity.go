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
// A project can hold two ports' findings; without it the same rule name on the same path would collide across ports.
const BaselineToolLanguage = "go"

// baselineOrdinalSeparator joins a symbol to its declaration ordinal.
// A symbol containing it could forge another symbol's ordinal, so such a symbol gets no identity rather than an ambiguous one.
const baselineOrdinalSeparator = "#"

// IsBaselineEligible reports whether a finding may ever receive a baseline identity.
// A sensitive finding never does: a stored identity is what would let a review hide a secret.
// It stays visible and blocking on every run until the user fixes it or excludes it with a written reason.
func (f Finding) IsBaselineEligible() bool {
	return f.Pillar != PillarSensitiveData && !strings.HasPrefix(f.RuleID, "sensitive-data.")
}

// measuredValuePattern matches every number a message can state: a length, a count, a percentage, or a version such as 1,234 or 12.5.
var measuredValuePattern = regexp.MustCompile(`[0-9]+(?:[.,][0-9]+)*`)

// measuredValuePlaceholder is what every number becomes in a subject, so a file that grew from 1010 to 1200 lines keeps its reviewed identity.
const measuredValuePlaceholder = "#"

// NormaliseMeasuredValues replaces every number in a message with "#", per the identity amendment of 2026-09-05.
// Only a symbol-less finding is named by its message, and its measurement is the one part of that name expected to change between runs.
func NormaliseMeasuredValues(message string) string {
	return measuredValuePattern.ReplaceAllString(message, measuredValuePlaceholder)
}

// BaselineSubject returns the identity subject: the symbol plus its declaration ordinal, or the normalised message when no symbol is named.
// The ordinal keeps two same-named functions apart; without it, reviewing one silently baselines the other.
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
// No line, column, severity, or tier enters it, so it survives every edit that does not change what the finding is about.
func (f Finding) ComputeBaselineIdentity() (string, error) {
	return f.ComputeBaselineIdentityFor(BaselineToolLanguage)
}

// ComputeBaselineIdentityFor hashes the identity under an explicit tool language.
// Conformance checks use it to reproduce the family oracle's pinned digests for other ports, which is the only proof the rule is one rule.
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
func AssignSymbolOrdinals(findings []Finding, declarationPosition func(Finding) int) []Finding {
	type symbolKey struct {
		file   string
		symbol string
	}
	positionsByKey := map[symbolKey][]int{}
	positions := make([]int, len(findings))
	for index, item := range findings {
		if item.Symbol == "" {
			continue
		}
		position := declarationPosition(item)
		// An unknown position still needs a deterministic rank; the first line keeps every such finding on one declaration.
		if position < 1 {
			position = 1
		}
		positions[index] = position
		key := symbolKey{file: item.File, symbol: item.Symbol}
		if !slices.Contains(positionsByKey[key], position) {
			positionsByKey[key] = append(positionsByKey[key], position)
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
// Groups the pipeline already ranked are left alone, so a mixed slice never carries two different ordinal rules for one symbol.
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
