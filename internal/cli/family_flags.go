// Package cli carries the family flag contract this port implements alongside its own flags.
//
// Three things live here, because all three are about one shared vocabulary rather than about any one command. The
// hard break refuses --min-severity, whose meaning inverts at 0.6.0. The plural display selectors keep working and say
// what to type instead. The family gates that gruff-go never had, --min-confidence and --fail-on-new, are parsed here.
//
// The exact refusal text is ratified: gruff-spec/fixtures/cli/locked-v05-min-severity.v1.json records the six runs that
// justify it and the operator's approval of the wording.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// minSeverityBreakMessage is the ratified refusal for a flag whose meaning inverts rather than disappears.
//
// Measured at v0.5: `--min-severity error` gated at error and exited 0 on an advisory-only project. Under the family
// meaning it filters the report and gates at the default, which is advisory, so the same command exits 1 and a passing
// build starts failing. That is why this is a refusal and not a warning.
const minSeverityBreakMessage = `--min-severity changed meaning in 0.6.0: it now filters which findings are displayed and no longer sets the exit gate.
Use --fail-on <severity> to keep gating the exit code, which is what --min-severity did in 0.5.
To filter the report instead, pass --min-severity in 0.7.0, where it returns with the family meaning.`

// supersededSpellings maps each superseded flag name to the family spelling that replaces it.
//
// Every one of these keeps working with identical behaviour, which is what makes them warnings rather than breaks: the
// old forms did exactly what the family names describe, so only the name is going away.
var supersededSpellings = map[string]string{
	"include-rules":   "--show-rule",
	"exclude-rules":   "--hide-rule",
	"include-pillars": "--show-pillar",
	"exclude-pillars": "--hide-pillar",
	"migrate":         "--migrate-baseline",
}

// refuseMinSeverity reports whether the user passed the one flag whose observable meaning inverts.
//
// It writes the ratified message and returns true so the caller can exit 2 before scanning anything, because a run that
// proceeded would produce a verdict under semantics the user did not ask for.
func refuseMinSeverity(flags *flag.FlagSet, stderr io.Writer) bool {
	refused := false

	flags.Visit(func(passed *flag.Flag) {
		if passed.Name == "min-severity" {
			refused = true
		}
	})

	// Only the message goes to stderr; the caller owns the exit code so every command refuses the same way.
	if refused {
		fmt.Fprintln(stderr, minSeverityBreakMessage)
	}

	return refused
}

// warnSupersededSpellings prints one line per superseded flag name the user passed.
//
// The run continues: behaviour is identical under the family spelling, so refusing would break a working command line
// for a rename. The warning is what tells the user the old name is going away.
func warnSupersededSpellings(flags *flag.FlagSet, stderr io.Writer) {
	flags.Visit(func(passed *flag.Flag) {
		if replacement, superseded := supersededSpellings[passed.Name]; superseded {
			fmt.Fprintf(stderr, "--%s is now %s; the old name still works and will be removed in 0.7.0.\n", passed.Name, replacement)
		}
	})
}

// familyGateValues carries the two exit gates gruff-go gains from the family contract.
type familyGateValues struct {
	// minConfidence is the lowest confidence a finding needs to reach the exit gate, independent of severity.
	minConfidence string
	// failOnNew exits 1 when any finding carries baseline status new, whatever its severity.
	failOnNew bool
}

// parseFamilyGates validates the two new gate flags before a scan starts.
//
// An unparseable confidence is a usage error rather than a silent fallback, for the same reason a mistyped severity is:
// a gate the user did not get is worse than a command that refused.
func parseFamilyGates(minConfidence string, failOnNew bool, stderr io.Writer) (familyGateValues, bool) {
	gates := familyGateValues{minConfidence: strings.ToLower(strings.TrimSpace(minConfidence)), failOnNew: failOnNew}

	// An empty value means the user set no confidence floor, which is the permissive default rather than an error.
	if gates.minConfidence == "" {
		gates.minConfidence = string(finding.ConfidenceLow)
		return gates, true
	}

	if !validConfidenceFloor(gates.minConfidence) {
		fmt.Fprintf(stderr, "unknown confidence %q: want one of low, medium, high\n", minConfidence)
		return familyGateValues{}, false
	}

	return gates, true
}

// validConfidenceFloor reports whether a confidence floor names one of the three ratified levels.
func validConfidenceFloor(candidate string) bool {
	switch candidate {
	case string(finding.ConfidenceLow), string(finding.ConfidenceMedium), string(finding.ConfidenceHigh):
		return true
	default:
		return false
	}
}

// confidenceRank orders the three confidence levels so a floor can be compared against a finding.
//
// An unrecognised value ranks highest, because a finding whose confidence nobody rated must not slip under a gate.
func confidenceRank(confidence string) int {
	switch strings.ToLower(string(confidence)) {
	case string(finding.ConfidenceLow):
		return 0
	case string(finding.ConfidenceMedium):
		return 1
	default:
		return 2
	}
}

// reachesFamilyGate reports whether one finding reaches both the severity and the confidence floor.
//
// Severity is already decided by the caller's threshold comparison; this adds the independent confidence dimension the
// family contract introduces, so neither floor alone decides the exit code.
func reachesFamilyGate(findingConfidence string, gates familyGateValues) bool {
	return confidenceRank(findingConfidence) >= confidenceRank(gates.minConfidence)
}
