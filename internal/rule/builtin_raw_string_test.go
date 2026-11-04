// Package rule tests the raw-string exclusion for sensitive-data.secret-pattern.
//
// A backtick literal holds documentation, templates and sample payloads. gosec's own
// g101_samples fixture is exactly that: a raw string full of secret-shaped lines, none of which
// is a credential. The exclusion is confined to this one rule because the shared line guard it
// would otherwise live in is reached by sixteen rules, measured 2026-09-07.
//
// Every fixture below uses secretPatternFixtureValue, which is secret-shaped but matches no
// vendor detector, so gruff-go's own self-scan stays clean on this file.
package rule

import "testing"

// secretPatternLines reports the lines sensitive-data.secret-pattern flags in one Go file.
//
// The source text is parsed through parseOne as pkg/sample.go and checked by SensitiveDataRule with an empty Context.
// Line numbers come back in the order the rule reports them, and the slice is empty but not nil when the rule flags nothing.
func secretPatternLines(t *testing.T, source string) []int {
	t.Helper()
	unit := parseOne(t, "pkg/sample.go", source)
	lines := []int{}
	for _, item := range (SensitiveDataRule{}).AnalyzeUnit(unit, Context{}) {
		lines = append(lines, item.Location.Line)
	}
	return lines
}

// requireSecretPatternCount fails unless the rule reported exactly wantFindings assignments.
// The source argument is the Go file text passed to secretPatternLines; a mismatch stops the test with the count, lines and wantFindings.
func requireSecretPatternCount(t *testing.T, source string, wantFindings int) {
	t.Helper()
	if got := secretPatternLines(t, source); len(got) != wantFindings {
		t.Fatalf("secret-pattern reported %d findings at lines %v, want %d", len(got), got, wantFindings)
	}
}

// TestSecretPatternIgnoresRawStringInteriors feeds the g101_samples shape: secret-shaped lines inside a multi-line raw string.
// Any finding means sample payloads and docs in backtick strings are reported as secrets again.
func TestSecretPatternIgnoresRawStringInteriors(t *testing.T) {
	value := secretPatternFixtureValue()
	requireSecretPatternCount(t, "package pkg\n\nconst samples = `\npassword = \""+value+"\"\nauth_token = \""+value+"\"\n`\n", 0)
}

// TestSecretPatternIgnoresASingleLineRawString checks that a single-line raw string is literal text too, so the rule reports nothing.
// A finding here means this single-line raw-string sample was reported as a secret.
func TestSecretPatternIgnoresASingleLineRawString(t *testing.T) {
	value := secretPatternFixtureValue()
	requireSecretPatternCount(t, "package pkg\n\nconst sample = `password = \""+value+"\"`\n", 0)
}

// TestSecretPatternStillReportsAnAssignmentInCode is the control: a real password assignment inside a function still reports one finding.
// Zero findings means the exclusion, or the rule itself, now misses real secrets in code.
func TestSecretPatternStillReportsAnAssignmentInCode(t *testing.T) {
	value := secretPatternFixtureValue()
	requireSecretPatternCount(t, "package pkg\n\nfunc connect() {\n\tpassword := \""+value+"\"\n\t_ = password\n}\n", 1)
}

// TestSecretPatternStillReportsAnInterpretedString checks that an interpreted string is ordinary code and is not excluded.
// Only backtick literals are excluded; zero findings means a double-quoted secret is now skipped too.
func TestSecretPatternStillReportsAnInterpretedString(t *testing.T) {
	value := secretPatternFixtureValue()
	requireSecretPatternCount(t, "package pkg\n\nvar authToken = \""+value+"\"\n", 1)
}

// TestSecretPatternResumesAfterARawStringCloses checks that code after a raw string closes is scanned again.
// One finding is expected, from authToken; zero means that assignment was missed, and two or more means an extra line was flagged.
func TestSecretPatternResumesAfterARawStringCloses(t *testing.T) {
	value := secretPatternFixtureValue()
	requireSecretPatternCount(t, "package pkg\n\nconst doc = `\npassword = \""+value+"\"\n`\n\nfunc connect() {\n\tauthToken := \""+value+"\"\n\t_ = authToken\n}\n", 1)
}
