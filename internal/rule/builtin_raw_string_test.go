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
func secretPatternLines(t *testing.T, source string) []int {
	t.Helper()
	unit := parseOne(t, "pkg/sample.go", source)
	lines := []int{}
	for _, item := range (SensitiveDataRule{}).AnalyzeUnit(unit, Context{}) {
		lines = append(lines, item.Location.Line)
	}
	return lines
}

// requireSecretPatternCount fails unless the rule reported exactly n assignments.
func requireSecretPatternCount(t *testing.T, source string, n int) {
	t.Helper()
	if got := secretPatternLines(t, source); len(got) != n {
		t.Fatalf("secret-pattern reported %d findings at lines %v, want %d", len(got), got, n)
	}
}

// The g101_samples shape: secret-shaped lines inside a multi-line raw string.
func TestSecretPatternIgnoresRawStringInteriors(t *testing.T) {
	value := secretPatternFixtureValue()
	requireSecretPatternCount(t, "package pkg\n\nconst samples = `\npassword = \""+value+"\"\nauth_token = \""+value+"\"\n`\n", 0)
}

// A single-line raw string is literal text too.
func TestSecretPatternIgnoresASingleLineRawString(t *testing.T) {
	value := secretPatternFixtureValue()
	requireSecretPatternCount(t, "package pkg\n\nconst sample = `password = \""+value+"\"`\n", 0)
}

// The control the task names: a real assignment in code still reports.
func TestSecretPatternStillReportsAnAssignmentInCode(t *testing.T) {
	value := secretPatternFixtureValue()
	requireSecretPatternCount(t, "package pkg\n\nfunc connect() {\n\tpassword := \""+value+"\"\n\t_ = password\n}\n", 1)
}

// An interpreted string is ordinary code and is not excluded: only backtick literals are.
func TestSecretPatternStillReportsAnInterpretedString(t *testing.T) {
	value := secretPatternFixtureValue()
	requireSecretPatternCount(t, "package pkg\n\nvar authToken = \""+value+"\"\n", 1)
}

// Code after a raw string closes is scanned again, so the exclusion cannot swallow a whole file.
func TestSecretPatternResumesAfterARawStringCloses(t *testing.T) {
	value := secretPatternFixtureValue()
	requireSecretPatternCount(t, "package pkg\n\nconst doc = `\npassword = \""+value+"\"\n`\n\nfunc connect() {\n\tauthToken := \""+value+"\"\n\t_ = authToken\n}\n", 1)
}
