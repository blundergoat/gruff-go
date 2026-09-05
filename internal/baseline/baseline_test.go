// Package baseline tests exercise the v3 contract as users meet it: reviewed
// debt that survives line movement, siblings that never inherit a review,
// secrets that never become entries, and a migration that leaves the 0.5
// original untouched.
package baseline

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// stamp keeps every generated file byte-comparable across a test.
var stamp = time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)

// ordinary builds one symbol-bearing finding on a declaration at line.
func ordinary(symbol string, line int) finding.Finding {
	return finding.Finding{
		RuleID:   "docs.missing-package-comment",
		Message:  "Missing documentation",
		File:     "internal/widget/widget.go",
		Symbol:   symbol,
		Location: &finding.Location{Line: line},
	}.WithFingerprint()
}

// classify applies a baseline built from reviewed against run, failing the
// test on any error so every case reads as a plain expectation.
func classify(t *testing.T, reviewed []finding.Finding, run []finding.Finding) ApplyResult {
	t.Helper()
	file, err := FromFindingsAt(reviewed, stamp)
	if err != nil {
		t.Fatalf("build baseline: %v", err)
	}
	result, err := Apply(run, file)
	if err != nil {
		t.Fatalf("apply baseline: %v", err)
	}
	return result
}

// counts is the six-way classification a test expects, in contract order.
type counts struct {
	unchanged, added, resolved, collision, notEligible int
}

// expectCounts compares all five run-side counts at once: reaching one expected
// number while moving another is not a pass.
func expectCounts(t *testing.T, result ApplyResult, want counts) {
	t.Helper()
	got := counts{result.UnchangedFindings, result.NewFindings, result.ResolvedFindings, result.CollisionFindings, result.NotEligibleFindings}
	if got != want {
		t.Fatalf("counts {unchanged added resolved collision notEligible} = %+v, want %+v", got, want)
	}
}

// TestIdentityMatchesTheFamilyOracle reproduces the digests the family case
// file pins for other ports, which is the only proof the rule is one rule.
func TestIdentityMatchesTheFamilyOracle(t *testing.T) {
	pins := []struct {
		toolLanguage string
		item         finding.Finding
		identity     string
	}{
		{"rs", finding.Finding{RuleID: "docs.missing-readme", File: "src/widget.rs", Symbol: "process", SymbolOrdinal: 1}, "aff839f0cf33b11e"},
		{"rs", finding.Finding{RuleID: "docs.missing-readme", File: "src/widget.rs", Symbol: "process", SymbolOrdinal: 2}, "4ab8dc0e1ec4b969"},
		{"rs", finding.Finding{RuleID: "docs.missing-readme", File: "src/widget.rs", Message: "File has no module documentation"}, "bdb4503a37614a4f"},
		{"ts", finding.Finding{RuleID: "docs.missing-readme", File: "src/widget.rs", Symbol: "process", SymbolOrdinal: 1}, "caa4bb2431af313d"},
		{"rs", finding.Finding{RuleID: "docs.missing-readme", File: "src/gadget.rs", Symbol: "process", SymbolOrdinal: 1}, "8f717ea2d0f8af15"},
		{"rs", finding.Finding{RuleID: "docs.missing-readme", File: "src/widget.rs", Message: "File has 1010 lines (limit 1000)"}, "0b6106408093761c"},
	}
	for _, pin := range pins {
		identity, err := pin.item.ComputeBaselineIdentityFor(pin.toolLanguage)
		if err != nil {
			t.Fatalf("identity: %v", err)
		}
		if identity != pin.identity {
			t.Fatalf("identity for %s %q = %s, want %s", pin.toolLanguage, pin.item.Symbol, identity, pin.identity)
		}
	}
}

// TestIdentityIgnoresEveryExcludedField is the property the whole line-free
// identity exists for: an edit that changes nothing about the finding changes
// nothing about its identity.
func TestIdentityIgnoresEveryExcludedField(t *testing.T) {
	base := ordinary("process", 10)
	base.SymbolOrdinal = 1
	identity, err := base.ComputeBaselineIdentity()
	if err != nil {
		t.Fatal(err)
	}
	moved := base
	moved.Location = &finding.Location{Line: 3000, Column: 42, EndLine: 3010}
	moved.Message = "Rewritten in a patch release"
	moved.Severity = finding.SeverityError
	movedIdentity, err := moved.ComputeBaselineIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if movedIdentity != identity {
		t.Fatalf("identity moved with excluded fields: %s != %s", movedIdentity, identity)
	}
	unranked := finding.Finding{RuleID: "r", File: "f", Symbol: "process"}
	if _, err := unranked.ComputeBaselineIdentity(); err == nil {
		t.Fatal("a symbol without a declaration ordinal must not receive an identity")
	}
}

// TestOrdinalsCountDeclarationsNotLines keeps two findings on one declaration
// together and separates a second declaration of the same name.
func TestOrdinalsCountDeclarationsNotLines(t *testing.T) {
	ranked := finding.AssignSymbolOrdinals([]finding.Finding{
		ordinary("process", 12), ordinary("process", 15), ordinary("process", 90), ordinary("handle", 40),
	}, func(item finding.Finding) int {
		// Lines 12 and 15 sit inside one declaration starting at line 10.
		if item.Location.Line < 20 {
			return 10
		}
		return item.Location.Line
	})
	got := []int{ranked[0].SymbolOrdinal, ranked[1].SymbolOrdinal, ranked[2].SymbolOrdinal, ranked[3].SymbolOrdinal}
	if got[0] != 1 || got[1] != 1 || got[2] != 2 || got[3] != 1 {
		t.Fatalf("ordinals = %v, want [1 1 2 1]", got)
	}
}

// TestLineMovementKeepsTheEntry inserts three hundred lines above a reviewed
// finding and expects nothing to expire.
func TestLineMovementKeepsTheEntry(t *testing.T) {
	result := classify(t, []finding.Finding{ordinary("process", 10)}, []finding.Finding{ordinary("process", 310)})
	expectCounts(t, result, counts{1, 0, 0, 0, 0})
}

// TestMatchingIsCountAware proves a second occurrence on one declaration is
// new, and that surplus reviewed occurrences are resolved, not silently kept.
func TestMatchingIsCountAware(t *testing.T) {
	one := ordinary("process", 10)
	duplicate := classify(t, []finding.Finding{one}, []finding.Finding{one, ordinary("process", 42)})
	expectCounts(t, duplicate, counts{1, 1, 0, 0, 0})
	decrease := classify(t, []finding.Finding{one, one, one}, []finding.Finding{one, one})
	expectCounts(t, decrease, counts{2, 0, 1, 0, 0})
	increase := classify(t, []finding.Finding{one, one}, []finding.Finding{one, one, one})
	expectCounts(t, increase, counts{2, 1, 0, 0, 0})
}

// TestReviewedCountIsSpentLowestLineFirst pins which occurrence is unchanged,
// not merely how many; the run is supplied out of order on purpose.
func TestReviewedCountIsSpentLowestLineFirst(t *testing.T) {
	result := classify(t, []finding.Finding{ordinary("process", 10)}, []finding.Finding{ordinary("process", 300), ordinary("process", 10)})
	if result.Statuses[0] != StatusNew || result.Statuses[1] != StatusUnchanged {
		t.Fatalf("statuses = %v, want [new unchanged]", result.Statuses)
	}
}

// TestReplacementAndRenameAreReviewWorthy keeps a new sibling from inheriting a
// review, whether the symbol or the file changed.
func TestReplacementAndRenameAreReviewWorthy(t *testing.T) {
	replaced := classify(t, []finding.Finding{ordinary("process", 10)}, []finding.Finding{ordinary("handle", 90)})
	expectCounts(t, replaced, counts{0, 1, 1, 0, 0})
	moved := ordinary("process", 10)
	moved.File = "internal/gadget/gadget.go"
	renamed := classify(t, []finding.Finding{ordinary("process", 10)}, []finding.Finding{moved})
	expectCounts(t, renamed, counts{0, 1, 1, 0, 0})
}

// TestSameNamedDeclarationsStayApart is the collision the ordinal was ratified
// to resolve: reviewing the first process must not baseline the second.
func TestSameNamedDeclarationsStayApart(t *testing.T) {
	result := classify(t, []finding.Finding{ordinary("process", 10)}, []finding.Finding{ordinary("process", 10), ordinary("process", 90)})
	expectCounts(t, result, counts{1, 1, 0, 0, 0})
}

// TestCollisionSuppressesNothingAndIsNamed forces the defect the ordinal
// prevents, by handing two declarations the same ordinal, and expects both
// findings reported with a diagnostic naming the subject.
func TestCollisionSuppressesNothingAndIsNamed(t *testing.T) {
	first := ordinary("process", 10)
	first.SymbolOrdinal, first.DeclarationPosition = 1, 10
	second := ordinary("process", 90)
	second.SymbolOrdinal, second.DeclarationPosition = 1, 90
	result := classify(t, []finding.Finding{first}, []finding.Finding{first, second})
	expectCounts(t, result, counts{0, 0, 0, 2, 0})
	if len(result.Collisions) != 1 || result.Collisions[0].RuleID != first.RuleID || !strings.Contains(strings.Join(result.Collisions[0].Subjects, " "), "process#1") {
		t.Fatalf("collisions = %#v, want one naming process#1", result.Collisions)
	}
}

// TestMessageRewordingOnlyMattersWithoutASymbol records the asymmetry
// deliberately: a symbol-bearing finding keeps its entry, a file-level one does not.
func TestMessageRewordingOnlyMattersWithoutASymbol(t *testing.T) {
	reworded := ordinary("process", 10)
	reworded.Message = "This function has no documentation comment"
	symbolBearing := classify(t, []finding.Finding{ordinary("process", 10)}, []finding.Finding{reworded})
	expectCounts(t, symbolBearing, counts{1, 0, 0, 0, 0})
	fileLevel := ordinary("", 1)
	fileLevel.Message = "File has no package comment"
	rewordedFileLevel := fileLevel
	rewordedFileLevel.Message = "This file has no package comment"
	result := classify(t, []finding.Finding{fileLevel}, []finding.Finding{rewordedFileLevel})
	expectCounts(t, result, counts{0, 1, 1, 0, 0})
}

// TestSensitiveFindingsAreNeverEligible covers both directions: a written
// baseline carries no sensitive entry and nothing that could name one, and a
// hand-written entry claiming a secret's identity suppresses nothing.
func TestSensitiveFindingsAreNeverEligible(t *testing.T) {
	rawSecret := "synthetic-fixture-credential-body"
	secret := finding.Finding{
		RuleID:   "sensitive-data.aws-access-key",
		Message:  "Possible AWS access key " + rawSecret,
		File:     "config/app.env",
		Pillar:   finding.PillarSensitiveData,
		Location: &finding.Location{Line: 3},
	}.WithFingerprint()
	written, err := FromFindingsAt([]finding.Finding{ordinary("process", 10), secret, secret}, stamp)
	if err != nil {
		t.Fatal(err)
	}
	if len(written.Occurrences) != 1 || written.Sensitive.Counts.Total != 2 || written.Sensitive.Counts.ByRule["sensitive-data.aws-access-key"] != 2 {
		t.Fatalf("written baseline = %#v, want one occurrence and two sensitive counts", written)
	}
	baselineJSON, err := Marshal(written)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(baselineJSON), rawSecret) || strings.Contains(string(baselineJSON), "config/app.env") {
		t.Fatalf("baseline persisted sensitive material:\n%s", baselineJSON)
	}
	hostile := File{
		SchemaVersion: SchemaVersion, ToolLanguage: "go", GeneratedAt: stamp.Format(time.RFC3339),
		Occurrences: []Occurrence{{Identity: "0000000000000000", Count: 1}},
		Sensitive:   SensitiveSummary{Reason: "hand written", Counts: SensitiveCounts{ByRule: map[string]int{}}},
	}
	result, err := Apply([]finding.Finding{secret}, hostile)
	if err != nil {
		t.Fatal(err)
	}
	// The hand-written entry matches nothing, so it is permanently stale rather than a suppression.
	expectCounts(t, result, counts{0, 0, 1, 0, 1})
	if len(result.Findings) != 1 {
		t.Fatalf("the sensitive finding must stay visible, got %d surviving findings", len(result.Findings))
	}
}

// TestForeignBaselineIsRefused keeps one port from silently discarding another's review.
func TestForeignBaselineIsRefused(t *testing.T) {
	file, err := FromFindingsAt([]finding.Finding{ordinary("process", 10)}, stamp)
	if err != nil {
		t.Fatal(err)
	}
	file.ToolLanguage = "ts"
	if _, err := Apply([]finding.Finding{ordinary("process", 10)}, file); err == nil || !strings.Contains(err.Error(), "written by ts") {
		t.Fatalf("apply = %v, want refusal naming ts", err)
	}
}

// TestGeneratedFilesAreDeterministic proves two builds over one run in
// different orders produce identical bytes, so regeneration is a no-op diff.
func TestGeneratedFilesAreDeterministic(t *testing.T) {
	run := []finding.Finding{ordinary("process", 10), ordinary("handle", 40), ordinary("", 1)}
	first, err := FromFindingsAt(run, stamp)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []finding.Finding{run[2], run[1], run[0]}
	second, err := FromFindingsAt(reversed, stamp)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := Marshal(first)
	secondJSON, _ := Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("generated files differ:\n%s\n%s", firstJSON, secondJSON)
	}
	if _, err := Parse(firstJSON); err != nil {
		t.Fatalf("a generated file must parse: %v", err)
	}
}

// TestParseRejectsEveryWayAFileCouldExpireLeakOrReorder covers the validator
// and the loud rejection of a 0.5 file.
func TestParseRejectsEveryWayAFileCouldExpireLeakOrReorder(t *testing.T) {
	legacy := `{"schemaVersion":"gruff-go.baseline.v0.1","findings":[]}`
	if _, err := Parse([]byte(legacy)); err == nil || !strings.Contains(err.Error(), "--migrate") {
		t.Fatalf("parse legacy = %v, want the migration command", err)
	}
	cases := map[string]File{
		"unsorted":   {SchemaVersion: SchemaVersion, ToolLanguage: "go", GeneratedAt: "x", Occurrences: []Occurrence{{Identity: "ffffffffffffffff", Count: 1}, {Identity: "0000000000000000", Count: 1}}},
		"duplicate":  {SchemaVersion: SchemaVersion, ToolLanguage: "go", GeneratedAt: "x", Occurrences: []Occurrence{{Identity: "0000000000000000", Count: 1}, {Identity: "0000000000000000", Count: 1}}},
		"zero count": {SchemaVersion: SchemaVersion, ToolLanguage: "go", GeneratedAt: "x", Occurrences: []Occurrence{{Identity: "0000000000000000", Count: 0}}},
		"foreign":    {SchemaVersion: SchemaVersion, ToolLanguage: "java", GeneratedAt: "x"},
		"eligible":   {SchemaVersion: SchemaVersion, ToolLanguage: "go", GeneratedAt: "x", Sensitive: SensitiveSummary{Eligible: true}},
		"counts":     {SchemaVersion: SchemaVersion, ToolLanguage: "go", GeneratedAt: "x", Sensitive: SensitiveSummary{Counts: SensitiveCounts{Total: 5}}},
	}
	for name, file := range cases {
		if err := Validate(file); err == nil {
			t.Fatalf("%s: validate accepted an invalid file", name)
		}
	}
	if _, err := Parse([]byte(`{"schemaVersion":"gruff.baseline.v3","toolLanguage":"go","generatedAt":"x","occurrences":[{"identity":"0000000000000000","count":1,"line":10}],"sensitive":{"eligible":false,"reason":"r","counts":{"total":0,"byRule":{}}}}`)); err == nil {
		t.Fatal("an occurrence carrying line must be rejected")
	}
}

// TestMigrationPreservesTheRetreatPath refuses in-place targets, keeps the 0.5
// input byte-identical, writes a valid v3 file, and translates no 0.5 digest.
func TestMigrationPreservesTheRetreatPath(t *testing.T) {
	root := t.TempDir()
	inputPath := filepath.Join(root, "legacy.json")
	legacyBytes := "{\n  \"schemaVersion\": \"gruff-go.baseline.v0.1\",\n  \"findings\": [{\"ruleId\": \"docs.missing-package-comment\", \"file\": \"internal/widget/widget.go\", \"fingerprint\": \"0e2f6d4b9a1c7e35\", \"stableIdentity\": \"77c1a4e6b0d3f912\"}]\n}\n"
	if err := os.WriteFile(inputPath, []byte(legacyBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	run := []finding.Finding{ordinary("process", 10), ordinary("unreviewed", 90)}
	run[1].RuleID = "naming.generic-function"
	if _, err := Migrate(inputPath, inputPath, run, stamp); err == nil || !strings.Contains(err.Error(), "same file") {
		t.Fatalf("same-path migration = %v, want refusal", err)
	}
	linkPath := filepath.Join(root, "link.json")
	if err := os.Symlink(inputPath, linkPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Migrate(inputPath, linkPath, run, stamp); err == nil || !strings.Contains(err.Error(), "resolves to the input") {
		t.Fatalf("symlink migration = %v, want refusal", err)
	}
	outputPath := filepath.Join(root, "gruff-baseline.json")
	result, err := Migrate(inputPath, outputPath, run, stamp)
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 1 || result.Occurrences != 1 {
		t.Fatalf("migration = %#v, want one accepted occurrence", result)
	}
	after, _ := os.ReadFile(inputPath)
	if string(after) != legacyBytes {
		t.Fatal("migration changed the 0.5 input")
	}
	written, err := Load(outputPath)
	if err != nil {
		t.Fatalf("migrated output must load as v3: %v", err)
	}
	if written.Occurrences[0].Identity == "0e2f6d4b9a1c7e35" || written.Occurrences[0].Identity == "77c1a4e6b0d3f912" {
		t.Fatal("migration translated a 0.5 digest instead of rebuilding the identity")
	}
	if _, err := ParseLegacy(mustRead(t, outputPath)); err == nil {
		t.Fatal("a 0.5 reader must refuse the v3 output")
	}
}

// mustRead reads a file or fails the test.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestMeasuredValuesNeverEnterASymbolLessIdentity keeps a file that grew behind
// its reviewed entry: the message names the finding, its numbers do not.
func TestMeasuredValuesNeverEnterASymbolLessIdentity(t *testing.T) {
	reviewed := finding.Finding{RuleID: "size.file-length", File: "src/widget.go", Message: "File has 1010 lines (limit 1000)"}
	grown := reviewed
	grown.Message = "File has 1,200 lines (limit 1000)"
	reworded := reviewed
	reworded.Message = "File is 1010 lines long (limit 1000)"

	reviewedIdentity, err := reviewed.ComputeBaselineIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	grownIdentity, err := grown.ComputeBaselineIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	rewordedIdentity, err := reworded.ComputeBaselineIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if grownIdentity != reviewedIdentity {
		t.Fatalf("a changed measurement re-keyed the finding: %s != %s", grownIdentity, reviewedIdentity)
	}
	// Rewording is still a new name: the message is the only stable thing a symbol-less finding has.
	if rewordedIdentity == reviewedIdentity {
		t.Fatalf("a reworded message kept the identity %s", reviewedIdentity)
	}
	if subject := finding.NormaliseMeasuredValues("12.5% over 1,234 lines in v0.5.2"); subject != "#% over # lines in v#" {
		t.Fatalf("normalised subject = %q", subject)
	}
}

// TestSymbolLessOccurrencesAreCountedNotCollided keeps two measurements of one
// file matched by count: they name no declaration, so nothing could separate
// them and a collision would suppress neither and block the run forever.
func TestSymbolLessOccurrencesAreCountedNotCollided(t *testing.T) {
	reviewed := finding.Finding{RuleID: "size.function-length", File: "src/widget.go", Message: "Function has 12 parameters", Location: &finding.Location{Line: 10}}
	second := reviewed
	second.Message = "Function has 14 parameters"
	second.Location = &finding.Location{Line: 90}

	file, err := FromFindings([]finding.Finding{reviewed})
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	result, err := Apply([]finding.Finding{reviewed, second}, file)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	got := counts{result.UnchangedFindings, result.NewFindings, result.ResolvedFindings, result.CollisionFindings, result.NotEligibleFindings}
	if want := (counts{1, 1, 0, 0, 0}); got != want {
		t.Fatalf("counts {unchanged added resolved collision notEligible} = %+v, want %+v", got, want)
	}
}

// TestMigrationRefusesAnAmbiguousInput keeps a 0.5 file that names two row
// containers from migrating one way here and another way in a sibling port.
func TestMigrationRefusesAnAmbiguousInput(t *testing.T) {
	root := t.TempDir()
	inputPath := filepath.Join(root, "legacy.json")
	legacyBytes := []byte(`{"schemaVersion":"gruff-go.baseline.v0.1","findings":[{"ruleId":"docs.example","file":"src/example.go","fingerprint":"5b1d9c0a3e7f2648"}],"entries":[]}`)
	if err := os.WriteFile(inputPath, legacyBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(root, "migrated.json")
	_, err := Migrate(inputPath, outputPath, []finding.Finding{ordinary("Process", 10)}, time.Now().UTC())

	if err == nil || !strings.Contains(err.Error(), "more than one row container") {
		t.Fatalf("migration error = %v, want a refusal naming the containers", err)
	}
	after, readErr := os.ReadFile(inputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, legacyBytes) {
		t.Fatal("a refused migration changed the 0.5 input")
	}
	// A refused migration writes nothing, so the user is not left with a half-migrated second file.
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Fatalf("refused migration wrote an output file: %v", statErr)
	}
}

// TestMigrationRefusesAHardLinkedOutput keeps a second name for one inode from
// overwriting the retreat copy the migration is supposed to preserve.
func TestMigrationRefusesAHardLinkedOutput(t *testing.T) {
	root := t.TempDir()
	inputPath := filepath.Join(root, "legacy.json")
	legacyBytes := []byte(`{"schemaVersion":"gruff-go.baseline.v0.1","findings":[{"ruleId":"docs.example","file":"src/example.go","fingerprint":"5b1d9c0a3e7f2648"}]}`)
	if err := os.WriteFile(inputPath, legacyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(root, "hard-link.json")
	if err := os.Link(inputPath, outputPath); err != nil {
		t.Fatal(err)
	}

	_, err := Migrate(inputPath, outputPath, []finding.Finding{ordinary("Process", 10)}, time.Now().UTC())

	if err == nil || !strings.Contains(err.Error(), "resolves to the input path") {
		t.Fatalf("migration error = %v, want a refusal naming the resolved path", err)
	}
	after, readErr := os.ReadFile(inputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, legacyBytes) {
		t.Fatal("a refused migration changed the 0.5 input")
	}
}

// TestABaselineOnlyEverRemovesReviewedFindings is the ratified score-and-exit
// invariant: applying a baseline may remove unchanged ordinary findings from the
// score and the exit code and nothing else. If any other total moves, enforcement
// moved silently and the run is wrong.
func TestABaselineOnlyEverRemovesReviewedFindings(t *testing.T) {
	reviewed := ordinary("Process", 10)
	fresh := ordinary("Handle", 40)
	secret := finding.Finding{
		RuleID:   "sensitive-data.secret-pattern",
		File:     "secrets.env",
		Pillar:   finding.PillarSensitiveData,
		Message:  "secret-like assignment detected",
		Location: &finding.Location{Line: 1},
	}

	file, err := FromFindings([]finding.Finding{reviewed, secret})
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	result, err := Apply([]finding.Finding{reviewed, fresh, secret}, file)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Only the reviewed finding leaves the gated set; the new one and the secret still fail the run.
	if len(result.Findings) != 2 {
		t.Fatalf("gated findings = %d, want the new finding and the secret: %#v", len(result.Findings), result.Findings)
	}
	got := counts{result.UnchangedFindings, result.NewFindings, result.ResolvedFindings, result.CollisionFindings, result.NotEligibleFindings}
	if want := (counts{1, 1, 0, 0, 1}); got != want {
		t.Fatalf("counts {unchanged added resolved collision notEligible} = %+v, want %+v", got, want)
	}
	if result.GatedCount() != 2 {
		t.Fatalf("gated count = %d, want 2: the score and the exit code count exactly the gated set", result.GatedCount())
	}
}

// TestDefaultPathProtectionKeepsTheRetreatCopy covers the four ratified cases:
// a pathless generate refuses over a 0.5 file, --force overrides it, v3 over v3
// is not destructive, and an empty project has nothing to protect.
func TestDefaultPathProtectionKeepsTheRetreatCopy(t *testing.T) {
	root := t.TempDir()
	defaultPath := filepath.Join(root, DefaultFilename)
	legacyBytes := []byte(`{"schemaVersion":"gruff-go.baseline.v0.1","findings":[]}`)

	// An empty project has nothing to protect.
	if err := RequireOverwritableDefaultPath(defaultPath, false); err != nil {
		t.Fatalf("an empty project must generate freely: %v", err)
	}

	if err := os.WriteFile(defaultPath, legacyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	err := RequireOverwritableDefaultPath(defaultPath, false)
	if err == nil || !strings.Contains(err.Error(), DefaultFilename) || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("refusal = %v, want one naming the file and --force", err)
	}
	// The refusal is not a write: the retreat copy is exactly as the user left it.
	after, readErr := os.ReadFile(defaultPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, legacyBytes) {
		t.Fatal("a refused generate changed the 0.5 baseline")
	}
	// The destructive case stays available and stays explicit.
	if err := RequireOverwritableDefaultPath(defaultPath, true); err != nil {
		t.Fatalf("--force must overwrite: %v", err)
	}

	// Regenerating v3 over v3 is not destructive, because v3 is what the tool now reads.
	file, err := FromFindings([]finding.Finding{ordinary("Process", 10)})
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(defaultPath, file); err != nil {
		t.Fatal(err)
	}
	if err := RequireOverwritableDefaultPath(defaultPath, false); err != nil {
		t.Fatalf("regenerating v3 over v3 must be allowed: %v", err)
	}
}

// TestAWrittenBaselineCarriesNoSentinel is proof C2's artifact half: a generated
// baseline holds no sensitive material in any form, so a file a team commits and
// shares cannot leak the secret it was counting.
func TestAWrittenBaselineCarriesNoSentinel(t *testing.T) {
	// A synthetic AWS-shaped literal, not a live credential; it exists to be searched for.
	sentinel := "AKIA" + "IOSFODNN7EXAMPLE"
	secret := finding.Finding{
		RuleID:   "sensitive-data.aws-access-key",
		File:     "src/config.go",
		Pillar:   finding.PillarSensitiveData,
		Message:  "possible AWS access key " + sentinel + " in a literal",
		Location: &finding.Location{Line: 3},
	}
	root := t.TempDir()
	outputPath := filepath.Join(root, DefaultFilename)

	file, err := FromFindings([]finding.Finding{secret})
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(outputPath, file); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}

	// Raw, partial, hashed and base64 forms are each searched for: a derived value is still the secret.
	for name, form := range sentinelForms(sentinel) {
		if bytes.Contains(written, []byte(form)) {
			t.Fatalf("the written baseline carries the %s form of the sentinel", name)
		}
	}
	// What it does carry is a count, which is what makes the secret auditable without naming it.
	if !bytes.Contains(written, []byte(`"sensitive-data.aws-access-key": 1`)) {
		t.Fatalf("the written baseline must still count the secret by rule: %s", written)
	}
}

// sentinelForms returns every shape a leaked secret could take in an artifact.
func sentinelForms(sentinel string) map[string]string {
	digest := sha256.Sum256([]byte(sentinel))
	return map[string]string{
		"raw":     sentinel,
		"partial": sentinel[:8],
		"hashed":  hex.EncodeToString(digest[:]),
		"encoded": base64.StdEncoding.EncodeToString([]byte(sentinel)),
	}
}
