// Package rule tests initialism guidance shown to Go users who enable naming.acronym-case.
//
// Idiomatic names stay quiet while mixed casing such as userId receives a concrete replacement.
// Generated files are checked only when the run includes ignored files; cgo-owned selectors stay outside Go rename findings.
package rule

import (
	"strings"
	"testing"
)

// TestAcronymCaseFlagsMixedCaseInitialisms checks that mixed-case initialisms in type, field, function, var and const names are flagged.
//
// Each finding's message recommends the canonical spelling, though this test checks only which names are flagged.
// A failure means a user would miss a finding such as userId, or get one on a name already cased like HTTPClient.
func TestAcronymCaseFlagsMixedCaseInitialisms(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type HttpClient struct {
	UrlParser  string
	HTTPClient string
}

type IdGenerator struct{}

func JsonReport(url URLParser) {
	var userId = 1
	_ = userId
}

type URLParser struct{}

var AwsRegion = "us-east-1"

const JwtToken = "token"
`)
	findings := AcronymCaseRule{}.AnalyzeUnit(unit, Context{})
	got := findingSymbols(findings)
	want := []string{"HttpClient", "UrlParser", "IdGenerator", "JsonReport", "userId", "AwsRegion", "JwtToken"}
	for _, symbol := range want {
		if !got[symbol] {
			t.Fatalf("findings = %#v, want symbol %q", findings, symbol)
		}
	}
	// A hit here means the rule would ask users to rename names already in Go's canonical casing.
	if got["HTTPClient"] || got["URLParser"] {
		t.Fatalf("correctly cased acronyms should not be flagged; got %#v", findings)
	}
	// An extra symbol, such as the all-lowercase url parameter, means users would see a finding outside the seven expected names.
	if len(got) != len(want) {
		t.Fatalf("findings = %#v, want exactly %v", findings, want)
	}
}

// TestAcronymCaseAllowsConsistentCase verifies that consistently cased initialisms produce no findings.
func TestAcronymCaseAllowsConsistentCase(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type HTTPClient struct {
	URLParser string
}

type IDGenerator struct{}

func JSONReport(urlParser URLParser) {
	userID := 1
	jwtToken := "token"
	_ = userID
	_ = jwtToken
}

type URLParser struct{}
`)
	findings := AcronymCaseRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("consistent acronym casing should pass, got %#v", findings)
	}
}

// TestAcronymCaseRemediationNamesAndAcceptsGoInitialisms connects the catalogue
// guidance users read to the exact identifier changes that clear the finding.
func TestAcronymCaseRemediationNamesAndAcceptsGoInitialisms(t *testing.T) {
	driftUnit := parseOne(t, "pkg/drift.go", `package pkg

type ParseUrl struct{}

func remember(userId int) {
	_ = userId
}
`)
	driftFindings := AcronymCaseRule{}.AnalyzeUnit(driftUnit, Context{})
	// Both common drift shapes should direct the user to Go's canonical spelling.
	if len(driftFindings) != 2 {
		t.Fatalf("mixed-case findings = %#v, want ParseUrl and userId", driftFindings)
	}

	remediation := AcronymCaseRule{}.Definition().Remediation
	// Concrete examples in the remediation text let the user apply the fix without inferring casing rules.
	if !strings.Contains(remediation, "parseURL") || !strings.Contains(remediation, "userID") {
		t.Fatalf("remediation = %q, want parseURL and userID examples", remediation)
	}

	fixedUnit := parseOne(t, "pkg/fixed.go", `package pkg

type ParseURL struct{}

func remember(userID int) {
	_ = userID
}
`)
	fixedFindings := AcronymCaseRule{}.AnalyzeUnit(fixedUnit, Context{})
	// Applying the catalogue's named replacements should leave the user with a clean scan.
	if len(fixedFindings) != 0 {
		t.Fatalf("fixed initialism findings = %#v, want none", fixedFindings)
	}
}

// TestAcronymCaseHonoursAllowAndAcceptedAbbreviations exercises both per-identifier and per-acronym allow lists.
// Allow must exempt HttpClient and AcceptedAbbreviations must exempt UrlParser, while JsonReport still reports.
func TestAcronymCaseHonoursAllowAndAcceptedAbbreviations(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type HttpClient struct{}
type UrlParser struct{}
type JsonReport struct{}
`)
	rule := AcronymCaseRule{
		Allow:                 []string{"HttpClient"},
		AcceptedAbbreviations: []string{"URL"},
	}
	findings := rule.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "JsonReport" {
		t.Fatalf("expected only JsonReport after allowlists, got %#v", findings)
	}
}

// TestAcronymCaseSupportsConfiguredAcronyms verifies that custom acronyms replace the defaults when configured.
func TestAcronymCaseSupportsConfiguredAcronyms(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type UuidStore struct{}
type UUIDCache struct{}
type HttpClient struct{}
`)
	rule := AcronymCaseRule{Acronyms: []string{"UUID"}}
	findings := rule.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "UuidStore" {
		t.Fatalf("expected only configured UUID acronym finding, got %#v", findings)
	}
}

// TestAcronymCaseSkipsGeneratedFiles confirms generated-file markers suppress acronym findings.
func TestAcronymCaseSkipsGeneratedFiles(t *testing.T) {
	unit := parseOne(t, "pkg/generated.go", `// Code generated by tool; DO NOT EDIT.
package pkg

type HttpClient struct{}
`)
	findings := AcronymCaseRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("generated file should be skipped, got %#v", findings)
	}
}

// TestAcronymCaseIncludeIgnoredScansGeneratedFiles verifies rule-level generated guards honor the run scope that deliberately includes ignored files.
func TestAcronymCaseIncludeIgnoredScansGeneratedFiles(t *testing.T) {
	unit := parseOne(t, "pkg/generated.go", `// Generated by tool. DO NOT EDIT.
package pkg

type HttpClient struct{}
`)
	findings := AcronymCaseRule{}.AnalyzeUnit(unit, Context{IncludeIgnored: true})
	if len(findings) != 1 || findings[0].Symbol != "HttpClient" {
		t.Fatalf("include-ignored generated unit should be analysed, got %#v", findings)
	}
}

// TestAcronymCaseGeneratedHeaderRequiresBothMarkers keeps bare DO NOT EDIT prose from suppressing a hand-authored source file.
func TestAcronymCaseGeneratedHeaderRequiresBothMarkers(t *testing.T) {
	unit := parseOne(t, "pkg/manual.go", `// DO NOT EDIT this fixture without updating tests.
package pkg

type HttpClient struct{}
`)
	findings := AcronymCaseRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "HttpClient" {
		t.Fatalf("bare DO NOT EDIT should not suppress hand-authored file, got %#v", findings)
	}
}

// TestAcronymCaseIgnoresCgoSelectorIdentifiers confirms C-owned underscore names
// do not become Go rename findings when a user calls them through package C.
func TestAcronymCaseIgnoresCgoSelectorIdentifiers(t *testing.T) {
	unit := parseOne(t, "pkg/cgo.go", `package pkg

/*
int read_url_id(void) { return 1; }
*/
import "C"

func cgoURLID() int {
	return int(C.read_url_id())
}
`)
	findings := AcronymCaseRule{}.AnalyzeUnit(unit, Context{})
	// A quiet result leaves generated C naming under cgo ownership instead of asking the Go user to rename it.
	if len(findings) != 0 {
		t.Fatalf("cgo selector findings = %#v, want none", findings)
	}
}

// TestAcronymCaseIsOptIn asserts the convention-only rule is opt-in and tagged as parser-capability.
func TestAcronymCaseIsOptIn(t *testing.T) {
	if (AcronymCaseRule{}).Definition().DefaultEnabled {
		t.Error("naming.acronym-case must be opt-in")
	}
	if (AcronymCaseRule{}).Definition().Capability != CapabilityParser {
		t.Error("naming.acronym-case must be parser-capability")
	}
}
