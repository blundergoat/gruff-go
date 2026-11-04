// Package rule defines gruff-go's rule registry and analysers.
//
// This file tests naming.package-stutter, the opt-in rule that flags an exported type or function whose name repeats its package name.
// It checks which names get a finding, the default and custom allow lists, and that the rule ships opt-in with parser capability.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestPackageStutterFlagsStutteredType checks that RuleRegistry, which callers read as rule.RuleRegistry, gets a stutter finding.
func TestPackageStutterFlagsStutteredType(t *testing.T) {
	unit := parseOne(t, "rule/registry.go", `package rule

type RuleRegistry struct{}
`)
	findings := PackageStutterRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
	got := findingSymbols(findings)
	if !got["RuleRegistry"] {
		t.Fatalf("findings should flag RuleRegistry; got %#v", findings)
	}
}

// TestPackageStutterAllowsDefaultExactMatch checks the default allow list permits finding.Finding.
// A failure means users enabling the rule would get a finding for the conventional finding.Finding type.
func TestPackageStutterAllowsDefaultExactMatch(t *testing.T) {
	unit := parseOne(t, "finding/finding.go", `package finding

type Finding struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("default allowlist should permit finding.Finding; got %#v", got)
	}
}

// TestPackageStutterAllowsConfigConfig confirms the default allow list covers config.Config.
// A failure means users enabling the rule would get a finding for the conventional config.Config type.
func TestPackageStutterAllowsConfigConfig(t *testing.T) {
	unit := parseOne(t, "config/config.go", `package config

type Config struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("default allowlist should permit config.Config; got %#v", got)
	}
}

// TestPackageStutterIgnoresNonStutter checks that config.Parser, whose name repeats nothing of its package, gets no finding.
func TestPackageStutterIgnoresNonStutter(t *testing.T) {
	unit := parseOne(t, "config/parser.go", `package config

type Parser struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("non-stutter type should not fire; got %#v", got)
	}
}

// TestPackageStutterIgnoresExtendedWord confirms identifiers extending the package name as one word do not fire.
// Rules in package rule reads as one word, so a finding for it would be a false positive.
func TestPackageStutterIgnoresExtendedWord(t *testing.T) {
	unit := parseOne(t, "rule/rules.go", `package rule

type Rules struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("Rules extends the package name as a single word; should not fire; got %#v", got)
	}
}

// TestPackageStutterFlagsConcatenatedPackageName verifies concatenated package names still stutter.
// HttpServerOptions in package httpserver must be flagged even though the package name has no word break.
func TestPackageStutterFlagsConcatenatedPackageName(t *testing.T) {
	unit := parseOne(t, "httpserver/options.go", `package httpserver

type HttpServerOptions struct{}
`)
	findings := PackageStutterRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
	got := findingSymbols(findings)
	if !got["HttpServerOptions"] {
		t.Fatalf("HttpServerOptions in httpserver should stutter; got %#v", findings)
	}
}

// TestPackageStutterFlagsFunctions checks that an exported function such as RuleBuild, read as rule.RuleBuild, is flagged like a type.
func TestPackageStutterFlagsFunctions(t *testing.T) {
	unit := parseOne(t, "rule/build.go", `package rule

func RuleBuild() {}
`)
	findings := PackageStutterRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
	got := findingSymbols(findings)
	if !got["RuleBuild"] {
		t.Fatalf("function RuleBuild in rule should stutter; got %#v", findings)
	}
}

// TestPackageStutterSkipsMethods asserts methods with receivers are not flagged as stutter.
// Holder.RuleApply is read through its receiver, so a finding for it would be noise.
func TestPackageStutterSkipsMethods(t *testing.T) {
	unit := parseOne(t, "rule/foo.go", `package rule

type Holder struct{}

func (Holder) RuleApply() {}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("methods should not be checked (receiver makes them unambiguous); got %#v", got)
	}
}

// TestPackageStutterSkipsUnexported asserts unexported identifiers are excluded from checks.
// ruleInternal is never seen by the package's callers, so the rule must not report it.
func TestPackageStutterSkipsUnexported(t *testing.T) {
	unit := parseOne(t, "rule/foo.go", `package rule

type ruleInternal struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("unexported names are package-internal and should not fire; got %#v", got)
	}
}

// TestPackageStutterHonoursCustomAllow checks that listing RuleRegistry in AllowStutter lets a project keep that name with no finding.
func TestPackageStutterHonoursCustomAllow(t *testing.T) {
	unit := parseOne(t, "rule/registry.go", `package rule

type RuleRegistry struct{}
`)
	findings := PackageStutterRule{AllowStutter: []string{"RuleRegistry"}}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("custom allowlist should suppress; got %#v", findings)
	}
}

// TestPackageStutterIsOptIn asserts the convention-only rule ships opt-in with parser capability.
// A failure means default scans would start reporting stutter, or the rule would declare a capability other than CapabilityParser.
func TestPackageStutterIsOptIn(t *testing.T) {
	if (PackageStutterRule{}).Definition().DefaultEnabled {
		t.Error("naming.package-stutter must be opt-in")
	}
	if (PackageStutterRule{}).Definition().Capability != CapabilityParser {
		t.Error("naming.package-stutter must be parser-capability")
	}
}
