// Package rule defines gruff-go's rule registry and analysers.
// This file exercises the naming.package-stutter rule across declaration kinds.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestPackageStutterFlagsStutteredType confirms a type whose name repeats its package is flagged.
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
func TestPackageStutterAllowsDefaultExactMatch(t *testing.T) {
	unit := parseOne(t, "finding/finding.go", `package finding

type Finding struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("default allowlist should permit finding.Finding; got %#v", got)
	}
}

// TestPackageStutterAllowsConfigConfig confirms the default allow list covers config.Config.
func TestPackageStutterAllowsConfigConfig(t *testing.T) {
	unit := parseOne(t, "config/config.go", `package config

type Config struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("default allowlist should permit config.Config; got %#v", got)
	}
}

// TestPackageStutterIgnoresNonStutter ensures unrelated identifier names do not trigger findings.
func TestPackageStutterIgnoresNonStutter(t *testing.T) {
	unit := parseOne(t, "config/parser.go", `package config

type Parser struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("non-stutter type should not fire; got %#v", got)
	}
}

// TestPackageStutterIgnoresExtendedWord confirms identifiers extending the package name as one word do not fire.
func TestPackageStutterIgnoresExtendedWord(t *testing.T) {
	unit := parseOne(t, "rule/rules.go", `package rule

type Rules struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("Rules extends the package name as a single word; should not fire; got %#v", got)
	}
}

// TestPackageStutterFlagsConcatenatedPackageName verifies concatenated package names still stutter.
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

// TestPackageStutterFlagsFunctions ensures exported functions are scanned alongside types.
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
func TestPackageStutterSkipsUnexported(t *testing.T) {
	unit := parseOne(t, "rule/foo.go", `package rule

type ruleInternal struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("unexported names are package-internal and should not fire; got %#v", got)
	}
}

// TestPackageStutterHonoursCustomAllow verifies the AllowStutter option suppresses the named identifier.
func TestPackageStutterHonoursCustomAllow(t *testing.T) {
	unit := parseOne(t, "rule/registry.go", `package rule

type RuleRegistry struct{}
`)
	findings := PackageStutterRule{AllowStutter: []string{"RuleRegistry"}}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("custom allowlist should suppress; got %#v", findings)
	}
}

// TestPackageStutterIsDefaultEnabled asserts the rule ships enabled with parser capability.
func TestPackageStutterIsDefaultEnabled(t *testing.T) {
	if !(PackageStutterRule{}).Definition().DefaultEnabled {
		t.Error("naming.package-stutter must be default-enabled")
	}
	if (PackageStutterRule{}).Definition().Capability != CapabilityParser {
		t.Error("naming.package-stutter must be parser-capability")
	}
}
