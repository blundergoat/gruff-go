package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
)

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

func TestPackageStutterAllowsDefaultExactMatch(t *testing.T) {
	unit := parseOne(t, "finding/finding.go", `package finding

type Finding struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("default allowlist should permit finding.Finding; got %#v", got)
	}
}

func TestPackageStutterAllowsConfigConfig(t *testing.T) {
	unit := parseOne(t, "config/config.go", `package config

type Config struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("default allowlist should permit config.Config; got %#v", got)
	}
}

func TestPackageStutterIgnoresNonStutter(t *testing.T) {
	unit := parseOne(t, "config/parser.go", `package config

type Parser struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("non-stutter type should not fire; got %#v", got)
	}
}

func TestPackageStutterIgnoresExtendedWord(t *testing.T) {
	unit := parseOne(t, "rule/rules.go", `package rule

type Rules struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("Rules extends the package name as a single word; should not fire; got %#v", got)
	}
}

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

func TestPackageStutterSkipsMethods(t *testing.T) {
	unit := parseOne(t, "rule/foo.go", `package rule

type Holder struct{}

func (Holder) RuleApply() {}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("methods should not be checked (receiver makes them unambiguous); got %#v", got)
	}
}

func TestPackageStutterSkipsUnexported(t *testing.T) {
	unit := parseOne(t, "rule/foo.go", `package rule

type ruleInternal struct{}
`)
	if got := (PackageStutterRule{}).AnalyzeProject([]parser.Unit{unit}, Context{}); len(got) != 0 {
		t.Fatalf("unexported names are package-internal and should not fire; got %#v", got)
	}
}

func TestPackageStutterHonoursCustomAllow(t *testing.T) {
	unit := parseOne(t, "rule/registry.go", `package rule

type RuleRegistry struct{}
`)
	findings := PackageStutterRule{AllowStutter: []string{"RuleRegistry"}}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("custom allowlist should suppress; got %#v", findings)
	}
}

func TestPackageStutterIsDefaultEnabled(t *testing.T) {
	if !(PackageStutterRule{}).Definition().DefaultEnabled {
		t.Error("naming.package-stutter must be default-enabled")
	}
	if (PackageStutterRule{}).Definition().Capability != CapabilityParser {
		t.Error("naming.package-stutter must be parser-capability")
	}
}
