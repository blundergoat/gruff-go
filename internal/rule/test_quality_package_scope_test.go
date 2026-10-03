// Package rule tests the package-scoped shapes test-quality.no-failure-path must credit.
//
// Every case here is a shape measured in the family precision corpus on 2026-09-07, where the
// rule reported a test that demonstrably can fail. The final case is the negative control: a
// test that genuinely cannot fail must still be reported, because a rule that credits
// everything is worth nothing.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// noFailurePathSymbols reports the tests the rule flags across a whole package.
func noFailurePathSymbols(t *testing.T, units ...parser.Unit) []string {
	t.Helper()
	symbols := []string{}
	for _, item := range (NoFailurePathTestRule{}).AnalyzeProject(units, Context{}) {
		symbols = append(symbols, item.Symbol)
	}
	return symbols
}

// requireSymbols fails unless the rule flagged exactly the expected tests.
func requireSymbols(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("flagged %v, want %v", got, want)
	}
	for index, symbol := range want {
		if got[index] != symbol {
			t.Fatalf("flagged %v, want %v", got, want)
		}
	}
}

// A failure helper declared in a sibling _test.go is still visible to the test that calls it.
// Measured in gorm, where fourteen table tests delegated to clause_test.go's checkBuildClauses.
func TestNoFailurePathCreditsHelperFromSiblingFile(t *testing.T) {
	caller := parseOne(t, "pkg/delete_test.go", `package pkg

import "testing"

func TestDelete(t *testing.T) {
	checkBuild(t, "DELETE")
}
`)
	helper := parseOne(t, "pkg/clause_test.go", `package pkg

import "testing"

func checkBuild(t *testing.T, want string) {
	if want == "" {
		t.Errorf("empty")
	}
}
`)

	requireSymbols(t, noFailurePathSymbols(t, caller, helper))

	// Without its sibling the helper is invisible, which is exactly the old behaviour.
	requireSymbols(t, noFailurePathSymbols(t, caller), "TestDelete")
}

// A method that takes the testing receiver fails the test exactly as a free function does.
func TestNoFailurePathCreditsMethodHelper(t *testing.T) {
	unit := parseOne(t, "pkg/harness_test.go", `package pkg

import "testing"

type harness struct{}

func (h *harness) verify(t *testing.T, ok bool) {
	if !ok {
		t.Fatalf("not ok")
	}
}

func TestViaMethod(t *testing.T) {
	h := &harness{}
	h.verify(t, true)
}
`)

	requireSymbols(t, noFailurePathSymbols(t, unit))
}

// Inside an assertion library the package's own assertions are called without a qualifier.
// Measured in testify, the single largest shape at 118 findings in one package.
func TestNoFailurePathCreditsInPackageAssertion(t *testing.T) {
	inside := parseOne(t, "assert/assertions_test.go", `package assert

import "testing"

func TestBytesEqual(t *testing.T) {
	Equal(t, 1, 1, "case")
}
`)

	requireSymbols(t, noFailurePathSymbols(t, inside))

	// The same bare call outside such a package is ordinary project code and stays reported,
	// which is what keeps this credit from suppressing real findings everywhere.
	outside := parseOne(t, "pkg/widget_test.go", `package pkg

import "testing"

func TestBare(t *testing.T) {
	Equal(t, 1, 1, "case")
}
`)

	requireSymbols(t, noFailurePathSymbols(t, outside), "TestBare")
}

// A subtest handed a function value runs assertions this walk cannot enter.
// Measured in cobra, where t.Run(name, tc.test) accounted for most of the package's findings.
func TestNoFailurePathCreditsDelegatedSubtest(t *testing.T) {
	unit := parseOne(t, "pkg/command_test.go", `package pkg

import "testing"

type testcase struct{}

func (tc *testcase) test(t *testing.T) {
	t.Errorf("boom")
}

func TestCalledAs(t *testing.T) {
	cases := map[string]*testcase{"one": {}}
	for name, tc := range cases {
		t.Run(name, tc.test)
	}
}
`)

	requireSymbols(t, noFailurePathSymbols(t, unit))
}

// A Ginkgo bootstrap hands the suite to a runner whose specs this parser never sees.
// Measured in gosec, where every suite file was reported.
func TestNoFailurePathCreditsGinkgoSuite(t *testing.T) {
	dotImported := parseOne(t, "pkg/suite_test.go", `package pkg

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAnalyzers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Analyzers Suite")
}
`)

	requireSymbols(t, noFailurePathSymbols(t, dotImported))

	// The qualified spelling is the same handover and must be credited too.
	qualified := parseOne(t, "pkg/qualified_test.go", `package pkg

import (
	"testing"

	ginkgo "github.com/onsi/ginkgo/v2"
)

func TestQualified(t *testing.T) {
	ginkgo.RunSpecs(t, "Suite")
}
`)

	requireSymbols(t, noFailurePathSymbols(t, qualified))
}

// The negative control. None of the credits above may rescue a test that cannot fail.
func TestNoFailurePathStillReportsATestThatCannotFail(t *testing.T) {
	unit := parseOne(t, "pkg/plain_test.go", `package pkg

import "testing"

func TestNoAssertion(t *testing.T) {
	t.Log("running")
}

func TestAlsoNothing(t *testing.T) {
	value := 1 + 1
	_ = value
}
`)

	requireSymbols(t, noFailurePathSymbols(t, unit), "TestNoAssertion", "TestAlsoNothing")
}

// Two packages in one directory cannot see each other's helpers, so the grouping must keep
// them apart. Without the package clause in the key, an external test package would silently
// credit helpers it cannot actually call.
func TestNoFailurePathKeepsExternalTestPackageSeparate(t *testing.T) {
	internal := parseOne(t, "pkg/internal_test.go", `package pkg

import "testing"

func checkInternal(t *testing.T) {
	t.Errorf("boom")
}
`)
	external := parseOne(t, "pkg/external_test.go", `package pkg_test

import "testing"

func TestExternal(t *testing.T) {
	checkInternal(t)
}
`)

	requireSymbols(t, noFailurePathSymbols(t, internal, external), "TestExternal")
}

var _ = finding.Finding{}
