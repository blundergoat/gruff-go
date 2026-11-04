// Package rule tests the recovery boundary that exempts a package from maintainability.production-panic.
//
// A package that panics deliberately declares the matching deferred recover in whichever file owns
// its entry point. Judged one file at a time every such panic looks unhandled, which is the shape
// measured in the precision corpus at twenty emissions.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// analyseProductionPanicUnit runs the package-scoped rule over a single file.
//
// The unit is wrapped as a one-file package with a zero Context, so a recovery declared in a sibling file is not seen.
// It returns the findings ProductionPanicRule reports for that file alone; an empty result means the rule reported no panics.
func analyseProductionPanicUnit(unit parser.Unit) []finding.Finding {
	return ProductionPanicRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
}

// analyseProductionPanic runs the rule over several files of one package at once.
//
// The units are passed with a zero Context, so a qualifying recovery boundary in any eligible production file of the package is visible.
// A recovery declared in an excluded file, such as a _test.go file, lends the package no boundary.
//
// It returns the findings ProductionPanicRule reports across all units; an empty result means the rule reported no panics.
func analyseProductionPanic(units ...parser.Unit) []finding.Finding {
	return ProductionPanicRule{}.AnalyzeProject(units, Context{})
}

// The promql shape: the panic is deep in one file and the recovery is at the entry point in another.
// A failure means a recovery in a sibling file no longer exempts the package, or a file judged alone no longer reports its panic.
func TestProductionPanicExemptsAPackageThatRecoversIntoAnError(t *testing.T) {
	panics := parseOne(t, "promql/eval.go", `package promql

func evaluate(depth int) {
	if depth < 0 {
		panic("negative depth")
	}
}
`)
	// The real shape: a named handler taking an *error, deferred by reference from the entry
	// point. prometheus/promql writes exactly this.
	recovers := parseOne(t, "promql/engine.go", `package promql

func handle(errp *error) {
	e := recover()
	if e == nil {
		return
	}
	*errp = errFromRecover(e)
}

func Query() (err error) {
	defer handle(&err)
	evaluate(1)
	return nil
}

func errFromRecover(r any) error { return nil }
`)

	if got := analyseProductionPanic(panics, recovers); len(got) != 0 {
		t.Fatalf("package with a recovery boundary reported %d panics, want 0", len(got))
	}

	// Without its sibling the boundary is invisible, so the same panic is reported when the file is judged alone.
	if got := analyseProductionPanicUnit(panics); len(got) != 1 {
		t.Fatalf("file alone reported %d panics, want 1", len(got))
	}
}

// The control. A package with no recovery boundary still reports its literal panics.
// A failure means the lone panic in Handle went unreported or was attributed to another symbol.
func TestProductionPanicStillReportsAnUnrecoveredPackage(t *testing.T) {
	unit := parseOne(t, "server/handler.go", `package server

func Handle(request string) {
	if request == "" {
		panic("empty request")
	}
}
`)

	got := analyseProductionPanic(unit)
	if len(got) != 1 || got[0].Symbol != "Handle" {
		t.Fatalf("reported %#v, want one panic in Handle", got)
	}
}

// A deferred recover that only logs does not hand the failure back, so it exempts nothing.
// A failure means a recover that only logs the value now hides the panic in Serve.
func TestProductionPanicRequiresTheRecoveredValueToReachTheCaller(t *testing.T) {
	unit := parseOne(t, "server/swallow.go", `package server

func Serve() {
	defer func() {
		if r := recover(); r != nil {
			log(r)
		}
	}()
	panic("boom")
}

func log(any) {}
`)

	if got := analyseProductionPanic(unit); len(got) != 1 {
		t.Fatalf("a swallowing recover reported %d panics, want 1", len(got))
	}
}

// A test file's recovery must not exempt the production package, because test files are excluded from this rule.
// A failure means the recover in server/main_test.go lent its boundary to the panic in server/handler.go.
func TestProductionPanicIgnoresRecoveryDeclaredInAnExcludedFile(t *testing.T) {
	panics := parseOne(t, "server/handler.go", `package server

func Handle() {
	panic("boom")
}
`)
	excludedTestFile := parseOne(t, "server/main_test.go", `package server

func helper() (err error) {
	defer func() {
		if r := recover(); r != nil {
			*(&err) = nil
		}
	}()
	return nil
}
`)

	if got := analyseProductionPanic(panics, excludedTestFile); len(got) != 1 {
		t.Fatalf("reported %d panics, want 1: a test file must not lend a recovery boundary", len(got))
	}
}
