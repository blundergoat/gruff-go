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
func analyseProductionPanicUnit(unit parser.Unit) []finding.Finding {
	return ProductionPanicRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
}

// analyseProductionPanic runs the rule over a whole package.
func analyseProductionPanic(units ...parser.Unit) []finding.Finding {
	return ProductionPanicRule{}.AnalyzeProject(units, Context{})
}

// The promql shape: the panic is deep in one file and the recovery is at the entry point in another.
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

	// Without its sibling the boundary is invisible, which is the behaviour this task changed.
	if got := analyseProductionPanicUnit(panics); len(got) != 1 {
		t.Fatalf("file alone reported %d panics, want 1", len(got))
	}
}

// The control. A package with no recovery boundary still reports its literal panics.
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

// A bootstrap file's recovery must not exempt the package the rule actually judges, because
// bootstrap paths are excluded from this rule and would otherwise lend a boundary they do not own.
func TestProductionPanicIgnoresRecoveryDeclaredInAnExcludedFile(t *testing.T) {
	panics := parseOne(t, "server/handler.go", `package server

func Handle() {
	panic("boom")
}
`)
	bootstrap := parseOne(t, "server/main_test.go", `package server

func helper() (err error) {
	defer func() {
		if r := recover(); r != nil {
			*(&err) = nil
		}
	}()
	return nil
}
`)

	if got := analyseProductionPanic(panics, bootstrap); len(got) != 1 {
		t.Fatalf("reported %d panics, want 1: a test file must not lend a recovery boundary", len(got))
	}
}
