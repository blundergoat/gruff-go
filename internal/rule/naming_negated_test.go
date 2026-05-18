package rule

import "testing"

func TestNegatedBooleanFlagsExportedBoolFields(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Options struct {
	NoConfig   bool
	NoBaseline bool
	SkipCache  bool
	Verbose    bool
	NoOp       func()
	Notify     chan struct{}
	NoCache    string
}
`)
	findings := NegatedBooleanRule{}.AnalyzeUnit(unit, Context{})
	got := findingSymbols(findings)
	if len(got) != 2 || !got["NoConfig"] || !got["NoBaseline"] {
		t.Fatalf("findings = %#v, want NoConfig and NoBaseline", findings)
	}
}

func TestNegatedBooleanFlagsBoolReturnFunction(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func DisableCache() bool { return true }
func NotReady(a, b int) bool { return false }
func NoteCount() int { return 0 }
func Enabled() bool { return true }
`)
	findings := NegatedBooleanRule{}.AnalyzeUnit(unit, Context{})
	got := findingSymbols(findings)
	if len(got) != 2 || !got["DisableCache"] || !got["NotReady"] {
		t.Fatalf("findings = %#v, want DisableCache and NotReady", findings)
	}
}

func TestNegatedBooleanFlagsBoolParameters(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func Configure(NoConfig bool, verbose bool, NoOp func()) {}
`)
	findings := NegatedBooleanRule{
		Scope: "all",
	}.AnalyzeUnit(unit, Context{})
	got := findingSymbols(findings)
	if len(got) != 1 || !got["NoConfig"] {
		t.Fatalf("findings = %#v, want NoConfig", findings)
	}
}

func TestNegatedBooleanRespectsAllowList(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Sample struct {
	NoOp     bool
	NoConfig bool
}
`)
	findings := NegatedBooleanRule{}.AnalyzeUnit(unit, Context{})
	got := findingSymbols(findings)
	if got["NoOp"] {
		t.Fatalf("NoOp should be on default allow list, got %#v", findings)
	}
	if !got["NoConfig"] {
		t.Fatalf("NoConfig should still be flagged, got %#v", findings)
	}
}

func TestNegatedBooleanScopeExportedHidesLocals(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func Run() {
	var noBaseline bool
	_ = noBaseline
}
`)
	if got := (NegatedBooleanRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("default scope (exported) should hide locals, got %#v", got)
	}
	findings := NegatedBooleanRule{Scope: "locals"}.AnalyzeUnit(unit, Context{})
	got := findingSymbols(findings)
	if len(got) != 1 || !got["noBaseline"] {
		t.Fatalf("findings = %#v, want noBaseline under scope=locals", findings)
	}
}

func TestNegatedBooleanIgnoresNonBoolTypes(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Sample struct {
	NoConfig string
	NoToken  int
	NoBuffer []byte
}

func DisableLogging() string { return "" }
`)
	if got := (NegatedBooleanRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("non-bool types should be ignored, got %#v", got)
	}
}

func TestNegatedBooleanRequiresUppercaseAfterPrefix(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Sample struct {
	Note bool
	Now  bool
	No   bool
}
`)
	if got := (NegatedBooleanRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("prefix must be followed by uppercase to flag, got %#v", got)
	}
}

func TestNegatedBooleanIsDefaultEnabled(t *testing.T) {
	if !(NegatedBooleanRule{}).Definition().DefaultEnabled {
		t.Error("naming.negated-boolean must be default-enabled")
	}
	if (NegatedBooleanRule{}).Definition().Capability != CapabilityParser {
		t.Error("naming.negated-boolean must be parser-capability")
	}
}
