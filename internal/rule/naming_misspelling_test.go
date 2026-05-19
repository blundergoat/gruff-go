// Package rule defines gruff-go's rule registry and analysers.
// This file exercises the naming.misspelling rule against fixture sources.
package rule

import "testing"

// TestMisspellingFlagsIdentifiers verifies that common misspellings in identifiers fire findings.
func TestMisspellingFlagsIdentifiers(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Sample struct {
	Lenght int
}

func Recieve() {}

var Adress string

const Wierd = 1
`)
	findings := MisspellingRule{}.AnalyzeUnit(unit, Context{})
	got := findingMessages(findings)
	for _, want := range []string{
		`"lenght" looks like a misspelling of "length"`,
		`"recieve" looks like a misspelling of "receive"`,
		`"adress" looks like a misspelling of "address"`,
		`"wierd" looks like a misspelling of "weird"`,
	} {
		if !got[want] {
			t.Fatalf("findings missing %s; got %#v", want, findings)
		}
	}
}

// TestMisspellingFlagsCamelCaseTokens checks that camelCase sub-tokens are detected.
func TestMisspellingFlagsCamelCaseTokens(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func GetRecievedMessage() {}

type EnviromentConfig struct{}
`)
	findings := MisspellingRule{}.AnalyzeUnit(unit, Context{})
	got := findingMessages(findings)
	if !got[`"recieved" looks like a misspelling of "received"`] {
		t.Fatalf("findings should flag camelCase token; got %#v", findings)
	}
	if !got[`"enviroment" looks like a misspelling of "environment"`] {
		t.Fatalf("findings should flag PascalCase token; got %#v", findings)
	}
}

// TestMisspellingFlagsDocComments confirms misspellings inside doc comments are reported.
func TestMisspellingFlagsDocComments(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

// Recieves the next message from the queue.
func Process() {}
`)
	findings := MisspellingRule{}.AnalyzeUnit(unit, Context{})
	got := findingMessages(findings)
	if !got[`"recieves" looks like a misspelling of "receives"`] {
		t.Fatalf("findings should flag doc comment misspelling; got %#v", findings)
	}
}

// TestMisspellingFlagsStructTags ensures struct tag literals are scanned for misspellings.
func TestMisspellingFlagsStructTags(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Sample struct {
	Address string `+"`json:\"adress\"`"+`
}
`)
	findings := MisspellingRule{}.AnalyzeUnit(unit, Context{})
	got := findingMessages(findings)
	if !got[`"adress" looks like a misspelling of "address"`] {
		t.Fatalf("findings should flag struct tag misspelling; got %#v", findings)
	}
}

// TestMisspellingHonoursIgnoreList checks that tokens listed in Ignore are suppressed.
func TestMisspellingHonoursIgnoreList(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Sample struct {
	Recieve string
}
`)
	findings := MisspellingRule{Ignore: []string{"recieve"}}.AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("ignored token should not fire; got %#v", findings)
	}
}

// TestMisspellingAcceptsExtraDictionary verifies user-provided Extra entries augment the dictionary.
func TestMisspellingAcceptsExtraDictionary(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Sample struct {
	Foo string
}
`)
	findings := MisspellingRule{
		Extra: map[string]string{"foo": "bar"},
	}.AnalyzeUnit(unit, Context{})
	got := findingMessages(findings)
	if !got[`"foo" looks like a misspelling of "bar"`] {
		t.Fatalf("findings should flag extra-dictionary token; got %#v", findings)
	}
}

// TestMisspellingIsDefaultEnabled asserts the rule ships enabled with parser capability.
func TestMisspellingIsDefaultEnabled(t *testing.T) {
	if !(MisspellingRule{}).Definition().DefaultEnabled {
		t.Error("naming.misspelling must be default-enabled")
	}
	if (MisspellingRule{}).Definition().Capability != CapabilityParser {
		t.Error("naming.misspelling must be parser-capability")
	}
}

// TestMisspellingClampsToWordBoundaries ensures clean identifiers and comments produce no findings.
func TestMisspellingClampsToWordBoundaries(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

// This handler returns valid responses.
func GoodHandler() {}

type Length int
`)
	if got := (MisspellingRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("clean identifiers should not fire; got %#v", got)
	}
}
