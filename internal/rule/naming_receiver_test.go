// Package rule defines gruff-go's rule registry and analysers.
//
// This file exercises the naming.receiver-consistency rule against inline fixture sources run through AnalyzeProject.
// Failures point at changed receiver findings, finding metadata, option handling, package isolation, opt-in default or parser capability.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestReceiverConsistencyAllowsConsistentReceivers ensures matching receivers produce no findings.
// A failure means a type whose methods all use the same receiver gets a false finding.
func TestReceiverConsistencyAllowsConsistentReceivers(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Client struct{}

func (c *Client) Start() {}
func (c *Client) Stop() {}
`)
	findings := ReceiverConsistencyRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("consistent receivers should pass, got %#v", findings)
	}
}

// TestReceiverConsistencyFlagsReceiverNameMinority asserts the rule flags a method that diverges from the dominant receiver name.
// It also checks the finding metadata carries dominantName and receiverName, which tell the user which name to switch to.
func TestReceiverConsistencyFlagsReceiverNameMinority(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Client struct{}

func (c *Client) Start() {}
func (client *Client) Stop() {}
func (c *Client) Close() {}
`)
	findings := ReceiverConsistencyRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 1 || findings[0].Symbol != "Stop" {
		t.Fatalf("expected receiver name finding for Stop, got %#v", findings)
	}
	if findings[0].Metadata["dominantName"] != "c" || findings[0].Metadata["receiverName"] != "client" {
		t.Fatalf("metadata = %#v, want dominant c and receiver client", findings[0].Metadata)
	}
}

// TestReceiverConsistencyFlagsPointerFormMinority asserts a method that diverges on pointer/value form is flagged.
// It also checks the finding metadata carries dominantForm and receiverForm, here pointer and value.
func TestReceiverConsistencyFlagsPointerFormMinority(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Client struct{}

func (c *Client) Start() {}
func (c Client) Stop() {}
func (c *Client) Close() {}
`)
	findings := ReceiverConsistencyRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 1 || findings[0].Symbol != "Stop" {
		t.Fatalf("expected receiver form finding for Stop, got %#v", findings)
	}
	if findings[0].Metadata["dominantForm"] != "pointer" || findings[0].Metadata["receiverForm"] != "value" {
		t.Fatalf("metadata = %#v, want dominant pointer and receiver value", findings[0].Metadata)
	}
}

// TestReceiverConsistencyHonoursAllowMixed verifies AllowMixed suppresses form findings for the named type.
// A failure means a type the user listed as deliberately mixed still fires pointer/value findings.
func TestReceiverConsistencyHonoursAllowMixed(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Client struct{}

func (c *Client) Start() {}
func (c Client) Stop() {}
func (c *Client) Close() {}
`)
	rule := ReceiverConsistencyRule{AllowMixed: []string{"Client"}}
	findings := rule.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("allowMixed should suppress pointer/value findings, got %#v", findings)
	}
}

// TestReceiverConsistencyHonoursInspectGroup checks the InspectGroup option restricts what kinds of mismatch fire.
// The fixture's Stop differs in both name and form; name must report only reason name, and pointer only reason form.
func TestReceiverConsistencyHonoursInspectGroup(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

type Client struct{}

func (c *Client) Start() {}
func (client Client) Stop() {}
func (c *Client) Close() {}
`)
	nameOnly := ReceiverConsistencyRule{InspectGroup: "name"}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(nameOnly) != 1 || nameOnly[0].Metadata["reason"] != "name" {
		t.Fatalf("name-only findings = %#v, want name mismatch only", nameOnly)
	}
	pointerOnly := ReceiverConsistencyRule{InspectGroup: "pointer"}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(pointerOnly) != 1 || pointerOnly[0].Metadata["reason"] != "form" {
		t.Fatalf("pointer-only findings = %#v, want form mismatch only", pointerOnly)
	}
}

// TestReceiverConsistencyIsolatesByPackage ensures same-named types in different packages are not merged into one receiver group.
//
// Each package is internally consistent, so a finding here means a user with a Service type in two packages gets a false mismatch.
func TestReceiverConsistencyIsolatesByPackage(t *testing.T) {
	unitA := parseOne(t, "pkg/a/file.go", `package a

type Service struct{}

func (s *Service) Start() {}
func (s *Service) Stop() {}
`)
	unitB := parseOne(t, "pkg/b/file.go", `package b

type Service struct{}

func (svc *Service) Start() {}
func (svc *Service) Stop() {}
`)
	findings := ReceiverConsistencyRule{}.AnalyzeProject([]parser.Unit{unitA, unitB}, Context{})
	if len(findings) != 0 {
		t.Fatalf("same type name in different packages must not merge, got %#v", findings)
	}
}

// TestReceiverConsistencyIsOptIn asserts the convention-only rule ships opt-in with parser capability.
//
// A DefaultEnabled failure means default gruff-go analyse runs would start reporting receiver style findings.
// A capability failure alone flags a changed Capability declaration and leaves enablement untouched.
func TestReceiverConsistencyIsOptIn(t *testing.T) {
	if (ReceiverConsistencyRule{}).Definition().DefaultEnabled {
		t.Error("naming.receiver-consistency must be opt-in")
	}
	if (ReceiverConsistencyRule{}).Definition().Capability != CapabilityParser {
		t.Error("naming.receiver-consistency must be parser-capability")
	}
}
