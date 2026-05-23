// Package rule defines gruff-go's rule registry and analysers.
// This file exercises the naming.receiver-consistency rule against fixture sources.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestReceiverConsistencyAllowsConsistentReceivers ensures matching receivers produce no findings.
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

// TestReceiverConsistencyIsolatesByPackage ensures two same-named types in
// different packages do not get merged into one receiver group. Each package
// is internally consistent, so the rule should emit no findings.
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

// TestReceiverConsistencyIsDefaultEnabled asserts the rule ships enabled with parser capability.
func TestReceiverConsistencyIsDefaultEnabled(t *testing.T) {
	if !(ReceiverConsistencyRule{}).Definition().DefaultEnabled {
		t.Error("naming.receiver-consistency must be default-enabled")
	}
	if (ReceiverConsistencyRule{}).Definition().Capability != CapabilityParser {
		t.Error("naming.receiver-consistency must be parser-capability")
	}
}
