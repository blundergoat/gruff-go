package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
)

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

func TestReceiverConsistencyIsDefaultEnabled(t *testing.T) {
	if !(ReceiverConsistencyRule{}).Definition().DefaultEnabled {
		t.Error("naming.receiver-consistency must be default-enabled")
	}
	if (ReceiverConsistencyRule{}).Definition().Capability != CapabilityParser {
		t.Error("naming.receiver-consistency must be parser-capability")
	}
}
