package cli

import (
	"io"

	"github.com/blundergoat/gruff-go/internal/report"
)

// hookContractVersion is the cross-analyzer contract emitted by hook mode.
const hookContractVersion = "gruff.hook.v1"

// hookCapabilities is the §4 capability negotiation payload.
type hookCapabilities struct {
	ContractVersion string              `json:"contractVersion"`
	Analyzer        hookAnalyzer        `json:"analyzer"`
	Supports        hookCapabilityFlags `json:"supports"`
	Flags           hookFlagNames       `json:"flags"`
	FlagOrder       string              `json:"flagOrder"`
}

// hookAnalyzer identifies the analyzer binary in hook payloads.
type hookAnalyzer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// hookCapabilityFlags advertises which hook contract features are implemented.
type hookCapabilityFlags struct {
	ChangedRanges  bool `json:"changedRanges"`
	Diff           bool `json:"diff"`
	Baseline       bool `json:"baseline"`
	ScopeField     bool `json:"scopeField"`
	Metadata       bool `json:"metadata"`
	StableIdentity bool `json:"stableIdentity"`
	IgnoreReport   bool `json:"ignoreReport"`
	NewOnly        bool `json:"newOnly"`
}

// hookFlagNames maps contract concepts to this analyzer's real flags.
type hookFlagNames struct {
	ChangedRanges string `json:"changedRanges"`
	Diff          string `json:"diff"`
	Baseline      string `json:"baseline"`
}

// writeHookCapabilities writes the stable §4 JSON payload.
func writeHookCapabilities(writer io.Writer) error {
	return report.WriteJSON(writer, hookCapabilitiesPayload())
}

// hookCapabilitiesPayload returns gruff-go's hook contract support matrix.
func hookCapabilitiesPayload() hookCapabilities {
	return hookCapabilities{
		ContractVersion: hookContractVersion,
		Analyzer:        hookAnalyzer{Name: "gruff-go", Version: toolVersion},
		Supports: hookCapabilityFlags{
			ChangedRanges:  true,
			Diff:           true,
			Baseline:       true,
			ScopeField:     true,
			Metadata:       true,
			StableIdentity: true,
			IgnoreReport:   true,
			NewOnly:        true,
		},
		Flags: hookFlagNames{
			ChangedRanges: "--changed-ranges",
			Diff:          "--diff",
			Baseline:      "--baseline",
		},
		FlagOrder: "flags-before-path",
	}
}
