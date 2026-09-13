package cli

import (
	"io"

	"github.com/blundergoat/gruff-go/internal/report"
)

// hookContractVersion is the cross-analyzer contract emitted by hook mode.
const hookContractVersion = "gruff.hook.v2"

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
	Baseline       bool `json:"baseline"`
	BaselineV3     bool `json:"baselineV3"`
	ChangedRanges  bool `json:"changedRanges"`
	ConfidenceGate bool `json:"confidenceGate"`
	DeepScanBudget bool `json:"deepScanBudget"`
	Diagnostics    bool `json:"diagnostics"`
	Diff           bool `json:"diff"`
	IgnoreReport   bool `json:"ignoreReport"`
	Metadata       bool `json:"metadata"`
	NewOnly        bool `json:"newOnly"`
	ScopeField     bool `json:"scopeField"`
	StableIdentity bool `json:"stableIdentity"`
}

// hookFlagNames maps contract concepts to this analyzer's real flags.
type hookFlagNames struct {
	Baseline          string `json:"baseline"`
	ChangedRanges     string `json:"changedRanges"`
	DeepScanBudget    string `json:"deepScanBudget"`
	Diff              string `json:"diff"`
	FailOnDiagnostics string `json:"failOnDiagnostics"`
	MinConfidence     string `json:"minConfidence"`
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
			Baseline:       true,
			BaselineV3:     true,
			ChangedRanges:  true,
			ConfidenceGate: true,
			DeepScanBudget: true,
			Diagnostics:    true,
			Diff:           true,
			IgnoreReport:   true,
			Metadata:       true,
			NewOnly:        true,
			ScopeField:     true,
			StableIdentity: true,
		},
		Flags: hookFlagNames{
			Baseline:          "--baseline",
			ChangedRanges:     "--changed-ranges",
			DeepScanBudget:    "--deep-scan-budget",
			Diff:              "--diff",
			FailOnDiagnostics: "--fail-on-diagnostics",
			MinConfidence:     "--min-confidence",
		},
		// Measured 2026-08-12 across all five ports: this port accepts flags after the path, so advertising anything
		// narrower told every consumer something untrue about it.
		FlagOrder: "any",
	}
}
