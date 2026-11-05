package cli

import (
	"io"

	"github.com/blundergoat/gruff-go/internal/report"
)

// hookContractVersion is the cross-analyzer contract emitted by hook mode.
//
// It is sent as contractVersion in the capabilities JSON, telling a hook consumer which hook payload shape gruff-go speaks.
const hookContractVersion = "gruff.hook.v2"

// hookCapabilities is the §4 capability negotiation payload.
//
// A hook consumer reads it to learn the contract version, which hook features gruff-go supports and how each flag is spelled.
// FlagOrder is any because gruff-go accepts flags after the path as well as before it.
type hookCapabilities struct {
	ContractVersion string              `json:"contractVersion"`
	Analyzer        hookAnalyzer        `json:"analyzer"`
	Supports        hookCapabilityFlags `json:"supports"`
	Flags           hookFlagNames       `json:"flags"`
	FlagOrder       string              `json:"flagOrder"`
}

// hookAnalyzer identifies the analyzer binary in hook payloads.
//
// In the capabilities JSON, Name is gruff-go and Version is toolVersion, so a consumer can tell which build answered.
type hookAnalyzer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// hookCapabilityFlags advertises which hook contract features are implemented.
//
// hookCapabilitiesPayload sets every field to true, so a consumer may rely on each of these features when it runs gruff-go hook.
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
//
// A consumer reads the flag for each concept here, such as --diff or --min-confidence, instead of guessing how gruff-go spells it.
type hookFlagNames struct {
	Baseline          string `json:"baseline"`
	ChangedRanges     string `json:"changedRanges"`
	DeepScanBudget    string `json:"deepScanBudget"`
	Diff              string `json:"diff"`
	FailOnDiagnostics string `json:"failOnDiagnostics"`
	MinConfidence     string `json:"minConfidence"`
}

// writeHookCapabilities writes the stable §4 JSON payload.
//
// writer receives the payload built by hookCapabilitiesPayload, encoded by report.WriteJSON.
// It returns the writer's error unchanged if writing the capability JSON fails, and nil on success.
func writeHookCapabilities(writer io.Writer) error {
	return report.WriteJSON(writer, hookCapabilitiesPayload())
}

// hookCapabilitiesPayload returns gruff-go's hook contract support matrix.
// The result marks every feature supported, lists gruff-go's real flag spellings, and sets FlagOrder to any.
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
