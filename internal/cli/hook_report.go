package cli

import (
	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/diff"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// hookReport is the top-level gruff.hook.v1 payload.
type hookReport struct {
	ContractVersion string          `json:"contractVersion"`
	Analyzer        hookAnalyzer    `json:"analyzer"`
	Findings        []hookFinding   `json:"findings"`
	Suppressed      hookSuppressed  `json:"suppressed"`
	Ignored         hookIgnored     `json:"ignored"`
	Config          hookConfigState `json:"config"`
}

// hookSuppressed reports findings dropped by hook changed-region scope.
type hookSuppressed struct {
	Count int `json:"count"`
}

// hookIgnored groups ignored path records under the contract key.
type hookIgnored struct {
	Paths []hookIgnoredPath `json:"paths"`
}

// hookIgnoredPath describes a source file skipped by config or ignore policy.
type hookIgnoredPath struct {
	Path    string `json:"path"`
	Source  string `json:"source"`
	Pattern string `json:"pattern,omitempty"`
}

// hookConfigState reports whether config loading succeeded.
type hookConfigState struct {
	SchemaOK bool    `json:"schemaOk"`
	Error    *string `json:"error"`
}

// hookFinding is the contract-normalized finding shape.
type hookFinding struct {
	RuleID         string           `json:"ruleId"`
	Pillar         finding.Pillar   `json:"pillar"`
	Severity       finding.Severity `json:"severity"`
	Scope          string           `json:"scope"`
	File           string           `json:"file"`
	Line           *int             `json:"line"`
	EndLine        *int             `json:"endLine,omitempty"`
	Symbol         *string          `json:"symbol"`
	Message        string           `json:"message"`
	Remediation    string           `json:"remediation"`
	Metadata       map[string]any   `json:"metadata"`
	StableIdentity string           `json:"stableIdentity"`
	Fingerprint    string           `json:"fingerprint,omitempty"`
}

// buildHookReport applies the hook contract filter and wraps run metadata.
func buildHookReport(input analysis.Report, definitions []rule.Definition, changed diff.ChangedLines, changedEnabled bool, base hookIdentitySet) hookReport {
	findings, suppressed := hookFindings(input.Findings, definitions, changed, changedEnabled, base)
	return hookReport{
		ContractVersion: hookContractVersion,
		Analyzer:        hookAnalyzer{Name: input.Tool.Name, Version: input.Tool.Version},
		Findings:        findings,
		Suppressed:      hookSuppressed{Count: suppressed},
		Ignored:         hookIgnored{Paths: hookIgnoredPaths(input.Paths.Skipped)},
		Config:          hookConfigState{SchemaOK: true, Error: nil},
	}
}

// hookIgnoredPaths projects analysis skip details into the hook contract.
func hookIgnoredPaths(skipped []analysis.SkippedPath) []hookIgnoredPath {
	out := make([]hookIgnoredPath, 0, len(skipped))
	for _, skippedPath := range skipped {
		out = append(out, hookIgnoredPath{Path: skippedPath.Path, Source: skippedPath.Source, Pattern: skippedPath.Pattern})
	}
	return out
}
