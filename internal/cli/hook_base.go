// Package cli prepares prior findings for agent-hook new-only filtering.
// This file resolves baseline or git history into the shared one-to-one matcher
// so hook users see the same duplicate and line-shift behavior as analyse.
package cli

import (
	"context"
	"path/filepath"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/baseline"
	"github.com/blundergoat/gruff-go/internal/diff"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// hookFindingBaseline stores the optional prior findings used by hook new-only.
// An enabled empty file means the user explicitly selected a base with no debt;
// a disabled value means hook output should skip baseline classification.
type hookFindingBaseline struct {
	enabled bool
	file    baseline.File
	// path is the project-relative baseline the user named, empty for a baseline derived from git history.
	path string
}

// runBaseline reports which baseline classified this run, for the audit block a consumer reads before trusting it.
//
// A suppressed finding is only explicable if the consumer can see what suppressed it, so an applied baseline names both
// its schema and its file.
func (hookBaseline hookFindingBaseline) runBaseline() hookRunBaseline {
	// Without a baseline there is nothing to name, and the contract asks for null rather than an empty string.
	if !hookBaseline.enabled {
		return hookRunBaseline{}
	}

	schemaVersion := baseline.SchemaVersion
	applied := hookRunBaseline{Applied: true, SchemaVersion: &schemaVersion}

	// A git-derived base has no file the user can open, so its path stays null rather than naming a temporary export.
	if hookBaseline.path != "" {
		path := hookBaseline.path
		applied.Path = &path
	}

	return applied
}

// newFindings classifies the complete current slice through baseline.Apply.
// Disabled input returns every finding because the user selected no prior base.
func (hookBaseline hookFindingBaseline) newFindings(currentFindings []finding.Finding) []finding.Finding {
	// Without a baseline or git base, every current finding remains hook-visible and none carries a status.
	if !hookBaseline.enabled {
		return currentFindings
	}
	result, err := baseline.Apply(currentFindings, hookBaseline.file)
	// A baseline that cannot be applied hides nothing; a hook shows every finding rather than guess at what was reviewed.
	if err != nil {
		return currentFindings
	}
	return stampHookBaselineStatuses(currentFindings, result)
}

// stampHookBaselineStatuses records on each surviving finding what the baseline made of it.
//
// A consumer that cannot see why a finding survived cannot tell a genuinely new problem from one the baseline could not
// identify, so the status travels with the finding rather than only in a count.
func stampHookBaselineStatuses(currentFindings []finding.Finding, result baseline.ApplyResult) []finding.Finding {
	statusByFingerprint := map[string]string{}

	for index, status := range result.Statuses {
		if index < len(currentFindings) {
			statusByFingerprint[currentFindings[index].Fingerprint] = string(status)
		}
	}

	stamped := make([]finding.Finding, 0, len(result.Findings))

	for _, survivor := range result.Findings {
		survivor.BaselineStatus = statusByFingerprint[survivor.Fingerprint]
		stamped = append(stamped, survivor)
	}

	return stamped
}

// resolveHookChanged computes changed lines used for hook location attribution.
// Disabled output means the user requested no changed-region filtering.
func resolveHookChanged(scanContext context.Context, projectRoot string, scannedPaths []string, hookFlags hookFlagValues) (diff.ChangedLines, bool, error) {
	switch {
	case hookFlags.changedRanges != "":
		changedLines, err := diff.ExplicitRanges("explicit", hookFlags.changedRanges, scannedPaths)
		return changedLines, err == nil, err
	case hookFlags.diffMode == "-":
		return diff.Parse("stdin", hookFlags.diffPatch), true, nil
	case hookFlags.diffMode != "":
		changedLines, err := diff.FromMode(scanContext, projectRoot, hookFlags.diffMode, hookFlags.paths)
		return changedLines, err == nil, err
	default:
		return diff.ChangedLines{}, false, nil
	}
}

// hookBaseScan groups the scan policy the git-base run shares with the primary
// hook run: the configured registry, the discovery ignore patterns, and the
// sensitive exclusions. Grouped rather than passed individually so the base
// resolver keeps a reviewable parameter list.
type hookBaseScan struct {
	// registry is the config-resolved rule registry both runs execute.
	registry rule.Registry
	// ignoredPathPatterns are the discovery ignore globs both runs apply.
	ignoredPathPatterns []string
	// sensitiveExclusions are the section 13a scopes both runs suppress.
	sensitiveExclusions []analysis.SensitiveExclusion
	// deepScanBudget keeps base-tree and current-tree analysis under identical cost policy.
	deepScanBudget analysis.DeepScanBudget
}

// resolveHookFindingBaseline loads the user's new-only base from a baseline or git.
// Empty success means no base was requested; errors retain existing hook handling.
func resolveHookFindingBaseline(scanContext context.Context, projectRoot string, hookFlags hookFlagValues, scan hookBaseScan) (hookFindingBaseline, error) {
	// An explicit baseline takes precedence over any git-derived hook base.
	if hookFlags.baselinePath != "" {
		return hookFindingBaselineFromFile(projectRoot, hookFlags.baselinePath)
	}
	baseRevision, hasBaseRevision, err := hookBaseTreeish(scanContext, projectRoot, hookFlags.diffMode)
	// A git resolution failure is returned for the hook's existing error policy.
	if err != nil {
		return hookFindingBaseline{}, err
	}
	// No diff base means the user requested changed ranges without new-only history.
	if !hasBaseRevision {
		return hookFindingBaseline{}, nil
	}
	baseProjectRoot, cleanupBaseProject, err := exportGitTree(scanContext, projectRoot, baseRevision, hookFlags.paths)
	// An unavailable base tree cannot provide reliable prior findings.
	if err != nil {
		return hookFindingBaseline{}, err
	}
	defer cleanupBaseProject()
	baseAnalysisReport, err := analysis.Analyze(analysis.Options{
		Root:                baseProjectRoot,
		Paths:               hookFlags.paths,
		Format:              "json",
		FailOn:              finding.FailThresholdNone,
		Registry:            scan.registry,
		IgnorePaths:         scan.ignoredPathPatterns,
		SensitiveExclusions: scan.sensitiveExclusions,
		DeepScanBudget:      scan.deepScanBudget,
		IncludeIgnored:      hookFlags.includeIgnored,
	})
	// Analysis failures stop the prior base from being treated as complete.
	if err != nil {
		return hookFindingBaseline{}, err
	}
	return hookFindingBaselineFromFindings(baseAnalysisReport.Findings)
}

// hookFindingBaselineFromFile loads modern or legacy entries without reshaping.
// The shared matcher decides whether each row supports stable or exact-only use.
func hookFindingBaselineFromFile(projectRoot, baselinePath string) (hookFindingBaseline, error) {
	resolvedBaselinePath := baselinePath
	// Relative paths are resolved from the project the user asked hook to scan.
	if !filepath.IsAbs(resolvedBaselinePath) {
		resolvedBaselinePath = filepath.Join(projectRoot, resolvedBaselinePath)
	}
	baselineFile, err := baseline.Load(resolvedBaselinePath)
	// Invalid or missing baseline files retain hook's fatal diagnostic behavior.
	if err != nil {
		return hookFindingBaseline{}, err
	}
	return hookFindingBaseline{enabled: true, file: baselineFile, path: filepath.ToSlash(baselinePath)}, nil
}

// hookFindingBaselineFromFindings converts a git-base scan to baseline entries.
// FromFindings supplies deterministic ordering and the ratified line-free identity.
func hookFindingBaselineFromFindings(priorFindings []finding.Finding) (hookFindingBaseline, error) {
	file, err := baseline.FromFindings(priorFindings)
	// A prior finding that cannot be identified means no base can be trusted.
	if err != nil {
		return hookFindingBaseline{}, err
	}
	return hookFindingBaseline{enabled: true, file: file}, nil
}

// hookBaseTreeish selects the prior git tree used for user-facing new-only results.
// Working/staged use HEAD, unstaged uses the index tree, and explicit refs use
// themselves; empty or stdin modes intentionally have no base.
func hookBaseTreeish(scanContext context.Context, projectRoot, diffMode string) (string, bool, error) {
	switch diffMode {
	case "", "-":
		return "", false, nil
	case "working-tree", "staged":
		return "HEAD", true, nil
	case "unstaged":
		indexTree, err := gitWriteTree(scanContext, projectRoot)
		// Git can fail here when the user's repository has no usable index tree.
		if err != nil {
			return "", false, err
		}
		return indexTree, true, nil
	default:
		return diffMode, true, nil
	}
}
