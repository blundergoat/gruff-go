// Package cli prepares prior findings for agent-hook new-only filtering.
//
// This file turns a baseline file or git history into prior findings for the shared one-to-one matcher.
// Hook users therefore see the same duplicate and line-shift behavior as analyse.
// Reached when the user runs gruff-go hook with a baseline path or a git diff mode.
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
//
// An enabled value with an empty file means the user selected a base that held no findings.
// A disabled value means the hook skips baseline classification and keeps every finding.
type hookFindingBaseline struct {
	enabled bool
	file    baseline.File
	// path is the user-supplied baseline path with forward slashes, or empty for a git-derived baseline.
	path string
}

// runBaseline reports the baseline the user selected, for the audit block a consumer reads before trusting the run.
//
// A consumer can identify an applied baseline by its schema and, for a file-based baseline, its user-supplied path.
// Applied follows enabled alone, so it stays true even when newFindings could not apply the baseline and kept every finding.
//
// It returns the zero value, with Applied false and nil SchemaVersion and Path, when no baseline is enabled.
// Otherwise the result has Applied true, the baseline schema version, and a Path only for a file-based baseline.
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
//
// Disabled input returns every finding because the user selected no prior base.
// currentFindings is this run's complete slice, returned whole when baseline.Apply fails, so a baseline that cannot apply hides nothing.
// Otherwise the result holds only the findings the baseline left visible, each stamped with its baseline status.
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
//
// currentFindings is the slice passed to baseline.Apply, and result is its output; result.Statuses is read by index against currentFindings.
// It returns a copy of result.Findings with each BaselineStatus set from the status of the current finding sharing its Fingerprint.
// A survivor with no matching fingerprint gets an empty status, and an empty result.Findings gives an empty, non-nil slice.
func stampHookBaselineStatuses(currentFindings []finding.Finding, result baseline.ApplyResult) []finding.Finding {
	statusByFingerprint := map[string]string{}

	// Findings that share a Fingerprint share one entry, so every survivor with that Fingerprint shows the status of the last of them.
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
//
// Disabled output means the user requested no changed-region filtering.
//
// scanContext is passed to the git diff, and projectRoot is the repository a git diff mode is resolved in.
// hookFlags picks the source in order: explicit ranges for scannedPaths, a stdin patch, or a git diff mode.
//
// It returns the changed lines and true when a source is selected and resolves, and empty lines with false when none is selected.
// The error is returned, with false, when the explicit ranges or the git diff mode fail to resolve; a stdin patch never fails.
func resolveHookChanged(scanContext context.Context, projectRoot string, scannedPaths []string, hookFlags hookFlagValues) (diff.ChangedLines, bool, error) {
	switch {
	case hookFlags.changedRangesSet || hookFlags.changedRanges != "":
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

// hookBaseScan groups the scan policy the git-base run shares with the primary hook run.
//
// It holds the configured registry, the discovery ignore patterns, the sensitive exclusions and the deep-scan budget.
// They are grouped rather than passed one by one so the base resolver keeps a reviewable parameter list.
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

// resolveHookFindingBaseline loads the user's new-only base from a baseline file or from a git base tree.
//
// No base is requested when there is no baseline path and the diff mode is empty or stdin; errors go to the hook's existing handling.
//
// scanContext is passed to the git base resolution and export, not to the base analysis.
// projectRoot is the scanned project, and hookFlags supplies the baseline path, diff mode, paths and include-ignored choice.
// scan carries the registry, ignore patterns, sensitive exclusions and deep-scan budget the git-base analysis reuses.
//
// It returns an enabled baseline from the file or the git base, or a disabled zero value when neither is requested.
// The error is returned when the baseline file fails to load or the git base cannot be resolved, exported, analysed or turned into entries.
func resolveHookFindingBaseline(scanContext context.Context, projectRoot string, hookFlags hookFlagValues, scan hookBaseScan) (hookFindingBaseline, error) {
	// An explicit baseline takes precedence over any git-derived hook base.
	if hookFlags.baselinePath != "" {
		return hookFindingBaselineFromFile(projectRoot, hookFlags.baselinePath)
	}
	baseRevision, hasBaseRevision, err := hookBaseTreeish(scanContext, projectRoot, hookFlags.diffMode)
	// Only --diff unstaged fails here, when git cannot write the index tree; the hook then emits a fatal baseline diagnostic and exits 2.
	if err != nil {
		return hookFindingBaseline{}, err
	}
	// An empty diff mode or a stdin patch supplies no git base, so baseline classification stays disabled.
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
	// A returned analysis error aborts baseline preparation; diagnostics in baseAnalysisReport are not checked here.
	if err != nil {
		return hookFindingBaseline{}, err
	}
	return hookFindingBaselineFromFindings(baseAnalysisReport.Findings)
}

// hookFindingBaselineFromFile loads a validated gruff.baseline.v3 file; any other schema, such as a 0.5 file, is refused with a migration hint.
//
// baseline.Apply later spends each stable identity's reviewed count against the current findings.
//
// baselinePath is the user's path, joined to projectRoot when relative; the stored path keeps the user's spelling with forward slashes.
// It returns an enabled baseline holding the loaded file and that path.
// The error is returned, with a zero baseline, when baseline.Load cannot read the file or rejects it as malformed, non-v3 or invalid.
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
//
// FromFindings supplies deterministic ordering and the ratified line-free identity.
//
// priorFindings are the findings from scanning the git base tree, which baseline.FromFindings converts to entries.
// It returns an enabled baseline with an empty path, since a git-derived base has no file the user can open.
// The error is returned, with a zero baseline, when baseline.FromFindings fails, as when a prior finding cannot be identified.
func hookFindingBaselineFromFindings(priorFindings []finding.Finding) (hookFindingBaseline, error) {
	file, err := baseline.FromFindings(priorFindings)
	// A prior finding that cannot be identified means no base can be trusted.
	if err != nil {
		return hookFindingBaseline{}, err
	}
	return hookFindingBaseline{enabled: true, file: file}, nil
}

// hookBaseTreeish selects the prior git tree used for user-facing new-only results.
//
// Working-tree and staged modes use HEAD, unstaged uses the index tree, and any other mode is taken as an explicit ref.
// Empty or stdin modes intentionally have no base.
//
// diffMode is the hook's diff mode; scanContext and projectRoot go to gitWriteTree, which writes the index tree for unstaged mode.
// It returns the treeish and true when a base applies, and an empty string with false for an empty or stdin mode.
// The error is returned, with an empty string and false, when git fails to write the index tree for unstaged mode.
func hookBaseTreeish(scanContext context.Context, projectRoot, diffMode string) (string, bool, error) {
	switch diffMode {
	case "", "-":
		return "", false, nil
	case "working-tree", "staged":
		return "HEAD", true, nil
	case "unstaged":
		indexTree, err := gitWriteTree(scanContext, projectRoot)
		// If git cannot write the index tree, as mid-merge with unresolved conflicts, --diff unstaged gets a fatal baseline diagnostic and exit 2.
		if err != nil {
			return "", false, err
		}
		return indexTree, true, nil
	default:
		return diffMode, true, nil
	}
}
