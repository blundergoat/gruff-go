// Package cli prepares prior findings for agent-hook new-only filtering.
//
// This file turns a baseline file or git history into prior findings for the shared one-to-one matcher.
//
// Hook users therefore see the same duplicate and line-shift behavior as analyse.
// Reached when the user runs gruff-go hook with a baseline path or a git diff mode.
package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"

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
// This is rendered only after classification succeeds.
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

// newFindings classifies currentFindings through baseline.Apply.
//
// With no baseline it returns every finding. With a baseline it returns the visible findings and their statuses, or an error if classification fails.
func (hookBaseline hookFindingBaseline) newFindings(currentFindings []finding.Finding) ([]finding.Finding, error) {
	// Without a baseline or git base, every current finding remains hook-visible and none carries a status.
	if !hookBaseline.enabled {
		return currentFindings, nil
	}
	result, err := baseline.Apply(currentFindings, hookBaseline.file)
	// A baseline from another language may load but cannot classify Go findings, so the caller publishes a fatal diagnostic.
	if err != nil {
		return nil, err
	}
	return stampHookBaselineStatuses(currentFindings, result), nil
}

// stampHookBaselineStatuses records on each surviving finding what the baseline made of it.
//
// A consumer that cannot see why a finding survived cannot tell a genuinely new problem from one the baseline could not identify, so the status
// travels with the finding rather than only in a count.
//
// currentFindings is the slice passed to baseline.Apply, and result is its output; result.Statuses is read by index against currentFindings.
//
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

// resolveHookChanged returns the lines eligible for hook findings. hookFlags gives explicit ranges for scannedPaths priority over stdin and Git.
// scanContext can cancel Git in projectRoot before the hook publishes its report.
//
// Returns true when a comparison resolved, false with empty lines when none was requested, or false and an error when a comparison fails.
func resolveHookChanged(scanContext context.Context, projectRoot string, scannedPaths []string, hookFlags hookFlagValues) (diff.ChangedLines, bool, error) {
	switch {
	case hookFlags.changedRangesSet || hookFlags.changedRanges != "":
		changedLines, err := diff.ExplicitRanges("explicit", hookFlags.changedRanges, scannedPaths)
		return changedLines, err == nil, err
	case hookFlags.diffMode == "-":
		changedLines, err := diff.ParseStdin(hookFlags.diffPatch)
		return changedLines, err == nil, err
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

// resolveHookFindingBaseline loads the baseline file or scans the Git base chosen in hookFlags before a new-only hook run.
// scanContext controls Git resolution and export in projectRoot. scan reuses the edited tree's rules, ignores, exclusions, and scan budget.
//
// Returns an enabled comparison, a disabled one if none was requested, or an error if the base cannot be loaded, scanned, or turned into reviews.
// A file missing from the base is expected for a new edit. Other fatal base diagnostics prevent a trustworthy comparison.
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
	if err != nil {
		return hookFindingBaseline{}, err
	}
	// Only a usable base scan can tell a hook which findings the developer already had.
	for _, diagnostic := range baseAnalysisReport.Diagnostics {
		// A new file is absent in the base by design, so there is no older finding to review for it.
		if diagnostic.Stage == "discovery" && slices.Contains(baseAnalysisReport.Paths.Missing, diagnostic.File) {
			continue
		}
		// A syntax error in the base can hide references. Stop instead of deriving reviewed findings from that partial scan.
		if diagnostic.InvalidatesRun == nil || *diagnostic.InvalidatesRun {
			return hookFindingBaseline{}, fmt.Errorf("cannot build a baseline from %s: %s: %s", baseRevision, diagnostic.File, diagnostic.Message)
		}
	}
	return hookFindingBaselineFromFindings(baseAnalysisReport.Findings)
}

// pathsRelativeToProject keeps the hook operands usable in both root and its exported Git base.
// It returns paths outside root as absolute names so discovery can report the original input.
func pathsRelativeToProject(root string, paths []string) []string {
	resolved := targetsForRoot(root, paths)
	relative := make([]string, len(resolved))
	// Express files inside the project relative to its root so the same hook inputs work in the exported comparison tree.
	for index, path := range resolved {
		relative[index] = path
		// Keep paths outside the chosen project absolute so discovery can explain the original request.
		if filepath.IsAbs(path) && isSameOrDescendant(path, root) {
			// A relative path inside the project selects the same file in the current tree and the exported base.
			if inside, err := filepath.Rel(root, path); err == nil {
				relative[index] = inside
			}
		}
	}
	return relative
}

// hookFindingBaselineFromFile loads baselinePath for the agent hook and resolves a relative path against projectRoot.
//
// Returns an enabled comparison with a project-relative report path when available. An external file leaves that optional path empty.
// Returns a zero baseline and an error for a missing, unreadable, malformed, or incompatible file.
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
	displayPath := ""
	// Only publish a project-relative name. A baseline stored outside the repo can still be used.
	if relative, err := filepath.Rel(projectRoot, resolvedBaselinePath); err == nil &&
		isSameOrDescendant(resolvedBaselinePath, projectRoot) {
		displayPath = filepath.ToSlash(relative)
	}
	return hookFindingBaseline{enabled: true, file: baselineFile, path: displayPath}, nil
}

// hookFindingBaselineFromFindings converts a git-base scan to baseline entries.
//
// FromFindings supplies deterministic ordering and the ratified line-free identity.
//
// priorFindings are the findings from scanning the git base tree, which baseline.FromFindings converts to entries.
//
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
//
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
