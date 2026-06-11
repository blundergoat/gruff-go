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

// hookIdentityKey identifies a prior finding by B3 stable identity.
type hookIdentityKey struct {
	ruleID         string
	file           string
	stableIdentity string
}

// hookFingerprintKey preserves fallback matching for older baseline files.
type hookFingerprintKey struct {
	ruleID      string
	file        string
	fingerprint string
}

// hookIdentitySet stores the optional new-only base identity set.
type hookIdentitySet struct {
	enabled      bool
	stable       map[hookIdentityKey]struct{}
	fingerprints map[hookFingerprintKey]struct{}
}

// contains reports whether a current finding already existed in the base.
func (set hookIdentitySet) contains(item finding.Finding) bool {
	if !set.enabled {
		return false
	}
	stable := item.ComputeContractStableIdentity()
	if _, ok := set.stable[hookIdentityKey{ruleID: item.RuleID, file: item.File, stableIdentity: stable}]; ok {
		return true
	}
	_, ok := set.fingerprints[hookFingerprintKey{ruleID: item.RuleID, file: item.File, fingerprint: item.Fingerprint}]
	return ok
}

// resolveHookChanged computes the changed region used for line/symbol attribution.
func resolveHookChanged(ctx context.Context, root string, scanned []string, values hookFlagValues) (diff.ChangedLines, bool, error) {
	switch {
	case values.changedRanges != "":
		changed, err := diff.ExplicitRanges("explicit", values.changedRanges, scanned)
		return changed, err == nil, err
	case values.diffMode == "-":
		return diff.Parse("stdin", values.diffPatch), true, nil
	case values.diffMode != "":
		changed, err := diff.FromMode(ctx, root, values.diffMode, values.paths)
		return changed, err == nil, err
	default:
		return diff.ChangedLines{}, false, nil
	}
}

// resolveHookBaseIdentities loads the B3 new-only base from baseline or git diff.
func resolveHookBaseIdentities(ctx context.Context, root string, values hookFlagValues, registry rule.Registry, ignorePaths []string) (hookIdentitySet, error) {
	if values.baselinePath != "" {
		return hookIdentitySetFromBaseline(root, values.baselinePath)
	}
	baseRef, ok, err := hookBaseTreeish(ctx, root, values.diffMode)
	if err != nil {
		return hookIdentitySet{}, err
	}
	if !ok {
		return hookIdentitySet{}, nil
	}
	baseRoot, cleanup, err := exportGitTree(ctx, root, baseRef, values.paths)
	if err != nil {
		return hookIdentitySet{}, err
	}
	defer cleanup()
	baseReport, err := analysis.Analyze(analysis.Options{
		Root:           baseRoot,
		Paths:          values.paths,
		Format:         "json",
		FailOn:         finding.FailThresholdNone,
		Registry:       registry,
		IgnorePaths:    ignorePaths,
		IncludeIgnored: values.includeIgnored,
	})
	if err != nil {
		return hookIdentitySet{}, err
	}
	return hookIdentitySetFromFindings(baseReport.Findings), nil
}

// hookIdentitySetFromBaseline reads stable identities from a baseline file.
func hookIdentitySetFromBaseline(root, path string) (hookIdentitySet, error) {
	loadPath := path
	if !filepath.IsAbs(loadPath) {
		loadPath = filepath.Join(root, loadPath)
	}
	file, err := baseline.Load(loadPath)
	if err != nil {
		return hookIdentitySet{}, err
	}
	set := newHookIdentitySet()
	for _, entry := range file.Findings {
		if entry.StableIdentity != "" {
			set.stable[hookIdentityKey{ruleID: entry.RuleID, file: entry.File, stableIdentity: entry.StableIdentity}] = struct{}{}
			continue
		}
		set.fingerprints[hookFingerprintKey{ruleID: entry.RuleID, file: entry.File, fingerprint: entry.Fingerprint}] = struct{}{}
	}
	return set, nil
}

// hookIdentitySetFromFindings builds a stable-identity base from analysis output.
func hookIdentitySetFromFindings(findings []finding.Finding) hookIdentitySet {
	set := newHookIdentitySet()
	for _, item := range findings {
		set.stable[hookIdentityKey{ruleID: item.RuleID, file: item.File, stableIdentity: item.ComputeContractStableIdentity()}] = struct{}{}
	}
	return set
}

// newHookIdentitySet creates an enabled empty identity set.
func newHookIdentitySet() hookIdentitySet {
	return hookIdentitySet{
		enabled:      true,
		stable:       map[hookIdentityKey]struct{}{},
		fingerprints: map[hookFingerprintKey]struct{}{},
	}
}

// hookBaseTreeish resolves the git tree that represents the pre-edit state a
// diff mode is measured against, so new-only matching uses the same base as the
// changed region:
//   - working-tree (uncommitted vs HEAD) and staged (index vs HEAD) -> HEAD
//   - unstaged (working tree vs index) -> the index itself, written to a tree, so
//     a finding introduced by a staged edit is not mislabelled "new"
//   - an explicit base ref -> that ref
//
// The "" / "-" modes have no git base (no diff mode, or a stdin patch).
func hookBaseTreeish(ctx context.Context, root, diffMode string) (string, bool, error) {
	switch diffMode {
	case "", "-":
		return "", false, nil
	case "working-tree", "staged":
		return "HEAD", true, nil
	case "unstaged":
		tree, err := gitWriteTree(ctx, root)
		if err != nil {
			return "", false, err
		}
		return tree, true, nil
	default:
		return diffMode, true, nil
	}
}
