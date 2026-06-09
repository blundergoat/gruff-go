// Package rule defines gruff-go's rule registry and analysers.
// This file implements parser-only GitHub Actions workflow security checks that
// scan .github/workflows YAML as text (no YAML library, no execution).
package rule

import (
	"regexp"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// Workflow-scanning patterns. Each is a line- or source-level text match because
// the dependency-free scanner does not parse YAML structurally.
var (
	workflowUsesPattern        = regexp.MustCompile(`^\s*-?\s*uses:\s*["']?([^"'\s#]+)`)
	workflowRemoteShellPattern = regexp.MustCompile(`(?i)(?:curl|wget|invoke-webrequest|iwr)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|fish|iex|invoke-expression)\b`)
	workflowProcessSubPattern  = regexp.MustCompile(`(?i)\b(?:bash|sh|zsh)\b\s+<\(\s*(?:curl|wget)\b`)
	workflowBroadPermsPattern  = regexp.MustCompile(`(?i)^\s*permissions:\s*['"]?(write-all|write)['"]?\s*(?:#.*)?$`)
	workflowSecretPattern      = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z0-9_]+)`)
	workflowRunKeyPattern      = regexp.MustCompile(`^\s*-?\s*run:`)
	// workflowOnKeyPattern matches only a top-level (column-0) on: key. Indenting
	// it would let a nested mapping key such as a step's `with: { on: ... }` be
	// misread as a workflow trigger, so the anchor deliberately forbids leading
	// whitespace.
	workflowOnKeyPattern    = regexp.MustCompile(`^['"]?on['"]?\s*:`)
	workflowPRTargetPattern = regexp.MustCompile(`pull_request_target`)
	workflowPRPattern       = regexp.MustCompile(`pull_request\b`)
	actionShaRefPattern     = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	actionVersionTagPattern = regexp.MustCompile(`^(?:v\d+(?:\.\d+){0,2}|\d+\.\d+(?:\.\d+)?)$`)
)

// isWorkflowFile reports whether a path is a GitHub Actions workflow YAML file
// under .github/workflows.
//
// This intentionally matches the segment anywhere in the path (not only at the
// project root) because gruff renders paths outside the scan root as absolute, so
// `gruff-go analyse /abs/project` reaches the rules with absolute paths. Anchoring
// to a leading .github/workflows/ would silently disable every workflow rule for
// absolute-path scans. The cost is that a nested docs/.github/workflows/ copy is
// still treated as a workflow; that minor false positive is preferred over a
// silent false negative across all workflow security rules.
func isWorkflowFile(path string) bool {
	clean := strings.ReplaceAll(path, "\\", "/")
	if !strings.Contains(clean, ".github/workflows/") {
		return false
	}
	lower := strings.ToLower(clean)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

// GitHubActionsUnpinnedActionRule flags third-party actions referenced by a
// mutable branch ref, which a maintainer can repoint to malicious code.
type GitHubActionsUnpinnedActionRule struct{}

// Definition declares the security.github-actions-unpinned-action rule for
// mutable-ref third-party actions.
func (GitHubActionsUnpinnedActionRule) Definition() Definition {
	return Definition{
		ID:             "security.github-actions-unpinned-action",
		Title:          "Unpinned GitHub Actions action",
		Description:    "Flags third-party GitHub Actions referenced by a mutable branch ref (for example @main or @master), which can be repointed to new code without review. Version-shaped tags (@v4, @v4.1.0) and full 40-character commit-SHA pins pass, and first-party actions/* and github/* are exempt.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"ci", "github-actions", "security"},
		Remediation:    "Pin third-party actions to a release tag or a full commit SHA instead of a branch ref so the referenced code cannot change underneath you.",
	}
}

// AnalyzeUnit emits findings for third-party actions pinned to a mutable ref.
func (GitHubActionsUnpinnedActionRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if !isWorkflowFile(unit.File.Path) {
		return nil
	}
	findings := []finding.Finding{}
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		match := workflowUsesPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		action, ref, ok := splitActionRef(match[1])
		if !ok || isFirstPartyActionOwner(action) || !isMutableActionRef(ref) {
			continue
		}
		findings = append(findings, finding.Finding{
			Message:  "third-party action is pinned to a mutable ref; pin to a tag or commit SHA",
			File:     unit.File.Path,
			Location: &finding.Location{Line: lineNumber + 1},
			Metadata: map[string]any{"action": action, "ref": ref},
		})
	}
	return findings
}

// GitHubActionsRemoteShellRule flags workflow steps that download a script and
// pipe it straight into a shell interpreter.
type GitHubActionsRemoteShellRule struct{}

// Definition declares the security.github-actions-remote-shell rule for
// download-pipe-to-shell run steps.
func (GitHubActionsRemoteShellRule) Definition() Definition {
	return Definition{
		ID:             "security.github-actions-remote-shell",
		Title:          "Remote script piped to shell in workflow",
		Description:    "Flags workflow run steps that download a remote script with curl/wget/Invoke-WebRequest and pipe it into a shell (for example `curl … | bash`), which executes unreviewed remote code in CI.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"ci", "github-actions", "security"},
		Remediation:    "Download the script to a file, verify its checksum, and review it before executing rather than piping a remote download directly into a shell.",
	}
}

// AnalyzeUnit emits findings for remote-download-to-shell pipelines.
func (GitHubActionsRemoteShellRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if !isWorkflowFile(unit.File.Path) {
		return nil
	}
	findings := []finding.Finding{}
	runLines := executableRunLines(unit.Source)
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		if !runLines[lineNumber] {
			continue
		}
		// Strip shell comments before matching. A documented `# curl … | bash`
		// inside a run: block is never executed, so matching the raw line would
		// fire on inert documentation. stripYAMLComment cuts at a # that starts a
		// comment (line start or after whitespace) while leaving an in-token #
		// such as a URL fragment intact, matching shell comment semantics.
		code := stripYAMLComment(line)
		if workflowRemoteShellPattern.MatchString(code) || workflowProcessSubPattern.MatchString(code) {
			findings = append(findings, finding.Finding{
				Message:  "workflow step pipes a remote download into a shell",
				File:     unit.File.Path,
				Location: &finding.Location{Line: lineNumber + 1},
				Metadata: map[string]any{"sink": "remote-shell"},
			})
		}
	}
	return findings
}

// GitHubActionsBroadPermissionsRule flags workflows that grant blanket write
// permissions to the GITHUB_TOKEN.
type GitHubActionsBroadPermissionsRule struct{}

// Definition declares the security.github-actions-broad-permissions rule for
// blanket write permission grants.
func (GitHubActionsBroadPermissionsRule) Definition() Definition {
	return Definition{
		ID:             "security.github-actions-broad-permissions",
		Title:          "Broad workflow permissions",
		Description:    "Flags workflows that grant blanket write access with `permissions: write-all` or a bare `permissions: write`. Scoped grants such as `permissions:` with `contents: write` underneath are not flagged.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"ci", "github-actions", "security"},
		Remediation:    "Grant the least-privilege permission scopes the workflow needs (for example `contents: read`) instead of blanket write access.",
	}
}

// AnalyzeUnit emits findings for blanket write permission lines.
func (GitHubActionsBroadPermissionsRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if !isWorkflowFile(unit.File.Path) {
		return nil
	}
	findings := []finding.Finding{}
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		match := workflowBroadPermsPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		findings = append(findings, finding.Finding{
			Message:  "workflow grants blanket write permissions",
			File:     unit.File.Path,
			Location: &finding.Location{Line: lineNumber + 1},
			Metadata: map[string]any{"permission": strings.ToLower(match[1])},
		})
	}
	return findings
}

// GitHubActionsPullRequestTargetRule flags the pull_request_target trigger when
// the workflow also executes code, the classic fork-PR escalation footgun.
type GitHubActionsPullRequestTargetRule struct{}

// Definition declares the security.github-actions-pull-request-target rule.
func (GitHubActionsPullRequestTargetRule) Definition() Definition {
	return Definition{
		ID:             "security.github-actions-pull-request-target",
		Title:          "Risky pull_request_target workflow",
		Description:    "Flags workflows triggered by pull_request_target that also check out or run code. pull_request_target runs with repository secrets in the context of a fork's pull request, so executing PR-controlled code can leak secrets. Candidate wording.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"ci", "github-actions", "security"},
		Remediation:    "Use pull_request for untrusted contributions, or keep pull_request_target jobs free of fork-controlled checkout and execution.",
	}
}

// AnalyzeUnit emits a finding when pull_request_target pairs with execution.
func (GitHubActionsPullRequestTargetRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if !isWorkflowFile(unit.File.Path) || !isPullRequestTargetTriggered(unit.Source) || !workflowHasExecution(unit.Source) {
		return nil
	}
	return []finding.Finding{{
		Message:  "pull_request_target workflow checks out or runs code with secret access",
		File:     unit.File.Path,
		Location: &finding.Location{Line: firstPatternLine(unit.Source, workflowPRTargetPattern)},
		Metadata: map[string]any{"trigger": "pull_request_target"},
	}}
}

// GitHubActionsSecretsInPRRule flags pull-request workflows that reference named
// secrets, which are exposed to fork-controlled runs.
type GitHubActionsSecretsInPRRule struct{}

// Definition declares the security.github-actions-secrets-in-pr rule.
func (GitHubActionsSecretsInPRRule) Definition() Definition {
	return Definition{
		ID:             "security.github-actions-secrets-in-pr",
		Title:          "Secrets in pull-request workflow",
		Description:    "Flags workflows triggered by pull_request or pull_request_target that reference a named secret other than the auto-provided GITHUB_TOKEN, exposing it to fork-controlled runs. Candidate wording.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"ci", "github-actions", "security"},
		Remediation:    "Keep named secrets out of pull-request-triggered workflows; gate secret-using jobs on a trusted event such as push or workflow_run.",
	}
}

// AnalyzeUnit emits findings for named secrets referenced in PR workflows.
func (GitHubActionsSecretsInPRRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if !isWorkflowFile(unit.File.Path) || !isPullRequestTriggered(unit.Source) {
		return nil
	}
	findings := []finding.Finding{}
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		// Strip YAML comments first so an inert documentation line such as
		// `# do not use ${{ secrets.DEPLOY_KEY }} on PRs` is not reported as a
		// secret reference, matching the remote-shell and broad-permissions rules.
		code := stripYAMLComment(line)
		for _, match := range workflowSecretPattern.FindAllStringSubmatch(code, -1) {
			if match[1] == "GITHUB_TOKEN" {
				continue
			}
			findings = append(findings, finding.Finding{
				Message:  "pull-request workflow references a named secret",
				File:     unit.File.Path,
				Location: &finding.Location{Line: lineNumber + 1},
				Metadata: map[string]any{"secret": match[1]},
			})
		}
	}
	return findings
}

// splitActionRef splits an action reference into its owner/repo and ref. It
// returns ok=false for local (`./…`) or container (`docker://…`) actions and for
// references with no @ref.
func splitActionRef(uses string) (string, string, bool) {
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "../") || strings.HasPrefix(uses, "docker://") {
		return "", "", false
	}
	at := strings.LastIndex(uses, "@")
	if at <= 0 || at == len(uses)-1 {
		return "", "", false
	}
	return uses[:at], uses[at+1:], true
}

// isFirstPartyActionOwner reports whether the action is maintained by GitHub
// (the actions/* and github/* namespaces), which are exempt from the pin check.
func isFirstPartyActionOwner(action string) bool {
	owner := action
	if slash := strings.Index(action, "/"); slash >= 0 {
		owner = action[:slash]
	}
	return owner == "actions" || owner == "github"
}

// isMutableActionRef reports whether a ref can move under the consumer: anything
// that is neither a commit SHA nor a version tag is treated as a mutable branch.
func isMutableActionRef(ref string) bool {
	if actionShaRefPattern.MatchString(ref) || actionVersionTagPattern.MatchString(ref) {
		return false
	}
	return true
}

// workflowHasExecution reports whether the workflow checks out code or has a run
// step, the execution surface that makes pull_request_target dangerous. Each line
// has its trailing comment stripped first so a metadata-only target workflow that
// merely mentions actions/checkout or run: in a comment is not treated as
// executing code (mirrors the comment handling in workflowTriggerSection).
func workflowHasExecution(source string) bool {
	for _, line := range strings.Split(source, "\n") {
		code := stripYAMLComment(line)
		if strings.Contains(code, "actions/checkout") || workflowRunKeyPattern.MatchString(code) {
			return true
		}
	}
	return false
}

// isPullRequestTriggered reports whether the workflow's on: triggers include a
// pull-request event (pull_request or pull_request_target). It inspects only the
// on: block so a pull_request mention in a comment, job name, or step condition
// elsewhere does not register as a trigger.
func isPullRequestTriggered(source string) bool {
	section := workflowTriggerSection(source)
	return workflowPRTargetPattern.MatchString(section) || workflowPRPattern.MatchString(section)
}

// isPullRequestTargetTriggered reports whether the workflow's on: triggers include
// pull_request_target specifically.
func isPullRequestTargetTriggered(source string) bool {
	return workflowPRTargetPattern.MatchString(workflowTriggerSection(source))
}

// leadingSpaces counts the leading space characters of a YAML line, a cheap
// indentation measure for the dependency-free block-scope heuristics below.
func leadingSpaces(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n
}

// stripYAMLComment removes a trailing "# …" comment from a line. A '#' counts as a
// comment only at line start or after whitespace, so a '#' inside a quoted scalar
// is left intact and commented text cannot register as a trigger.
func stripYAMLComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

// executableRunLines returns the 0-indexed lines that belong to a run: step body —
// the inline content on the run: line plus the more-indented block-scalar
// continuation lines. Limiting the remote-shell scan to these lines excludes
// non-run keys that CI never executes; the caller additionally strips shell
// comments within these lines so a documented (non-executed) pipeline does not match.
func executableRunLines(source string) map[int]bool {
	lines := strings.Split(source, "\n")
	inRun := map[int]bool{}
	runColumn := -1
	for i, line := range lines {
		if runColumn >= 0 {
			if strings.TrimSpace(line) == "" {
				inRun[i] = true
				continue
			}
			if leadingSpaces(line) > runColumn {
				inRun[i] = true
				continue
			}
			runColumn = -1 // a dedent ends the block; re-check this line as a key
		}
		if workflowRunKeyPattern.MatchString(line) {
			inRun[i] = true
			runColumn = strings.Index(line, "run:")
		}
	}
	return inRun
}

// workflowTriggerSection returns the text of the workflow on: block — the inline
// value plus its nested, more-indented event lines, with trailing comments
// stripped — so trigger detection sees only declared events.
func workflowTriggerSection(source string) string {
	lines := strings.Split(source, "\n")
	var section strings.Builder
	onColumn := -1
	for _, line := range lines {
		if onColumn >= 0 {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if leadingSpaces(line) > onColumn {
				section.WriteString(stripYAMLComment(line))
				section.WriteByte('\n')
				continue
			}
			onColumn = -1 // a dedent ends the section; re-check this line as a key
		}
		if workflowOnKeyPattern.MatchString(line) {
			section.WriteString(stripYAMLComment(line))
			section.WriteByte('\n')
			onColumn = leadingSpaces(line)
		}
	}
	return section.String()
}

// firstPatternLine returns the 1-indexed line of the first match for pattern, or
// 1 when no line matches.
func firstPatternLine(source string, pattern *regexp.Regexp) int {
	for index, line := range strings.Split(source, "\n") {
		if pattern.MatchString(line) {
			return index + 1
		}
	}
	return 1
}
