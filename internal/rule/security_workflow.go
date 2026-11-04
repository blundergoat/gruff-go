// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements the GitHub Actions workflow security checks that gruff-go runs on .github/workflows YAML files.
// They read the YAML as plain text, with no YAML library and no execution, so nesting is judged by indentation alone.
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
	// workflowOnKeyPattern matches only a top-level, column-0 on: key, quoted or not.
	//
	// Allowing indentation would let a nested key, such as on: inside a step's with: map, be misread as a workflow trigger.
	// The anchor therefore forbids leading whitespace.
	workflowOnKeyPattern    = regexp.MustCompile(`^['"]?on['"]?\s*:`)
	workflowPRTargetPattern = regexp.MustCompile(`pull_request_target`)
	workflowPRPattern       = regexp.MustCompile(`pull_request\b`)
	actionShaRefPattern     = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	actionVersionTagPattern = regexp.MustCompile(`^(?:v\d+(?:\.\d+){0,2}|\d+\.\d+(?:\.\d+)?)$`)
)

// isWorkflowFile reports whether path is treated as a GitHub Actions workflow file; false makes every workflow rule skip it.
//
// Absolute paths outside the project root need an unanchored match, or every workflow rule would skip those files.
// Nested docs/.github/workflows/ and not.github/workflows/ copies also match; that false positive is preferred to missing a workflow.
// It reports true when path, with backslashes as slashes, contains .github/workflows/ and ends in .yml or .yaml in any letter case.
func isWorkflowFile(path string) bool {
	clean := strings.ReplaceAll(path, "\\", "/")
	if !strings.Contains(clean, ".github/workflows/") {
		return false
	}
	lower := strings.ToLower(clean)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

// GitHubActionsUnpinnedActionRule is security.github-actions-unpinned-action, run on workflow files.
//
// It flags a third-party uses: ref that is neither a full commit SHA nor version-shaped, since its owner can repoint it to malicious code.
type GitHubActionsUnpinnedActionRule struct{}

// Definition declares the security.github-actions-unpinned-action rule for mutable-ref third-party actions.
// It returns fixed rule metadata, advisory severity and high confidence, enabled by default with no thresholds.
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
//
// The unit must be a workflow YAML file; local, docker:// and ref-less uses: values are skipped, as are actions and github owners.
// Any other ref is reported unless it is a 40-character hex SHA or matches actionVersionTagPattern, so a prerelease tag is reported.
// It returns nil for any other unit, else one finding per such line, or an empty slice when none qualifies.
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

// GitHubActionsRemoteShellRule is security.github-actions-remote-shell, run on workflow files.
//
// It flags a run: line that pipes curl, wget or Invoke-WebRequest output into a shell, or runs bash <(curl ...), running remote code unreviewed.
type GitHubActionsRemoteShellRule struct{}

// Definition declares the security.github-actions-remote-shell rule for download-pipe-to-shell run steps.
// It returns fixed rule metadata, advisory severity and high confidence, enabled by default with no thresholds.
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
//
// The unit must be a workflow YAML file; matching run: lines and their indented continuations are scanned after comment stripping.
// A run: line nested in another YAML scalar, such as a multi-line name: value, also matches, since only text and indentation are read.
// It returns nil for any other unit, else one finding per matching line, or an empty slice when none matches.
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
		// Strip comments before matching, so a documented # curl URL | bash inside a run: block is not reported.
		//
		// stripYAMLComment cuts at a # at line start or after whitespace and keeps an in-token #, such as a URL fragment.
		// It does not track quotes, so a # after a space inside a quoted shell string cuts the line there and a pipeline after it is missed.
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

// GitHubActionsBroadPermissionsRule is security.github-actions-broad-permissions, run on workflow files.
//
// It flags a permissions: line set to write-all or a bare write, the blanket GITHUB_TOKEN grants; scoped permission maps do not match.
// The match is text only, so such a line inside another YAML value, such as a multi-line name:, is flagged too.
type GitHubActionsBroadPermissionsRule struct{}

// Definition declares the security.github-actions-broad-permissions rule for blanket write permission grants.
// It returns fixed rule metadata, advisory severity and high confidence, enabled by default with no thresholds.
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
//
// The unit must be a workflow YAML file; a permissions: line set to write-all or write, quoted or not and in any case, gives one finding.
// It returns nil for any other unit, else one finding per such line, or an empty slice when none matches.
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

// GitHubActionsPullRequestTargetRule is security.github-actions-pull-request-target, aimed at the classic fork-PR escalation footgun.
//
// It flags a workflow whose on: text mentions pull_request_target and that also mentions actions/checkout or a run: key.
// The trigger check is a text search, so pull_request_target inside a nested event filter, such as a push filter value, also counts.
type GitHubActionsPullRequestTargetRule struct{}

// Definition declares the security.github-actions-pull-request-target rule.
// It returns fixed rule metadata, advisory severity and medium confidence, enabled by default with no thresholds.
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
//
// The unit must be a workflow YAML file whose on: section text contains pull_request_target, nested filter values included.
// Some comment-stripped line must also mention actions/checkout or start a run: key, which workflowHasExecution takes as execution.
// It returns a single finding on the first source line mentioning pull_request_target, and nil otherwise.
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

// GitHubActionsSecretsInPRRule flags pull_request_target workflows that reference named secrets.
//
// That trigger gives the base-branch workflow the repository's secrets, while a plain pull_request run from a fork receives none.
// The trigger check is a text search of the on: section, so a nested filter value naming pull_request_target also counts.
type GitHubActionsSecretsInPRRule struct{}

// Definition declares the security.github-actions-secrets-in-pr rule.
// It returns fixed rule metadata, advisory severity and medium confidence, enabled by default with no thresholds.
func (GitHubActionsSecretsInPRRule) Definition() Definition {
	return Definition{
		ID:             "security.github-actions-secrets-in-pr",
		Title:          "Secrets in pull-request workflow",
		Description:    "Flags workflows triggered by pull_request_target that reference a named secret other than the auto-provided GITHUB_TOKEN, exposing it to fork-controlled runs. A plain pull_request run from a fork receives no secrets.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"ci", "github-actions", "security"},
		Remediation:    "Keep named secrets out of pull-request-triggered workflows. Run secret-using jobs only on trusted events such as push, and when a workflow_run job follows a pull-request workflow, check the triggering repository and branch before it uses secrets.",
	}
}

// AnalyzeUnit emits findings for named secrets referenced in PR workflows.
//
// For a workflow unit with pull_request_target in its on: text, each ${{ secrets.NAME other than GITHUB_TOKEN gives one finding.
// The reference must open the expression, so a nested one such as ${{ toJSON(secrets.DEPLOY_KEY) }} is missed.
// Comments are stripped first, and lines that workflowUnreachableSecretLines marks are skipped.
//
// It returns nil for any other unit, else one finding per reference, or an empty slice when none qualifies.
func (GitHubActionsSecretsInPRRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if !isWorkflowFile(unit.File.Path) || !isPullRequestTargetTriggered(unit.Source) {
		return nil
	}
	findings := []finding.Finding{}
	unreachable := workflowUnreachableSecretLines(unit.Source)
	for lineNumber, line := range strings.Split(unit.Source, "\n") {
		// Strip YAML comments first, as the remote-shell and broad-permissions rules also ignore comments.
		// A documentation line such as # do not use ${{ secrets.DEPLOY_KEY }} on PRs is then not reported as a secret reference.
		code := stripYAMLComment(line)
		for _, match := range workflowSecretPattern.FindAllStringSubmatch(code, -1) {
			if match[1] == "GITHUB_TOKEN" || unreachable[lineNumber+1] {
				continue
			}
			findings = append(findings, finding.Finding{
				Message:  "pull_request_target workflow references a named secret",
				File:     unit.File.Path,
				Location: &finding.Location{Line: lineNumber + 1},
				Metadata: map[string]any{"secret": match[1]},
			})
		}
	}
	return findings
}

// splitActionRef returns the action path, including any subdirectory, and the ref from uses, split at its last @, with true.
// It returns empty strings and false for a local ./ or ../ action, a docker:// container, and a value with no @ or nothing before or after it.
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

// isFirstPartyActionOwner reports whether action belongs to the actions or github owner, which the pin check exempts.
// A false result means the action is third-party, so its ref is checked for pinning.
func isFirstPartyActionOwner(action string) bool {
	owner := action
	if slash := strings.Index(action, "/"); slash >= 0 {
		owner = action[:slash]
	}
	return owner == "actions" || owner == "github"
}

// isMutableActionRef reports whether ref matches neither a full 40-character hexadecimal SHA nor a supported numeric-version shape.
// It reads spelling only, so a branch named v1 passes like a tag, while a prerelease tag such as v1.0.0-beta reports true as mutable.
func isMutableActionRef(ref string) bool {
	if actionShaRefPattern.MatchString(ref) || actionVersionTagPattern.MatchString(ref) {
		return false
	}
	return true
}

// workflowHasExecution reports whether any line mentions actions/checkout or starts a run: key.
//
// That is a text proxy for the execution surface that makes pull_request_target dangerous.
// Each line has its trailing comment stripped first, as in workflowTriggerSection, so a mention inside a comment does not count as execution.
//
// The source is the whole workflow text, so a name or other value that mentions actions/checkout also counts; false means no line qualifies.
func workflowHasExecution(source string) bool {
	for _, line := range strings.Split(source, "\n") {
		code := stripYAMLComment(line)
		if strings.Contains(code, "actions/checkout") || workflowRunKeyPattern.MatchString(code) {
			return true
		}
	}
	return false
}

// isPullRequestTargetTriggered reports whether pull_request_target appears in the on: text that workflowTriggerSection collects.
//
// A nested filter value or a longer word containing it also counts, so a push filter that names it is enough.
// The source is the whole workflow text; collection stops at any non-blank dedent, even a column-0 comment, so false can miss later events.
func isPullRequestTargetTriggered(source string) bool {
	return workflowPRTargetPattern.MatchString(workflowTriggerSection(source))
}

// leadingSpaces counts the leading space characters of a YAML line.
//
// It is a cheap indentation measure for the dependency-free block-scope heuristics below.
// It returns the number of space bytes before any other byte, so a tab stops the count and an unindented or empty line gives 0.
func leadingSpaces(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n
}

// stripYAMLComment removes a trailing comment from line.
//
// A '#' counts as a comment only at line start or after a space or tab, so a '#' inside a token, such as a URL fragment, is left intact.
// Quotes are not tracked, so a '#' after a space inside a quoted string also cuts the line; commented text cannot register as a trigger.
// It returns line cut just before the first such '#', or line unchanged when it has none.
func stripYAMLComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

// executableRunLines returns the 0-indexed lines that belong to a run: step body, each mapped to true.
//
// That is the run: line itself plus its more-indented block-scalar continuation lines; the caller strips comments within them.
// A run: line nested in another YAML scalar, such as a multi-line name: value, also matches, since only text and indentation are read.
//
// The source is the whole workflow text; blank lines inside a run block count as run lines, and a source without run: keys gives an empty map.
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

// workflowTriggerSection returns the text of the workflow on: block, so trigger detection ignores keys outside it.
//
// It collects the on: line and the more-indented lines after it, event filters included, each with its trailing comment stripped.
// Any non-blank line that is not more indented ends collection, even a column-0 comment, so events listed below such a comment are missed.
// The source is the workflow text; only a column-0 on: key starts the section, blank lines are dropped, and without one the result is empty.
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

// firstPatternLine returns the 1-indexed line of the first match for pattern, or 1 when no line matches.
// The source is split on newlines and pattern is matched against each line in turn.
func firstPatternLine(source string, pattern *regexp.Regexp) int {
	for index, line := range strings.Split(source, "\n") {
		if pattern.MatchString(line) {
			return index + 1
		}
	}
	return 1
}
