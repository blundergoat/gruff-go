// Package rule holds the expected default rule-ID catalogue for the registry tests.
// Keeping the long sorted lists here keeps builtin_test.go within the size budget.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestRetiredLowPrecisionRulesLeaveRegistryAndDispatch covers both catalogue
// membership and runtime execution on code each retired detector reported.
func TestRetiredLowPrecisionRulesLeaveRegistryAndDispatch(t *testing.T) {
	retired := map[string]bool{
		"naming.negated-boolean":       true,
		"test-quality.no-failure-path": true,
		"test-quality.skipped-test":    true,
	}
	registry := Defaults()
	for _, definition := range registry.Definitions() {
		if retired[definition.ID] {
			t.Errorf("retired rule %s remains in the catalogue", definition.ID)
		}
	}
	unit := parseOne(t, "pkg/retirement_test.go", `package sample
import "testing"
type Settings struct { DisableCache bool }
func TestSkipped(t *testing.T) { t.Skip("later") }
func TestLogging(t *testing.T) { t.Log("running") }
`)
	for _, item := range registry.Analyze([]parser.Unit{unit}, Context{}) {
		if retired[item.RuleID] {
			t.Errorf("retired rule %s still emits a finding", item.RuleID)
		}
	}
}

// defaultRuleIDs returns the sorted built-in rule IDs expected from Defaults.
// The catalogue is split into two halves at the security pillar boundary so each
// helper stays within the function-length threshold.
func defaultRuleIDs() []string {
	return append(defaultRuleIDsThroughNaming(), defaultRuleIDsSecurityOnward()...)
}

// defaultRuleIDsThroughNaming lists the sorted rule IDs from the complexity
// pillar through the naming pillar (everything before security).
func defaultRuleIDsThroughNaming() []string {
	return []string{
		"complexity.cognitive",
		"complexity.cyclomatic",
		"complexity.nesting-depth",
		"dead-code.empty-block",
		"dead-code.unreachable-code",
		"dead-code.unused-private-const",
		"dead-code.unused-private-function",
		"dead-code.unused-private-type",
		"dead-code.unused-private-var",
		"dependency.go-mod-local-replace",
		"dependency.go-mod-remote-replace",
		"design.hotspot-file",
		"docs.comment-rubric",
		"docs.config-field-comment",
		"docs.exported-symbol-comment",
		"docs.missing-param-doc",
		"docs.missing-return-doc",
		"docs.package-comment",
		"docs.suppression-without-rationale",
		"maintainability.context-todo-production",
		"maintainability.defer-in-loop",
		"maintainability.ignored-error",
		"maintainability.log-fatal-library",
		"maintainability.loop-variable-address",
		"maintainability.production-panic",
		"modernisation.ioutil-deprecated",
		"naming.acronym-case",
		"naming.contextual-generic",
		"naming.get-prefix",
		"naming.identifier-quality",
		"naming.misspelling",
		"naming.package-stutter",
		"naming.package-underscore",
		"naming.receiver-consistency",
	}
}

// defaultRuleIDsSecurityOnward lists the sorted rule IDs from the security pillar
// through test-quality (security, sensitive-data, size, test-quality).
func defaultRuleIDsSecurityOnward() []string {
	return []string{
		"security.archive-path-traversal",
		"security.github-actions-broad-permissions",
		"security.github-actions-pull-request-target",
		"security.github-actions-remote-shell",
		"security.github-actions-secrets-in-pr",
		"security.github-actions-unpinned-action",
		"security.http-client-no-timeout",
		"security.http-server-no-timeout",
		"security.insecure-random-secret",
		"security.open-redirect-candidate",
		"security.path-traversal-file-access",
		"security.permissive-file-mode",
		"security.request-body-without-limit",
		"security.request-controlled-url",
		"security.shell-command",
		"security.template-injection-xss",
		"security.tls-insecure-config",
		"security.unsafe-deserialization",
		"security.weak-crypto",
		"security.xxe-candidate",
		"sensitive-data.anthropic-api-key",
		"sensitive-data.aws-access-key",
		"sensitive-data.connection-string",
		"sensitive-data.gcp-service-account",
		"sensitive-data.github-token",
		"sensitive-data.gitlab-token",
		"sensitive-data.google-api-key",
		"sensitive-data.jwt-token",
		"sensitive-data.npm-token",
		"sensitive-data.phi-pattern",
		"sensitive-data.pii-pattern",
		"sensitive-data.private-key",
		"sensitive-data.secret-pattern",
		"sensitive-data.slack-token",
		"sensitive-data.stripe-key",
		"size.file-length",
		"size.function-length",
		"size.parameter-count",
		"test-quality.duplicate-test-body",
		"test-quality.empty-test",
		"test-quality.fatal-in-goroutine",
		"test-quality.helper-missing-t-helper",
		"test-quality.parallel-range-capture",
		"test-quality.sleep-in-test",
		"test-quality.static-analysis-redundant-test",
		"test-quality.tempdir-misuse",
	}
}

// defaultDisabledRuleIDs returns rules that ship opt-in because they enforce
// house-style conventions or candidate checks that still need calibration.
func defaultDisabledRuleIDs() map[string]bool {
	// Precision-floor M19 added seven rules on 2026-10-04: each was right less than half the time
	// on fewer than ten findings, so it is off by default rather than deleted (ADR-021).
	return map[string]bool{
		// Precision-floor M14 turned it off on 2026-10-09: after its repair its upper band was right on 23 of 40.
		"complexity.cyclomatic":           true,
		"dependency.go-mod-local-replace": true,
		// Precision-floor M13 builds the parameter- and return-prose rules off by default until their own measurement passes.
		"docs.missing-param-doc":          true,
		"docs.missing-return-doc":         true,
		"security.insecure-random-secret": true,
		// Precision-floor M02 turned it off on 2026-10-14: fewer than ten findings remain after its repair.
		"security.open-redirect-candidate": true,
		// Precision-floor M02 turned it off on 2026-10-14: fewer than ten findings remain after its repair.
		"security.request-body-without-limit":         true,
		"sensitive-data.aws-access-key":               true,
		"sensitive-data.connection-string":            true,
		"sensitive-data.gcp-service-account":          true,
		"sensitive-data.github-token":                 true,
		"sensitive-data.google-api-key":               true,
		"dead-code.unused-private-const":              true,
		"dead-code.unused-private-type":               true,
		"dead-code.unused-private-var":                true,
		"modernisation.ioutil-deprecated":             true,
		"naming.acronym-case":                         true,
		"naming.get-prefix":                           true,
		"naming.package-stutter":                      true,
		"naming.package-underscore":                   true,
		"naming.receiver-consistency":                 true,
		"sensitive-data.phi-pattern":                  true,
		"sensitive-data.pii-pattern":                  true,
		"test-quality.duplicate-test-body":            true,
		"test-quality.static-analysis-redundant-test": true,
	}
}
