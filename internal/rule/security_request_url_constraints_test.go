// Package rule tests the destination evidence shown in URL security findings.
// Its fixtures model user handlers that parse, validate, fetch, or redirect so
// terminal, JSON, and dashboard results agree on what counts as safe.
package rule

import "testing"

// TestRequestControlledURLRequiresAffirmativeConstraint distinguishes syntax
// parsing and name collisions from actual destination-validation evidence.
func TestRequestControlledURLRequiresAffirmativeConstraint(t *testing.T) {
	testCases := []struct {
		journeyName      string
		handlerBody      string
		expectedFindings int
	}{
		{
			journeyName: "bare parse before fetch still flags",
			handlerBody: `target := r.FormValue("url")
	// A user-facing parse error stops malformed syntax but does not trust a destination.
	if _, err := url.Parse(target); err != nil {
		return
	}
	_, _ = http.Get(target)`,
			expectedFindings: 1,
		},
		{
			journeyName: "assigned parse result still flags",
			handlerBody: `parsed, err := url.Parse(r.FormValue("url"))
	// A malformed submitted URL is rejected before the request is built.
	if err != nil {
		return
	}
	_, _ = http.Get(parsed.String())`,
			expectedFindings: 1,
		},
		{
			journeyName: "assigned ParseRequestURI result still flags",
			handlerBody: `parsed, err := url.ParseRequestURI(r.FormValue("url"))
	// A malformed submitted URI is rejected before the request is built.
	if err != nil {
		return
	}
	_, _ = http.Get(parsed.String())`,
			expectedFindings: 1,
		},
		{
			journeyName:      "inline parse-named helper still flags",
			handlerBody:      `_, _ = http.Get(parseAndReturn(r.FormValue("url")))`,
			expectedFindings: 1,
		},
		{
			journeyName: "parse-named check before request construction still flags",
			handlerBody: `target := r.FormValue("url")
	// A parser-named helper checks syntax only and leaves the destination untrusted.
	if !parser(target) {
		return
	}
	_, _ = http.NewRequest("GET", target, nil)`,
			expectedFindings: 1,
		},
		{
			journeyName: "parse-named check before contextual request still flags",
			handlerBody: `target := r.FormValue("url")
	_ = parseAndReturn(target)
	_, _ = http.NewRequestWithContext(context.Background(), "GET", target, nil)`,
			expectedFindings: 1,
		},
		{journeyName: "allowance collision still flags", handlerBody: requestURLHelperBody("allowanceURL"), expectedFindings: 1},
		{journeyName: "trustedness collision still flags", handlerBody: requestURLHelperBody("trustednessURL"), expectedFindings: 1},
		{journeyName: "sanitation collision still flags", handlerBody: requestURLHelperBody("sanitationURL"), expectedFindings: 1},
		{journeyName: "untrusted negative still flags", handlerBody: requestURLHelperBody("untrustedURL"), expectedFindings: 1},
		{journeyName: "not-trusted tokens still flag", handlerBody: requestURLHelperBody("notTrustedURL"), expectedFindings: 1},
		{journeyName: "disallow negative still flags", handlerBody: requestURLHelperBody("disallowHost"), expectedFindings: 1},
		{journeyName: "not-allowed tokens still flag", handlerBody: requestURLHelperBody("isNotAllowedDestination"), expectedFindings: 1},
		{journeyName: "invalidated negative still flags", handlerBody: requestURLHelperBody("invalidatedURL"), expectedFindings: 1},
		{journeyName: "exact allowed token is affirmative", handlerBody: requestURLHelperBody("isAllowedDestination"), expectedFindings: 0},
		{journeyName: "exact validated token is affirmative", handlerBody: requestURLHelperBody("validatedDestination"), expectedFindings: 0},
		{
			journeyName: "explicit scheme and host allowlist is affirmative",
			handlerBody: `target := r.FormValue("url")
	parsed, err := url.Parse(target)
	// The user request proceeds only for the configured HTTPS service host.
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "api.internal" {
		return
	}
	_, _ = http.Get(target)`,
			expectedFindings: 0,
		},
		{
			journeyName: "constrained assigned parse result is affirmative",
			handlerBody: `parsed, err := url.Parse(r.FormValue("url"))
	// The stored URL remains safe because both destination dimensions are checked.
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "api.internal" {
		return
	}
	_, _ = http.Get(parsed.String())`,
			expectedFindings: 0,
		},
		{
			journeyName: "field write after the guard still flags",
			handlerBody: `parsed, err := url.Parse(r.FormValue("url"))
	// Both dimensions are checked, then the submitted host replaces the one that passed.
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "api.internal" {
		return
	}
	parsed.Host = r.FormValue("host")
	_, _ = http.Get(parsed.String())`,
			expectedFindings: 1,
		},
		{
			journeyName: "scheme check without host still flags",
			handlerBody: `target := r.FormValue("url")
	parsed, err := url.Parse(target)
	// Restricting only the scheme still lets a user choose an internal or hostile host.
	if err != nil || parsed.Scheme != "https" {
		return
	}
	_, _ = http.Get(target)`,
			expectedFindings: 1,
		},
		{
			journeyName: "host check without scheme still flags",
			handlerBody: `target := r.FormValue("url")
	parsed, err := url.Parse(target)
	// Restricting only the host leaves unsupported destination schemes available.
	if err != nil || parsed.Hostname() != "api.internal" {
		return
	}
	_, _ = http.Get(target)`,
			expectedFindings: 1,
		},
		{
			journeyName: "scheme and host guards on exclusive branches still flag",
			handlerBody: `target := r.FormValue("url")
	parsed, err := url.Parse(target)
	if err != nil {
		return
	}
	// Each branch constrains one dimension, so no execution path checks both.
	if r.FormValue("mode") == "strict" {
		if parsed.Scheme != "https" {
			return
		}
	} else {
		if parsed.Hostname() != "api.internal" {
			return
		}
	}
	_, _ = http.Get(parsed.String())`,
			expectedFindings: 1,
		},
		{
			journeyName: "constraints after fetch do not cleanse",
			handlerBody: `target := r.FormValue("url")
	_, _ = http.Get(target)
	parsed, _ := url.Parse(target)
	// A check after the UI-triggered fetch cannot protect the request already sent.
	if parsed.Scheme != "https" || parsed.Hostname() != "api.internal" {
		return
	}`,
			expectedFindings: 1,
		},
		{
			journeyName: "fixed trusted base join stays safe",
			handlerBody: `base, _ := url.Parse("https://api.internal")
	target := base.JoinPath(r.FormValue("path"))
	_, _ = http.Get(target.String())`,
			expectedFindings: 0,
		},
	}

	// Run each user journey against the same request-URL report rule.
	for _, testCase := range testCases {
		t.Run(testCase.journeyName, func(t *testing.T) {
			unit := parseOne(t, "handler.go", requestURLConstraintSource("fetch", testCase.handlerBody))
			findings := RequestControlledURLRule{}.AnalyzeUnit(unit, Context{})
			// A mismatch means the user would see the wrong finding count.
			if len(findings) != testCase.expectedFindings {
				t.Fatalf("findings = %#v, want %d", findings, testCase.expectedFindings)
			}
		})
	}
}

// TestOpenRedirectRequiresAffirmativeConstraint pins robust relative and
// destination allowlists while rejecting parse/prefix-only evidence.
func TestOpenRedirectRequiresAffirmativeConstraint(t *testing.T) {
	testCases := []struct {
		journeyName      string
		handlerBody      string
		expectedFindings int
	}{
		{
			journeyName: "bare parse before redirect still flags",
			handlerBody: `target := r.FormValue("next")
	// Invalid syntax is rejected, but a valid external redirect is still possible.
	if _, err := url.Parse(target); err != nil {
		return
	}
	http.Redirect(w, r, target, 302)`,
			expectedFindings: 1,
		},
		{
			journeyName: "assigned parse result still flags",
			handlerBody: `parsed, err := url.Parse(r.FormValue("next"))
	// A parse failure stops the response before any redirect is written.
	if err != nil {
		return
	}
	http.Redirect(w, r, parsed.String(), 302)`,
			expectedFindings: 1,
		},
		{
			journeyName: "bare slash prefix check still flags",
			handlerBody: `target := r.FormValue("next")
	// A bare slash still permits a user to submit //external.example.
	if !strings.HasPrefix(target, "/") {
		return
	}
	http.Redirect(w, r, target, 302)`,
			expectedFindings: 1,
		},
		{
			journeyName: "committed segment prefix check is affirmative",
			handlerBody: `target := r.FormValue("next")
	// The UI accepts only destinations inside the account path segment.
	if !strings.HasPrefix(target, "/account/") {
		return
	}
	http.Redirect(w, r, target, 302)`,
			expectedFindings: 0,
		},
		{
			journeyName: "repeated protocol-relative prefix stripping is affirmative",
			handlerBody: `target := r.FormValue("next")
	// A user may submit several leading slashes, so remove them until the target is same-origin.
	for strings.HasPrefix(target, "//") {
		target = strings.TrimPrefix(target, "/")
	}
	http.Redirect(w, r, target, 302)`,
			expectedFindings: 0,
		},
		{journeyName: "parser helper still flags", handlerBody: redirectHelperBody("parser"), expectedFindings: 1},
		{journeyName: "allowance collision still flags", handlerBody: redirectHelperBody("allowanceURL"), expectedFindings: 1},
		{journeyName: "untrusted negative still flags", handlerBody: redirectHelperBody("untrustedURL"), expectedFindings: 1},
		{journeyName: "not-trusted tokens still flag", handlerBody: redirectHelperBody("notTrustedURL"), expectedFindings: 1},
		{journeyName: "disallow negative still flags", handlerBody: redirectHelperBody("disallowHost"), expectedFindings: 1},
		{journeyName: "exact relative helper is affirmative", handlerBody: redirectHelperBody("isRelativeRedirect"), expectedFindings: 0},
		{journeyName: "exact validated helper is affirmative", handlerBody: redirectHelperBody("validatedDestination"), expectedFindings: 0},
		{
			journeyName: "explicit scheme and host allowlist is affirmative",
			handlerBody: `target := r.FormValue("next")
	parsed, err := url.Parse(target)
	// The redirect proceeds only to the configured HTTPS login service.
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "login.internal" {
		return
	}
	http.Redirect(w, r, target, 302)`,
			expectedFindings: 0,
		},
		{
			journeyName:      "committed relative construction stays safe",
			handlerBody:      `http.Redirect(w, r, "/account/"+r.FormValue("page"), 302)`,
			expectedFindings: 0,
		},
	}

	// Run each user journey against the same open-redirect report rule.
	for _, testCase := range testCases {
		t.Run(testCase.journeyName, func(t *testing.T) {
			unit := parseOne(t, "handler.go", requestURLConstraintSource("redirect", testCase.handlerBody))
			findings := OpenRedirectRule{}.AnalyzeUnit(unit, Context{})
			// A mismatch means the user would see the wrong finding count.
			if len(findings) != testCase.expectedFindings {
				t.Fatalf("findings = %#v, want %d", findings, testCase.expectedFindings)
			}
		})
	}
}

// requestURLHelperBody builds a handler where a user URL passes one named check
// before an outbound fetch, making token-collision expectations easy to review.
func requestURLHelperBody(helperName string) string {
	return `target := r.FormValue("url")
	// The helper name is the only evidence available to the parser-only scan.
	if !` + helperName + `(target) {
		return
	}
	_, _ = http.Get(target)`
}

// redirectHelperBody builds the equivalent user journey for redirect sinks so
// request and redirect naming policies stay aligned.
func redirectHelperBody(helperName string) string {
	return `target := r.FormValue("next")
	// The helper name is the only evidence available to the parser-only scan.
	if !` + helperName + `(target) {
		return
	}
	http.Redirect(w, r, target, 302)`
}

// requestURLConstraintSource wraps one journey in a parseable handler with all
// helper-name variants a user project might expose to the scanner.
func requestURLConstraintSource(handlerName, handlerBody string) string {
	return `// Package handler models URL choices submitted through a web UI.
// It exercises syntax checks, destination validators, outbound fetches, and
// redirects so the scanner can show users the correct safety distinction.
package handler

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// parser models a syntax-only helper a user's handler might call.
func parser(string) bool { return true }
// parseAndReturn models syntax work that returns the submitted destination.
func parseAndReturn(value string) string { return value }
// sanitizedURL models a destination sanitizer that returns the trusted value.
func sanitizedURL(value string) string { return value }
// allowanceURL models a colliding helper name that must not hide a finding.
func allowanceURL(string) bool { return true }
// trustednessURL models a colliding helper name that does not prove trust.
func trustednessURL(string) bool { return true }
// sanitationURL models a colliding helper name that does not sanitize input.
func sanitationURL(string) bool { return true }
// untrustedURL models a negative helper name that keeps the finding visible.
func untrustedURL(string) bool { return true }
// notTrustedURL models explicit negation in the user's validation vocabulary.
func notTrustedURL(string) bool { return true }
// disallowHost models a rejection helper that does not prove a safe destination.
func disallowHost(string) bool { return true }
// isNotAllowedDestination models a multi-token rejection helper.
func isNotAllowedDestination(string) bool { return true }
// invalidatedURL models a collision with the positive validated token.
func invalidatedURL(string) bool { return true }
// isAllowedDestination models an affirmative allowlist helper.
func isAllowedDestination(string) bool { return true }
// validatedDestination models an affirmative destination validator.
func validatedDestination(string) bool { return true }
// isRelativeRedirect models a verified same-origin path check used before redirecting.
func isRelativeRedirect(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && !parsed.IsAbs() && parsed.Host == "" &&
		strings.HasPrefix(parsed.Path, "/") && !strings.HasPrefix(parsed.Path, "//")
}

// The handler models the user action that reaches an outbound URL sink.
func ` + handlerName + `(w http.ResponseWriter, r *http.Request) {
	` + handlerBody + `
}
`
}

// TestTrimLoopBranchAttribution pins which `break` spellings void the
// slash-normalisation proof. Go binds an unlabelled break to the innermost
// enclosing loop or switch, so a break inside a nested construct never escapes
// the trim; reading every break as an escape reported handlers that were in
// fact fully normalised, and a false open-redirect finding fails the default
// advisory gate.
func TestTrimLoopBranchAttribution(t *testing.T) {
	testCases := []struct {
		journeyName      string
		handlerBody      string
		expectedFindings int
	}{
		{
			journeyName: "complete normalisation stays clean",
			handlerBody: `target := r.FormValue("next")
	for strings.HasPrefix(target, "//") {
		target = strings.TrimPrefix(target, "/")
	}
	http.Redirect(w, r, target, 302)`,
			expectedFindings: 0,
		},
		{
			journeyName: "break bound to a nested loop still normalises",
			handlerBody: `target := r.FormValue("next")
	for strings.HasPrefix(target, "//") {
		for range target {
			break
		}
		target = strings.TrimPrefix(target, "/")
	}
	http.Redirect(w, r, target, 302)`,
			expectedFindings: 0,
		},
		{
			journeyName: "break bound to a nested switch still normalises",
			handlerBody: `target := r.FormValue("next")
	for strings.HasPrefix(target, "//") {
		switch len(target) {
		case 0:
			break
		}
		target = strings.TrimPrefix(target, "/")
	}
	http.Redirect(w, r, target, 302)`,
			expectedFindings: 0,
		},
		{
			journeyName: "break bound to the trim loop leaves the prefix intact",
			handlerBody: `target := r.FormValue("next")
	for strings.HasPrefix(target, "//") {
		if len(target) > 100 {
			break
		}
		target = strings.TrimPrefix(target, "/")
	}
	http.Redirect(w, r, target, 302)`,
			expectedFindings: 1,
		},
		{
			journeyName: "labelled break escapes from a nested loop",
			handlerBody: `target := r.FormValue("next")
outer:
	for strings.HasPrefix(target, "//") {
		for range target {
			break outer
		}
		target = strings.TrimPrefix(target, "/")
	}
	http.Redirect(w, r, target, 302)`,
			expectedFindings: 1,
		},
	}

	// Run each spelling against the same open-redirect report rule.
	for _, testCase := range testCases {
		t.Run(testCase.journeyName, func(t *testing.T) {
			unit := parseOne(t, "handler.go", requestURLConstraintSource("redirect", testCase.handlerBody))
			findings := OpenRedirectRule{}.AnalyzeUnit(unit, Context{})
			// A mismatch means the user would see the wrong finding count.
			if len(findings) != testCase.expectedFindings {
				t.Fatalf("findings = %#v, want %d", findings, testCase.expectedFindings)
			}
		})
	}
}

// TestRedirectPrefixSurvivesAppend pins that extending an already-normalised
// redirect target on the right keeps its proof. Caddy's file server writes the
// canonical form - strip every leading slash in a loop, then append the query
// string - and reading that append as invalidation reported correct code.
func TestRedirectPrefixSurvivesAppend(t *testing.T) {
	testCases := []struct {
		journeyName      string
		handlerBody      string
		expectedFindings int
	}{
		{
			journeyName: "query append after slash stripping stays safe",
			handlerBody: `toPath := r.FormValue("next")
	for strings.HasPrefix(toPath, "//") {
		toPath = strings.TrimPrefix(toPath, "/")
	}
	if r.URL.RawQuery != "" {
		toPath += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, toPath, 302)`,
			expectedFindings: 0,
		},
		{
			journeyName: "explicit self-concatenation after stripping stays safe",
			handlerBody: `toPath := r.FormValue("next")
	for strings.HasPrefix(toPath, "//") {
		toPath = strings.TrimPrefix(toPath, "/")
	}
	toPath = toPath + "?utm=1"
	http.Redirect(w, r, toPath, 302)`,
			expectedFindings: 0,
		},
		{
			journeyName: "query append after a committed prefix guard stays safe",
			handlerBody: `toPath := r.FormValue("next")
	if !strings.HasPrefix(toPath, "/account/") {
		return
	}
	toPath += "?utm=1"
	http.Redirect(w, r, toPath, 302)`,
			expectedFindings: 0,
		},
		{
			journeyName: "prepending after stripping puts the prefix back",
			handlerBody: `toPath := r.FormValue("next")
	for strings.HasPrefix(toPath, "//") {
		toPath = strings.TrimPrefix(toPath, "/")
	}
	toPath = "/" + toPath
	http.Redirect(w, r, toPath, 302)`,
			expectedFindings: 1,
		},
		{
			journeyName: "wholesale reassignment after stripping voids the proof",
			handlerBody: `toPath := r.FormValue("next")
	for strings.HasPrefix(toPath, "//") {
		toPath = strings.TrimPrefix(toPath, "/")
	}
	toPath = r.FormValue("other")
	http.Redirect(w, r, toPath, 302)`,
			expectedFindings: 1,
		},
	}

	// Run each spelling against the same open-redirect report rule.
	for _, testCase := range testCases {
		t.Run(testCase.journeyName, func(t *testing.T) {
			unit := parseOne(t, "handler.go", requestURLConstraintSource("redirect", testCase.handlerBody))
			findings := OpenRedirectRule{}.AnalyzeUnit(unit, Context{})
			// A mismatch means the user would see the wrong finding count.
			if len(findings) != testCase.expectedFindings {
				t.Fatalf("findings = %#v, want %d", findings, testCase.expectedFindings)
			}
		})
	}
}
