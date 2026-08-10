// Package rule pins request-URL regressions reproduced from PR review feedback.
package rule

import (
	goparser "go/parser"
	"testing"
)

// TestRequestURLReviewRegressions keeps unsafe values visible until validation
// is tied to the value and control-flow path that actually reaches the sink.
func TestRequestURLReviewRegressions(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{
			name: "conjunctive rejecting guard is not an allowlist",
			body: `target := r.FormValue("url")
	parsed, _ := url.Parse(target)
	if parsed.Scheme != "https" && parsed.Hostname() != "api.internal" {
		return
	}
	_, _ = http.Get(target)`,
		},
		{
			name: "validation before tainted reassignment does not protect sink",
			body: `target := "https://api.internal"
	parsed, _ := url.Parse(target)
	if parsed.Scheme != "https" || parsed.Hostname() != "api.internal" {
		return
	}
	target = r.FormValue("url")
	_, _ = http.Get(target)`,
		},
		{
			name: "ignored validator result is not protection",
			body: `target := r.FormValue("url")
	_ = validatedDestination(target)
	_, _ = http.Get(target)`,
		},
		{
			name: "inverted validator guard is not protection",
			body: `target := r.FormValue("url")
	if validatedDestination(target) {
		return
	}
	_, _ = http.Get(target)`,
		},
		{
			name: "parsed String local remains tainted",
			body: `parsed, _ := url.Parse(r.FormValue("url"))
	target := parsed.String()
	_, _ = http.Get(target)`,
		},
		{
			name: "parsed allowlist becomes stale after parsed result reassignment",
			body: `target := r.FormValue("url")
	parsed, _ := url.Parse(target)
	parsed, _ = url.Parse("https://api.internal")
	if parsed.Scheme != "https" || parsed.Hostname() != "api.internal" {
		return
	}
	_, _ = http.Get(target)`,
		},
		{
			name: "validator inside optional branch does not protect later sink",
			body: `target := r.FormValue("url")
	if r.Method == "POST" {
		if !validatedDestination(target) {
			return
		}
	}
	_, _ = http.Get(target)`,
		},
		{
			name: "mixed sanitizer result and raw value still flags",
			body: `target := r.FormValue("url")
	_, _ = http.Get(sanitizedURL(target) + target)`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			unit := parseOne(t, "handler.go", requestURLConstraintSource("fetch", testCase.body))
			findings := (RequestControlledURLRule{}).AnalyzeUnit(unit, Context{})
			if len(findings) != 1 {
				t.Fatalf("findings = %#v, want one SSRF finding", findings)
			}
		})
	}
}

// TestRequestURLNestedValidatorProtectsSinkInSameBranch preserves the safe
// nested form where every path to the sink passes through the validator.
func TestRequestURLNestedValidatorProtectsSinkInSameBranch(t *testing.T) {
	body := `target := r.FormValue("url")
	if r.Method == "POST" {
		if !validatedDestination(target) {
			return
		}
		_, _ = http.Get(target)
	}`
	unit := parseOne(t, "handler.go", requestURLConstraintSource("fetch", body))
	findings := (RequestControlledURLRule{}).AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want no SSRF finding", findings)
	}
}

// TestRequestURLParsedAllowlistSurvivesLaterHelperReuse keeps valid evidence
// when only the parsed helper local changes after it has constrained the sink value.
func TestRequestURLParsedAllowlistSurvivesLaterHelperReuse(t *testing.T) {
	body := `target := r.FormValue("url")
	parsed, _ := url.Parse(target)
	if parsed.Scheme != "https" || parsed.Hostname() != "api.internal" {
		return
	}
	parsed, _ = url.Parse("https://audit.internal")
	_ = parsed
	_, _ = http.Get(target)`
	unit := parseOne(t, "handler.go", requestURLConstraintSource("fetch", body))
	findings := (RequestControlledURLRule{}).AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want no SSRF finding", findings)
	}
}

// TestRequestURLAcceptsWholeInlineSanitizerResult preserves the affirmative
// direct-wrapper shape while mixed expressions remain visible above.
func TestRequestURLAcceptsWholeInlineSanitizerResult(t *testing.T) {
	body := `_, _ = http.Get(sanitizedURL(r.FormValue("url")))`
	unit := parseOne(t, "handler.go", requestURLConstraintSource("fetch", body))
	findings := (RequestControlledURLRule{}).AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want no SSRF finding", findings)
	}
}

// TestRequestURLRecognizesTypedHTTPClient covers usable value declarations
// while keeping an unusable nil pointer out of the outbound-sink set.
func TestRequestURLRecognizesTypedHTTPClient(t *testing.T) {
	testCases := []struct {
		name string
		body string
		want int
	}{
		{
			name: "zero value client",
			body: "var client http.Client",
			want: 1,
		},
		{
			name: "typed factory result",
			body: "var client http.Client = newClient()",
			want: 1,
		},
		{
			name: "nil pointer client",
			body: "var client *http.Client",
			want: 0,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			unit := parseOne(t, "handler.go", `package handler

import "net/http"

func newClient() http.Client { return http.Client{} }

func fetch(w http.ResponseWriter, r *http.Request) {
	`+testCase.body+`
	_, _ = client.Get(r.FormValue("url"))
}
`)
			findings := (RequestControlledURLRule{}).AnalyzeUnit(unit, Context{})
			if len(findings) != testCase.want {
				t.Fatalf("findings = %#v, want %d SSRF findings", findings, testCase.want)
			}
		})
	}
}

// TestRequestURLHTTPClientBindingRespectsLexicalScope keeps an inner custom
// client out of the net/http sink set without losing the outer HTTP client.
func TestRequestURLHTTPClientBindingRespectsLexicalScope(t *testing.T) {
	unit := parseOne(t, "handler.go", `package handler

import "net/http"

type localClient struct{}

func (localClient) Get(string) (*http.Response, error) { return nil, nil }

func fetch(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{}
	if r.Method == "POST" {
		client := localClient{}
		_, _ = client.Get(r.FormValue("inner"))
	}
	_, _ = client.Get(r.FormValue("outer"))
}
`)
	findings := (RequestControlledURLRule{}).AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want only the outer HTTP-client finding", findings)
	}
}

// TestAssignedRootNameFindsTheWrittenValue pins which identifier a guard-
// invalidating write is attributed to. The discriminating case is the index
// expression: `cache[target] = value` writes cache and leaves target's guard
// evidence intact, so rooting at the subscript instead would invalidate guards
// that nothing overwrote.
func TestAssignedRootNameFindsTheWrittenValue(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{target: "parsed", want: "parsed"},
		{target: "parsed.Host", want: "parsed"},
		{target: "parsed.URL.Host", want: "parsed"},
		{target: "targets[0]", want: "targets"},
		{target: "cache[target]", want: "cache"},
		{target: "*parsed", want: "parsed"},
		{target: "(parsed).Host", want: "parsed"},
		{target: "url.Parse(x).Host", want: ""},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			expression, err := goparser.ParseExpr(test.target)
			if err != nil {
				t.Fatalf("parse %q: %v", test.target, err)
			}
			rootName, hasRoot := assignedRootName(expression)
			if !hasRoot {
				rootName = ""
			}
			if rootName != test.want {
				t.Fatalf("assignedRootName(%q) = %q, want %q", test.target, rootName, test.want)
			}
		})
	}
}

// TestOpenRedirectReviewRegressions rejects incomplete slash normalization and
// requires a redirect status before treating a Location header as a browser sink.
func TestOpenRedirectReviewRegressions(t *testing.T) {
	t.Run("normalization loop can exit early", func(t *testing.T) {
		body := `target := r.FormValue("next")
	for strings.HasPrefix(target, "//") {
		if r.Method == "GET" {
			break
		}
		target = strings.TrimPrefix(target, "/")
	}
	http.Redirect(w, r, target, http.StatusFound)`
		unit := parseOne(t, "handler.go", requestURLConstraintSource("redirect", body))
		findings := (OpenRedirectRule{}).AnalyzeUnit(unit, Context{})
		if len(findings) != 1 {
			t.Fatalf("findings = %#v, want one open-redirect finding", findings)
		}
	})

	t.Run("normalization loop can skip the trim with a labelled continue", func(t *testing.T) {
		body := `target := r.FormValue("next")
outer:
	for attempt := 0; attempt < 2; attempt++ {
		for strings.HasPrefix(target, "//") {
			if r.Method == "GET" {
				continue outer
			}
			target = strings.TrimPrefix(target, "/")
		}
	}
	http.Redirect(w, r, target, http.StatusFound)`
		unit := parseOne(t, "handler.go", requestURLConstraintSource("redirect", body))
		findings := (OpenRedirectRule{}).AnalyzeUnit(unit, Context{})
		if len(findings) != 1 {
			t.Fatalf("findings = %#v, want one open-redirect finding", findings)
		}
	})

	t.Run("normalization loop with an unlabelled continue stays affirmative", func(t *testing.T) {
		body := `target := r.FormValue("next")
	for strings.HasPrefix(target, "//") {
		if r.Method == "GET" {
			continue
		}
		target = strings.TrimPrefix(target, "/")
	}
	http.Redirect(w, r, target, http.StatusFound)`
		unit := parseOne(t, "handler.go", requestURLConstraintSource("redirect", body))
		findings := (OpenRedirectRule{}).AnalyzeUnit(unit, Context{})
		if len(findings) != 0 {
			t.Fatalf("findings = %#v, want no open-redirect finding; an unlabelled continue re-tests the loop condition", findings)
		}
	})

	t.Run("committed prefix guard becomes stale after reassignment", func(t *testing.T) {
		body := `target := r.FormValue("next")
	if !strings.HasPrefix(target, "/account/") {
		return
	}
	target = r.FormValue("fallback")
	http.Redirect(w, r, target, http.StatusFound)`
		unit := parseOne(t, "handler.go", requestURLConstraintSource("redirect", body))
		findings := (OpenRedirectRule{}).AnalyzeUnit(unit, Context{})
		if len(findings) != 1 {
			t.Fatalf("findings = %#v, want one open-redirect finding", findings)
		}
	})

	t.Run("normalization loop becomes stale after reassignment", func(t *testing.T) {
		body := `target := r.FormValue("next")
	for strings.HasPrefix(target, "//") {
		target = strings.TrimPrefix(target, "/")
	}
	target = r.FormValue("fallback")
	http.Redirect(w, r, target, http.StatusFound)`
		unit := parseOne(t, "handler.go", requestURLConstraintSource("redirect", body))
		findings := (OpenRedirectRule{}).AnalyzeUnit(unit, Context{})
		if len(findings) != 1 {
			t.Fatalf("findings = %#v, want one open-redirect finding", findings)
		}
	})

	t.Run("Location header with OK response is not a redirect", func(t *testing.T) {
		unit := parseOne(t, "handler.go", `package handler

import "net/http"

func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", r.FormValue("next"))
	w.WriteHeader(http.StatusOK)
}
`)
		findings := (OpenRedirectRule{}).AnalyzeUnit(unit, Context{})
		if len(findings) != 0 {
			t.Fatalf("findings = %#v, want no open-redirect finding", findings)
		}
	})

	t.Run("Location header and redirect status in exclusive branches", func(t *testing.T) {
		unit := parseOne(t, "handler.go", `package handler

import "net/http"

func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Location", r.FormValue("next"))
	} else {
		w.WriteHeader(http.StatusFound)
	}
}
`)
		findings := (OpenRedirectRule{}).AnalyzeUnit(unit, Context{})
		if len(findings) != 0 {
			t.Fatalf("findings = %#v, want no open-redirect finding", findings)
		}
	})

	t.Run("Location header and redirect status in same branch", func(t *testing.T) {
		unit := parseOne(t, "handler.go", `package handler

import "net/http"

func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Location", r.FormValue("next"))
		w.WriteHeader(http.StatusFound)
	}
}
`)
		findings := (OpenRedirectRule{}).AnalyzeUnit(unit, Context{})
		if len(findings) != 1 {
			t.Fatalf("findings = %#v, want one open-redirect finding", findings)
		}
	})
}
