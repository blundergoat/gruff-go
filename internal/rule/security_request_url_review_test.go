// Package rule pins request-URL regressions reproduced from PR review feedback.
package rule

import "testing"

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
}
