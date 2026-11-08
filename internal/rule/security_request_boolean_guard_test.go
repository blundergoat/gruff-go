// Package rule tests explicit-boolean validator guards on request-driven URLs.
//
// A handler that guards http.Get by comparing a validator result with true or false gets no request-controlled URL finding.
// A comparison against a variable, or a guard through a local named true, proves nothing and still gets one.
package rule

import "testing"

// TestRequestControlledURLBooleanComparisonGuards pins that comparing a validator result with a boolean literal guards the sink as negation does.
// A comparison that proves nothing still reports; a failure means a guarded fetch was flagged or an unproven one went unreported.
func TestRequestControlledURLBooleanComparisonGuards(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "equals false rejects then fetches",
			code: booleanGuardSource(`if validateURL(target) == false {
		return
	}
	_, _ = http.Get(target)`),
			want: 0,
		},
		{
			name: "equals true fetches inside the guarded branch",
			code: booleanGuardSource(`if validateURL(target) == true {
		_, _ = http.Get(target)
	}`),
			want: 0,
		},
		{
			name: "not equal true rejects then fetches",
			code: booleanGuardSource(`if validateURL(target) != true {
		return
	}
	_, _ = http.Get(target)`),
			want: 0,
		},
		{
			name: "not equal false fetches inside the guarded branch",
			code: booleanGuardSource(`if validateURL(target) != false {
		_, _ = http.Get(target)
	}`),
			want: 0,
		},
		{
			name: "parenthesised comparison still guards",
			code: booleanGuardSource(`if (validateURL(target)) == (false) {
		return
	}
	_, _ = http.Get(target)`),
			want: 0,
		},
		{
			name: "literal on the left still guards",
			code: booleanGuardSource(`if false == validateURL(target) {
		return
	}
	_, _ = http.Get(target)`),
			want: 0,
		},
		{
			name: "comparison against a variable proves nothing",
			code: booleanGuardSource(`allowed := target != ""
	if validateURL(target) == allowed {
		return
	}
	_, _ = http.Get(target)`),
			want: 1,
		},
		{
			name: "shadowed true is not the predeclared constant",
			code: booleanGuardSource(`true := validateURL(target) == false
	if true {
		return
	}
	_, _ = http.Get(target)`),
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "handler.go", tt.code)
			findings := RequestControlledURLRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}

// booleanGuardSource wraps a handler body with a request-derived target and a stub boolean validator; the body supplies the guard and the fetch.
// It returns the full Go source of package handler, with body inserted verbatim into fetch after target is read from the url form value.
func booleanGuardSource(body string) string {
	return `// Package handler is a test package.
package handler

import "net/http"

func validateURL(raw string) bool { return raw != "" }

func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
	` + body + `
}
`
}
