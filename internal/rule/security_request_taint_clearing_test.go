// Package rule tests when a later write clears a binding's request taint.
package rule

import "testing"

// TestRequestControlledURLTaintClearing pins both directions of the dominance
// rule: a write that must run before the sink clears the taint, while a write
// that may be skipped, keeps the old value, or is undone by a later write does not.
func TestRequestControlledURLTaintClearing(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "dominating overwrite clears the taint",
			code: taintClearingSource(`target = "https://fixed.example.com"
	_, _ = http.Get(target)`),
			want: 0,
		},
		{
			name: "overwrite inside the sink's own branch clears the taint",
			code: taintClearingSource(`if r.Method == "GET" {
		target = "https://fixed.example.com"
		_, _ = http.Get(target)
	}`),
			want: 0,
		},
		{
			name: "overwrite inside the sink's own loop clears the taint",
			code: taintClearingSource(`for i := 0; i < 3; i++ {
		target = "https://fixed.example.com"
		_, _ = http.Get(target)
	}`),
			want: 0,
		},
		{
			name: "overwrite inside the sink's own case clause clears the taint",
			code: taintClearingSource(`switch r.Method {
	case "GET":
		target = "https://fixed.example.com"
		_, _ = http.Get(target)
	}`),
			want: 0,
		},
		{
			name: "overwrite in a branch the sink sits outside of does not clear",
			code: taintClearingSource(`if r.Method == "GET" {
		target = "https://fixed.example.com"
	}
	_, _ = http.Get(target)`),
			want: 1,
		},
		{
			name: "overwrite in the else arm alone does not clear",
			code: taintClearingSource(`if r.Method == "GET" {
		_ = target
	} else {
		target = "https://fixed.example.com"
	}
	_, _ = http.Get(target)`),
			want: 1,
		},
		{
			name: "a later request write undoes the clear",
			code: taintClearingSource(`target = "https://fixed.example.com"
	target = r.FormValue("other")
	_, _ = http.Get(target)`),
			want: 1,
		},
		{
			name: "a conditional request write after the clear undoes it",
			code: taintClearingSource(`target = "https://fixed.example.com"
	if r.Method == "GET" {
		target = r.FormValue("other")
	}
	_, _ = http.Get(target)`),
			want: 1,
		},
		{
			name: "a compound assignment keeps the tainted value",
			code: taintClearingSource(`target += "/suffix"
	_, _ = http.Get(target)`),
			want: 1,
		},
		{
			name: "concatenating the tainted value keeps it",
			code: taintClearingSource(`target = target + "/suffix"
	_, _ = http.Get(target)`),
			want: 1,
		},
		{
			name: "assigning another tainted local keeps the taint",
			code: taintClearingSource(`other := r.FormValue("b")
	target = other
	_, _ = http.Get(target)`),
			want: 1,
		},
		{
			name: "a clear after the sink does not reach back",
			code: taintClearingSource(`_, _ = http.Get(target)
	target = "https://fixed.example.com"
	_ = target`),
			want: 1,
		},
		{
			name: "a goto can skip the clear so the taint stands",
			code: taintClearingSource(`if r.Method == "POST" {
		goto skip
	}
	target = "https://fixed.example.com"
skip:
	_, _ = http.Get(target)`),
			want: 1,
		},
		{
			name: "a closure that rewrites the value defeats the clear",
			code: taintClearingSource(`reset := func() { target = r.FormValue("other") }
	target = "https://fixed.example.com"
	reset()
	_, _ = http.Get(target)`),
			want: 1,
		},
		{
			name: "a deferred closure that rewrites the value defeats the clear",
			code: taintClearingSource(`target = "https://fixed.example.com"
	defer func() { target = r.FormValue("other") }()
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

// TestRequestControlledURLClearBeforeTaint confirms a request write after a clean
// initialiser still taints: the clear has to follow the taint to undo it.
func TestRequestControlledURLClearBeforeTaint(t *testing.T) {
	unit := parseOne(t, "handler.go", `// Package handler is a test package.
package handler

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	target := "https://fixed.example.com"
	target = r.FormValue("url")
	_, _ = http.Get(target)
}
`)
	findings := RequestControlledURLRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want 1", findings)
	}
}

// TestRequestControlledURLClearWithAddressTaken confirms that handing the binding's
// address to a callee defeats the clear: the callee can write request data back
// through the pointer without any assignment this analysis can see.
func TestRequestControlledURLClearWithAddressTaken(t *testing.T) {
	unit := parseOne(t, "handler.go", `// Package handler is a test package.
package handler

import "net/http"

func fill(dst *string, r *http.Request) { *dst = r.FormValue("x") }

func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
	target = "https://fixed.example.com"
	fill(&target, r)
	_, _ = http.Get(target)
}
`)
	findings := RequestControlledURLRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want 1", findings)
	}
}

// taintClearingSource wraps one handler body that starts from a tainted local.
func taintClearingSource(body string) string {
	return `// Package handler is a test package.
package handler

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
	` + body + `
}
`
}
