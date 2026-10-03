// Package analysis tests what users see when they select one Go file for scanning.
// Sibling package files may explain a selected file without adding their findings.
// These tests keep both the extra context and the selected-file boundary visible.
package analysis

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestAnalyzeExplicitFileUsesSiblingPackageContextForDeadCode proves an
// explicit-file scan still gives project rules enough same-package context to
// avoid false positives for declarations used from sibling files.
func TestAnalyzeExplicitFileUsesSiblingPackageContextForDeadCode(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "decl.go", "package svc\n\nfunc helper() string {\n\treturn \"ok\"\n}\n")
	writeFile(t, root, "caller.go", "package svc\n\nfunc Run() string {\n\treturn helper()\n}\n")
	t.Chdir(root)

	report, err := Analyze(Options{
		Paths:    []string{"decl.go"},
		Registry: rule.Defaults(),
		FailOn:   finding.FailThresholdNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if containsRuleID(report.Findings, "dead-code.unused-private-function") {
		t.Fatalf("explicit file scan falsely flagged sibling-used helper: %#v", report.Findings)
	}
}

// TestAnalyzeExplicitFileProvesFixedStoragePrefixes checks the warning users see when they scan only a tidy handler.
// Sibling constants and every closure call must prove a fixed storage-list prefix; an unsafe change keeps the warning.
func TestAnalyzeExplicitFileProvesFixedStoragePrefixes(t *testing.T) {
	const handler = `package svc

import (
	"net/http"
	"os"
)

type storage interface { List(string, string) ([]string, error) }
type logger struct{}
func (logger) Trace(string, ...any) {}

func tidy(s storage, logger logger, request *http.Request, secretOTP string) {
	capturedRequest := request
	_ = capturedRequest
	tidyFunc := func(secretIDPrefixToUse string, request *http.Request) error {
		logger.Trace("listing role HMACs", "prefix", secretIDPrefixToUse)
		_, err := s.List("ctx", secretIDPrefixToUse)
		return err
	}
	if request != nil {
		_ = tidyFunc(secretIDLocalPrefix, request)
	} else {
		_ = tidyFunc(secretIDPrefix, request)
		_ = tidyFunc(secretIDLocalPrefix, request)
	}
}
`
	const sibling = `package svc

const (
	secretIDPrefix = "secret_id/"
	secretIDLocalPrefix = "secret_id_local/"
)
`
	tests := []struct {
		name           string
		oldHandler     string
		newHandler     string
		oldSibling     string
		newSibling     string
		siblingPath    string
		withoutSibling bool
		wantWarnings   int
	}{
		{name: "fixed package constants", wantWarnings: 0},
		{name: "secret-derived prefix slice", oldHandler: "tidyFunc(secretIDPrefix, request)",
			newHandler: "tidyFunc(secretOTP[:4], request)", wantWarnings: 1},
		{name: "changed constant value", oldSibling: `"secret_id/"`, newSibling: `"private/"`, wantWarnings: 1},
		{name: "mutable sibling prefix", oldSibling: "const (", newSibling: "var (", wantWarnings: 1},
		{name: "test-only sibling", siblingPath: "backend_test.go", wantWarnings: 1},
		{name: "missing sibling", withoutSibling: true, wantWarnings: 1},
		{name: "closure alias", oldHandler: "if request != nil {", newHandler: `alias := tidyFunc
	_ = alias
	if request != nil {`, wantWarnings: 1},
		{name: "local prefix shadow", oldHandler: "if request != nil {", newHandler: `secretIDPrefix := secretOTP
	if request != nil {`, wantWarnings: 1},
		{name: "prefix reassignment", oldHandler: `logger.Trace("listing role HMACs"`, newHandler: `secretIDPrefixToUse = secretOTP
		logger.Trace("listing role HMACs"`, wantWarnings: 1},
		{name: "different storage list", oldHandler: `s.List("ctx", secretIDPrefixToUse)`,
			newHandler: `s.List("ctx", secretIDLocalPrefix)`, wantWarnings: 1},
		{name: "request credential beside prefix", oldHandler: `"prefix", secretIDPrefixToUse)`,
			newHandler: `"prefix", secretIDPrefixToUse, "auth", request.Header.Get("Authorization"))`, wantWarnings: 1},
		{name: "captured request credential beside prefix", oldHandler: `"prefix", secretIDPrefixToUse)`,
			newHandler: `"prefix", secretIDPrefixToUse, "auth", capturedRequest.Header.Get("Authorization"))`, wantWarnings: 1},
		{name: "captured request credential through a local value", oldHandler: `capturedRequest := request
	_ = capturedRequest
	tidyFunc := func(secretIDPrefixToUse string, request *http.Request) error {
		logger.Trace("listing role HMACs", "prefix", secretIDPrefixToUse)`,
			newHandler: `capturedRequest := request
	var capturedAuthValue string
	// A request may bring an authorization header into the outer handler.
	if capturedRequest != nil {
		capturedAuthValue = capturedRequest.Header.Get("Authorization")
	}
	tidyFunc := func(secretIDPrefixToUse string, request *http.Request) error {
		logger.Trace("listing role HMACs", "prefix", secretIDPrefixToUse, "auth", capturedAuthValue)`, wantWarnings: 1},
		{name: "environment credential beside prefix", oldHandler: `"prefix", secretIDPrefixToUse)`,
			newHandler: `"prefix", secretIDPrefixToUse, "password", os.Getenv("API_SECRET"))`, wantWarnings: 1},
	}
	// Each subtest models one edit to the handler or its sibling before an explicit-file scan.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			handlerSource := handler
			siblingSource := sibling
			// A replacement must change exactly the intended source occurrence or the control cannot prove its claim.
			if test.oldHandler != "" {
				if strings.Count(handlerSource, test.oldHandler) != 1 {
					t.Fatalf("handler mutation anchor %q must occur once", test.oldHandler)
				}
				handlerSource = strings.Replace(handlerSource, test.oldHandler, test.newHandler, 1)
			}
			// A changed package constant can no longer certify a storage prefix.
			if test.oldSibling != "" {
				if strings.Count(siblingSource, test.oldSibling) != 1 {
					t.Fatalf("sibling mutation anchor %q must occur once", test.oldSibling)
				}
				siblingSource = strings.Replace(siblingSource, test.oldSibling, test.newSibling, 1)
			}
			writeFile(t, root, "handler.go", handlerSource)
			// An explicit-file scan should load the sibling when it exists and retain a warning when it does not.
			if !test.withoutSibling {
				siblingPath := test.siblingPath
				// The default path models the observed production sibling; a test-only file cannot certify it.
				if siblingPath == "" {
					siblingPath = "backend.go"
				}
				writeFile(t, root, siblingPath, siblingSource)
			}
			t.Chdir(root)
			report, err := Analyze(Options{Paths: []string{"handler.go"}, Registry: rule.Defaults(), FailOn: finding.FailThresholdNone})
			if err != nil {
				t.Fatal(err)
			}
			// A parse failure cannot count as safely suppressing or retaining the user's warning.
			for _, diagnostic := range report.Diagnostics {
				if diagnostic.Stage == "parse" {
					t.Fatalf("source failed to parse: %#v", report.Diagnostics)
				}
			}
			warnings := 0
			// Only the logging rule's result answers whether the user's prefix warning was retained.
			for _, item := range report.Findings {
				if item.RuleID == "security.sensitive-data-logging" {
					warnings++
				}
			}
			if warnings != test.wantWarnings {
				t.Fatalf("logging warnings = %d, want %d: %#v", warnings, test.wantWarnings, report.Findings)
			}
		})
	}
}

// TestAnalyzeExplicitFileUsesSiblingPackageCommentContext proves package-level
// doc rules can see comments carried by a sibling package file.
func TestAnalyzeExplicitFileUsesSiblingPackageCommentContext(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "doc.go", "// Package svc explains the package.\npackage svc\n")
	writeFile(t, root, "impl.go", "package svc\n\nfunc Run() {}\n")
	t.Chdir(root)

	report, err := Analyze(Options{
		Paths:    []string{"impl.go"},
		Registry: rule.Defaults(),
		FailOn:   finding.FailThresholdNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if containsRuleID(report.Findings, "docs.package-comment") {
		t.Fatalf("explicit file scan missed sibling package doc: %#v", report.Findings)
	}
}

// TestAnalyzeExplicitFileSurfacesSiblingParseFailure proves a sibling pulled in
// only for package context still reports its parse failure. Otherwise a project
// rule can lose context and false-positive on the scanned file with no
// diagnostic explaining why.
func TestAnalyzeExplicitFileSurfacesSiblingParseFailure(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "caller.go", "package svc\n\nfunc Run() string {\n\treturn helper()\n}\n")
	writeFile(t, root, "broken.go", "package svc\n\nfunc helper() string {\n\treturn\n") // unterminated: fails to parse
	t.Chdir(root)

	report, err := Analyze(Options{
		Paths:    []string{"caller.go"},
		Registry: rule.Defaults(),
		FailOn:   finding.FailThresholdNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, diag := range report.Diagnostics {
		if diag.File == "broken.go" && diag.Stage == "parse" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a parse diagnostic for context-only sibling broken.go, got %#v", report.Diagnostics)
	}
}

// TestAnalyzeExplicitFileHidesContextOnlyFindings proves sibling package files
// are context for project rules, not additional report targets.
func TestAnalyzeExplicitFileHidesContextOnlyFindings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "impl.go", "// Package svc explains the package.\npackage svc\n\nfunc Run() {}\n")
	writeFile(t, root, "sibling.go", "package svc\n\nimport \"os/exec\"\n\nfunc Dangerous() {\n\t_ = exec.Command(\"sh\", \"-c\", \"echo hi\")\n}\n")
	t.Chdir(root)

	report, err := Analyze(Options{
		Paths:    []string{"impl.go"},
		Registry: rule.Defaults(),
		FailOn:   finding.FailThresholdNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range report.Findings {
		if item.File == "sibling.go" {
			t.Fatalf("context-only sibling produced finding: %#v", report.Findings)
		}
	}
}

// TestAnalyzeExplicitFileStillReportsMissingPackageComment proves a genuine
// package-level violation is reported (re-anchored to the requested file) even
// when the lexicographically-first file in the package is a context-only
// sibling, so the explicit-file context feature does not hide it.
func TestAnalyzeExplicitFileStillReportsMissingPackageComment(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "aaa.go", "package svc\n\nfunc Helper() {}\n")
	writeFile(t, root, "zzz.go", "package svc\n\nfunc Run() {}\n")
	t.Chdir(root)

	report, err := Analyze(Options{
		Paths:    []string{"zzz.go"},
		Registry: rule.Defaults(),
		FailOn:   finding.FailThresholdNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range report.Findings {
		if item.RuleID != "docs.package-comment" {
			continue
		}
		found = true
		if item.File != "zzz.go" {
			t.Fatalf("package-comment finding should anchor to the requested file zzz.go, got %q", item.File)
		}
	}
	if !found {
		t.Fatalf("explicit scan of zzz.go should still report the package's missing comment, got %#v", report.Findings)
	}
}
