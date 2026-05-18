package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
)

func TestHandlerServesShellOnRoot(t *testing.T) {
	handler := NewHandler(Options{ProjectRoot: "/tmp/proj"})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if contentType := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("Content-Type = %q", contentType)
	}
	body, _ := io.ReadAll(resp.Body)
	for _, fragment := range []string{
		`<title>gruff-go dashboard</title>`,
		`id="controls-toggle"`,
		`id="controls-panel"`,
		`id="report-frame"`,
		`<form id="scan-form"`,
	} {
		if !strings.Contains(string(body), fragment) {
			t.Errorf("shell missing fragment %q", fragment)
		}
	}
}

func TestHandlerScanRendersReportWithMetadata(t *testing.T) {
	tempDir := t.TempDir()
	handler := NewHandler(Options{ProjectRoot: tempDir, FailOn: "medium"})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/scan?project=" + tempDir + "&paths=&scanScope=full&failOn=medium")
	if err != nil {
		t.Fatalf("GET /scan: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Errorf("scan response is not HTML; body: %s", html)
	}
	if !strings.Contains(html, `id="gruff-dashboard-meta"`) {
		t.Error("scan response should include postMessage metadata script")
	}
	if !strings.Contains(html, `"type":"gruff-scan-complete"`) {
		t.Error("scan response metadata should declare gruff-scan-complete")
	}
}

func TestHandlerScanMetadataCommandIncludesParityFlags(t *testing.T) {
	project := t.TempDir()
	writeFile(t, filepath.Join(project, ".gitignore"), "ignored/\n")
	writeFile(t, filepath.Join(project, "ignored", "complex.go"), dashboardComplexFixture())

	handler := NewHandler(Options{ProjectRoot: project, FailOn: "medium"})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	query := url.Values{
		"project":           {project},
		"paths":             {"ignored/complex.go"},
		"scanScope":         {"full"},
		"failOn":            {"medium"},
		"includeIgnored":    {"1"},
		"reportInteractive": {"1"},
	}

	resp, err := http.Get(server.URL + "/scan?" + query.Encode())
	if err != nil {
		t.Fatalf("GET /scan: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if !strings.Contains(html, "complexity.cyclomatic") {
		t.Fatalf("scan should include ignored fixture finding; body:\n%s", html)
	}
	metadata := extractScanMetadata(t, html)
	if metadata.ExitCode != 1 {
		t.Fatalf("metadata exitCode = %d, want 1", metadata.ExitCode)
	}
	wantCommand := "gruff-go analyse --format html --report-interactive --include-ignored --min-severity medium ignored/complex.go"
	if metadata.Command != wantCommand {
		t.Fatalf("metadata command = %q, want %q", metadata.Command, wantCommand)
	}
}

func TestRunScanUsesProjectRootConfigWithoutChangingWorkingDirectory(t *testing.T) {
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	project := t.TempDir()
	writeFile(t, filepath.Join(project, ".gruff-go.yaml"), `
rules:
  size.file-length:
    thresholds:
      maxLines: 1
`)
	writeFile(t, filepath.Join(project, "short.go"), "package sample\n\nfunc ok() {}\n")

	reportData, err := runScan(context.Background(), scanRunOptions{
		projectRoot: project,
		paths:       []string{"."},
		failOn:      "medium",
	})
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if got, err := os.Getwd(); err != nil || got != originalWD {
		t.Fatalf("cwd after runScan = %q, %v; want %q", got, err, originalWD)
	}
	if !hasFinding(reportData.Findings, "size.file-length") {
		t.Fatalf("findings missing size.file-length from project .gruff-go.yaml: %#v", reportData.Findings)
	}
	if reportData.Run.WorkingDirectory != filepath.ToSlash(project) {
		t.Fatalf("report root = %q, want %q", reportData.Run.WorkingDirectory, filepath.ToSlash(project))
	}
}

func hasFinding(findings []finding.Finding, ruleID string) bool {
	for _, item := range findings {
		if item.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestRunScanRespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := runScan(ctx, scanRunOptions{
		projectRoot: t.TempDir(),
		failOn:      "medium",
	})
	if err == nil {
		t.Fatal("expected runScan to return context cancellation")
	}
	if err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestHandlerScanReturnsErrorDocOnInvalidProject(t *testing.T) {
	handler := NewHandler(Options{})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/scan?project=/nonexistent/path/to/project")
	if err != nil {
		t.Fatalf("GET /scan: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if !strings.Contains(html, "Scan failed") {
		t.Errorf("invalid project should produce error doc; got: %s", html)
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func TestHandlerRejectsPostOnRoot(t *testing.T) {
	handler := NewHandler(Options{})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	resp, err := http.Post(server.URL+"/", "text/plain", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestHandlerUnknownPathIs404(t *testing.T) {
	handler := NewHandler(Options{})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/unknown")
	if err != nil {
		t.Fatalf("GET /unknown: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestStateFromQueryAppliesDefaults(t *testing.T) {
	opts := Options{
		ProjectRoot:  "/repo",
		Paths:        []string{"internal"},
		ConfigPath:   ".gruff-go.yaml",
		BaselinePath: "baseline.json",
		FailOn:       "high",
	}
	values := map[string][]string{}
	state := stateFromQuery(opts, values)
	if state.Project != "/repo" {
		t.Errorf("project = %q, want /repo", state.Project)
	}
	if state.Paths != "internal" {
		t.Errorf("paths = %q, want internal", state.Paths)
	}
	if state.FailOn != "high" {
		t.Errorf("failOn = %q, want high", state.FailOn)
	}
}

func TestStateFromQueryOverridesDefaults(t *testing.T) {
	opts := Options{ProjectRoot: "/repo", FailOn: "high"}
	values := map[string][]string{
		"project":           {"/elsewhere"},
		"failOn":            {"critical"},
		"reportInteractive": {"1"},
	}
	state := stateFromQuery(opts, values)
	if state.Project != "/elsewhere" {
		t.Errorf("project override failed: %q", state.Project)
	}
	if state.FailOn != "critical" {
		t.Errorf("failOn override failed: %q", state.FailOn)
	}
	if state.ReportInteractive != "1" {
		t.Errorf("reportInteractive should be 1, got %q", state.ReportInteractive)
	}
}

func TestBuildScanOptionsIncludeIgnoredFromQuery(t *testing.T) {
	state := report.DashboardState{
		Project:        "/repo",
		FailOn:         "medium",
		IncludeIgnored: "1",
	}
	scan := buildScanOptions(Options{}, state)
	if !scan.includeIgnored {
		t.Fatalf("includeIgnored should be true when query/state sets it")
	}
}

func TestBuildScanOptionsIncludeIgnoredFromOptionsDefault(t *testing.T) {
	state := report.DashboardState{Project: "/repo", FailOn: "medium"}
	scan := buildScanOptions(Options{IncludeIgnored: true}, state)
	if !scan.includeIgnored {
		t.Fatalf("includeIgnored should be true when Options.IncludeIgnored is true and state is unset")
	}
}

func TestStateFromQueryIncludeIgnoredOverride(t *testing.T) {
	values := map[string][]string{"includeIgnored": {"1"}}
	state := stateFromQuery(Options{}, values)
	if state.IncludeIgnored != "1" {
		t.Fatalf("includeIgnored=1 query should round-trip, got %q", state.IncludeIgnored)
	}
}

func TestDisplayCommandIncludesKeyFlags(t *testing.T) {
	command := displayCommand(report.DashboardState{
		Project:           "/repo",
		Paths:             "src,internal",
		Config:            ".gruff-go.yaml",
		Baseline:          "baseline.json",
		FailOn:            "high",
		ScanScope:         "diff",
		SkipBaseline:      "",
		IncludeIgnored:    "1",
		ReportInteractive: "1",
	}, Options{EditorLink: "vscode"})
	for _, fragment := range []string{
		"gruff-go analyse --format html",
		"--report-interactive",
		"--report-editor-link vscode",
		"--config .gruff-go.yaml",
		"--baseline baseline.json",
		"--diff-base HEAD",
		"--include-ignored",
		"--min-severity high",
		"src",
		"internal",
	} {
		if !strings.Contains(command, fragment) {
			t.Errorf("displayCommand missing %q in %q", fragment, command)
		}
	}
}

func extractScanMetadata(t *testing.T, html string) struct {
	Type     string `json:"type"`
	ExitCode int    `json:"exitCode"`
	Command  string `json:"command"`
} {
	t.Helper()
	startMarker := `<script id="gruff-dashboard-meta" type="application/json">`
	start := strings.Index(html, startMarker)
	if start < 0 {
		t.Fatalf("metadata script missing from HTML:\n%s", html)
	}
	start += len(startMarker)
	end := strings.Index(html[start:], `</script>`)
	if end < 0 {
		t.Fatalf("metadata script is not closed:\n%s", html)
	}
	var payload struct {
		Type     string `json:"type"`
		ExitCode int    `json:"exitCode"`
		Command  string `json:"command"`
	}
	if err := json.Unmarshal([]byte(html[start:start+end]), &payload); err != nil {
		t.Fatalf("metadata JSON: %v", err)
	}
	if payload.Type != "gruff-scan-complete" {
		t.Fatalf("metadata type = %q, want gruff-scan-complete", payload.Type)
	}
	return payload
}

func dashboardComplexFixture() string {
	return "// Package sample is a test package.\npackage sample\n\nfunc risky(a bool) {\n" +
		strings.Repeat("\tif a {}\n", 21) +
		"}\n"
}

func TestSplitPaths(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{"  a , b  , c ", []string{"a", "b", "c"}},
		{",,a,,", []string{"a"}},
	}
	for _, tc := range cases {
		got := splitPaths(tc.input)
		if !equalSlices(got, tc.want) {
			t.Errorf("splitPaths(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
