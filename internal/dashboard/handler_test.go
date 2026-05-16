package dashboard

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
	writeFile(t, filepath.Join(project, ".gruff.json"), `{
  "rules": {
    "size.file-length": {
      "thresholds": {"maxLines": 1}
    }
  }
}`)
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
		t.Fatalf("findings missing size.file-length from project .gruff.json: %#v", reportData.Findings)
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
		ConfigPath:   ".gruff.yaml",
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
		Project:    "/repo",
		Paths:      "src,internal",
		Config:     ".gruff.yaml",
		Baseline:   "baseline.json",
		FailOn:     "high",
		ScanScope:  "diff",
		NoBaseline: "",
	})
	for _, fragment := range []string{
		"gruff-go analyse --format html",
		"--config .gruff.yaml",
		"--baseline baseline.json",
		"--diff-base HEAD",
		"--min-severity high",
		"src",
		"internal",
	} {
		if !strings.Contains(command, fragment) {
			t.Errorf("displayCommand missing %q in %q", fragment, command)
		}
	}
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
