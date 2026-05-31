// Package rule tests the parser-only GitHub Actions workflow security rules.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// workflowUnit builds a text unit located under .github/workflows for rule tests.
func workflowUnit(name, src string) parser.Unit {
	return parser.Unit{
		File:   source.File{Path: ".github/workflows/" + name, Type: source.FileTypeText},
		Source: src,
	}
}

// TestGitHubActionsUnpinnedActionRule covers mutable third-party refs and the
// first-party, tag, SHA, and local cases that must not fire.
func TestGitHubActionsUnpinnedActionRule(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want int
	}{
		{name: "third-party mutable branch", src: "jobs:\n  x:\n    steps:\n      - uses: somevendor/action@main\n", want: 1},
		{name: "third-party master", src: "      - uses: somevendor/action@master\n", want: 1},
		{name: "third-party tag pin", src: "      - uses: somevendor/action@v2\n", want: 0},
		{name: "third-party sha pin", src: "      - uses: somevendor/action@49933ea5288caeca8642d1e84afbd3f7d6820020\n", want: 0},
		{name: "first-party branch exempt", src: "      - uses: actions/checkout@main\n", want: 0},
		{name: "first-party tag", src: "      - uses: actions/setup-go@v5\n", want: 0},
		{name: "local action", src: "      - uses: ./.github/actions/local\n", want: 0},
		{name: "docker action", src: "      - uses: docker://alpine:3\n", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GitHubActionsUnpinnedActionRule{}.AnalyzeUnit(workflowUnit("ci.yml", tt.src), Context{})
			if len(got) != tt.want {
				t.Fatalf("findings = %#v, want %d", got, tt.want)
			}
		})
	}
}

// TestGitHubActionsRemoteShellRule covers download-pipe-to-shell steps and safe
// install commands.
func TestGitHubActionsRemoteShellRule(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want int
	}{
		{name: "curl pipe bash", src: "      - run: curl -sSL https://example.com/i.sh | bash\n", want: 1},
		{name: "wget pipe sh", src: "      - run: wget -qO- https://example.com/i | sh\n", want: 1},
		{name: "process substitution", src: "      - run: bash <(curl -s https://example.com/i)\n", want: 1},
		{name: "go install is safe", src: "      - run: go install golang.org/x/vuln/cmd/govulncheck@latest\n", want: 0},
		{name: "apt install is safe", src: "      - run: sudo apt-get install -y shellcheck\n", want: 0},
		{name: "curl pipe bash in comment is ignored", src: "# install docs: curl https://example.com | bash\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n", want: 0},
		{name: "curl pipe bash in run block scalar", src: "      - run: |\n          curl https://example.com/i.sh | bash\n", want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GitHubActionsRemoteShellRule{}.AnalyzeUnit(workflowUnit("ci.yml", tt.src), Context{})
			if len(got) != tt.want {
				t.Fatalf("findings = %#v, want %d", got, tt.want)
			}
		})
	}
}

// TestGitHubActionsBroadPermissionsRule covers blanket write grants and scoped
// permission blocks.
func TestGitHubActionsBroadPermissionsRule(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want int
	}{
		{name: "write-all", src: "permissions: write-all\n", want: 1},
		{name: "bare write", src: "permissions: write\n", want: 1},
		{name: "scoped block", src: "permissions:\n  contents: write\n  pull-requests: read\n", want: 0},
		{name: "read-all", src: "permissions: read-all\n", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GitHubActionsBroadPermissionsRule{}.AnalyzeUnit(workflowUnit("ci.yml", tt.src), Context{})
			if len(got) != tt.want {
				t.Fatalf("findings = %#v, want %d", got, tt.want)
			}
		})
	}
}

// TestGitHubActionsPullRequestTargetRule covers risky pull_request_target use and
// the plain pull_request / no-execution cases.
func TestGitHubActionsPullRequestTargetRule(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want int
	}{
		{name: "target with checkout", src: "on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n", want: 1},
		{name: "target with run", src: "on: pull_request_target\njobs:\n  x:\n    steps:\n      - run: make build\n", want: 1},
		{name: "plain pull_request", src: "on:\n  pull_request:\njobs:\n  x:\n    steps:\n      - run: make build\n", want: 0},
		{name: "target without execution", src: "on: pull_request_target\njobs:\n  x:\n    runs-on: ubuntu-latest\n", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GitHubActionsPullRequestTargetRule{}.AnalyzeUnit(workflowUnit("pr.yml", tt.src), Context{})
			if len(got) != tt.want {
				t.Fatalf("findings = %#v, want %d", got, tt.want)
			}
		})
	}
}

// TestGitHubActionsSecretsInPRRule covers named secrets in pull-request workflows
// and the GITHUB_TOKEN / non-PR exemptions.
func TestGitHubActionsSecretsInPRRule(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want int
	}{
		{name: "named secret in pull_request", src: "on: pull_request\njobs:\n  x:\n    steps:\n      - run: deploy\n        env:\n          KEY: ${{ secrets.NPM_TOKEN }}\n", want: 1},
		{name: "named secret in pull_request_target", src: "on: pull_request_target\nenv:\n  K: ${{ secrets.DEPLOY_KEY }}\n", want: 1},
		{name: "github token exempt", src: "on: pull_request\nenv:\n  K: ${{ secrets.GITHUB_TOKEN }}\n", want: 0},
		{name: "named secret on push", src: "on: push\nenv:\n  K: ${{ secrets.NPM_TOKEN }}\n", want: 0},
		{name: "pull_request in comment is not a trigger", src: "on: push\n# also relevant for pull_request builds\nenv:\n  K: ${{ secrets.NPM_TOKEN }}\n", want: 0},
		{name: "pull_request in job condition is not a trigger", src: "on: push\njobs:\n  x:\n    if: github.event_name == 'pull_request'\n    steps:\n      - run: deploy\n        env:\n          K: ${{ secrets.NPM_TOKEN }}\n", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GitHubActionsSecretsInPRRule{}.AnalyzeUnit(workflowUnit("pr.yml", tt.src), Context{})
			if len(got) != tt.want {
				t.Fatalf("findings = %#v, want %d", got, tt.want)
			}
		})
	}
}

// TestWorkflowRulesIgnoreNonWorkflowFiles confirms the rules only run on
// .github/workflows YAML, not arbitrary config files.
func TestWorkflowRulesIgnoreNonWorkflowFiles(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config/ci.yml", Type: source.FileTypeText},
		Source: "permissions: write-all\non: pull_request_target\n      - uses: somevendor/action@main\n",
	}
	if got := (GitHubActionsBroadPermissionsRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("broad-permissions on non-workflow file = %#v, want none", got)
	}
	if got := (GitHubActionsUnpinnedActionRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("unpinned-action on non-workflow file = %#v, want none", got)
	}
}
