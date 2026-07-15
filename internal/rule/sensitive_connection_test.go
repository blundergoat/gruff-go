package rule

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// connectionCredentialCase defines one named row in the reserved-delimiter,
// placeholder, or authority-boundary regression matrix.
type connectionCredentialCase struct {
	name        string
	url         string
	password    string
	wantFinding bool
}

// connectionURL builds a fixture URL at runtime so the dogfood scanner never
// reads a complete credential-bearing URI from this test file.
func connectionURL(user, password, host, suffix string) string {
	return "postgres" + "://" + user + ":" + password + "@" + host + suffix
}

// connectionCredentialCases returns every required M01 positive and negative
// boundary as a distinct, grep-friendly subtest.
func connectionCredentialCases() []connectionCredentialCase {
	return []connectionCredentialCase{
		{name: "raw slash password", url: connectionURL("app", "alpha/slash-42", "localhost:5432", "/orders"), password: "alpha/slash-42", wantFinding: true},
		{name: "encoded slash password", url: connectionURL("app", "alpha%2Fslash-42", "localhost", "/orders"), password: "alpha%2Fslash-42", wantFinding: true},
		{name: "raw colon password", url: connectionURL("app", "alpha:colon-42", "localhost", "/orders"), password: "alpha:colon-42", wantFinding: true},
		{name: "encoded colon password", url: connectionURL("app", "alpha%3Acolon-42", "localhost", "/orders"), password: "alpha%3Acolon-42", wantFinding: true},
		{name: "raw plus password", url: connectionURL("app", "alpha+plus-42", "localhost", "/orders"), password: "alpha+plus-42", wantFinding: true},
		{name: "encoded plus password", url: connectionURL("app", "alpha%2Bplus-42", "localhost", "/orders"), password: "alpha%2Bplus-42", wantFinding: true},
		{name: "raw equals password", url: connectionURL("app", "alpha=equal-42", "localhost", "/orders"), password: "alpha=equal-42", wantFinding: true},
		{name: "encoded equals password", url: connectionURL("app", "alpha%3Dequal-42", "localhost", "/orders"), password: "alpha%3Dequal-42", wantFinding: true},
		{name: "encoded at password", url: connectionURL("app", "alpha%40at-42", "localhost", "/orders"), password: "alpha%40at-42", wantFinding: true},
		{name: "mixed passphrase local", url: connectionURL("app", "myPassphrase2024", "localhost", "/orders"), password: "myPassphrase2024", wantFinding: true},
		{name: "mixed invalid local", url: connectionURL("app", "not-invalid-prod", "localhost", "/orders"), password: "not-invalid-prod", wantFinding: true},
		{name: "mixed example slash local", url: connectionURL("app", "example/real-secret", "localhost", "/orders"), password: "example/real-secret", wantFinding: true},
		{name: "exact placeholder localhost", url: connectionURL("app", "placeholder", "localhost", "/orders"), wantFinding: false},
		{name: "case folded placeholder localhost", url: connectionURL("app", "PLACEHOLDER", "LOCALHOST", "?ssl=false"), wantFinding: false},
		{name: "encoded placeholder localhost", url: connectionURL("app", "place%68older", "localhost:5432", "/orders?ssl=false"), wantFinding: false},
		{name: "exact placeholder ipv4 loopback", url: connectionURL("app", "dev_password_change_me", "127.0.0.1:5432", "/orders"), wantFinding: false},
		{name: "exact placeholder ipv6 loopback", url: connectionURL("app", "pass", "[::1]:5432", "/orders"), wantFinding: false},
		{name: "placeholder non local", url: connectionURL("app", "placeholder", "db.example.net:5432", "/orders"), password: "placeholder", wantFinding: true},
		{name: "malformed percent is non placeholder", url: connectionURL("app", "place%ZZholder", "localhost", "/orders"), password: "place%ZZholder", wantFinding: true},
		{name: "literal plus never becomes space", url: connectionURL("app", "your+password", "localhost", "/orders"), password: "your+password", wantFinding: true},
		{name: "real password ipv6 loopback", url: connectionURL("app", "real-ipv6-value", "[::1]:5432", "/orders?ssl=false"), password: "real-ipv6-value", wantFinding: true},
		{name: "no credentials", url: "postgres" + "://" + "localhost:5432/orders", wantFinding: false},
		{name: "username only", url: "postgres" + "://" + "app@localhost:5432/orders", wantFinding: false},
		{name: "empty password", url: connectionURL("app", "", "localhost", "/orders"), wantFinding: false},
		{name: "empty username", url: connectionURL("", "nonempty-value", "localhost", "/orders"), wantFinding: false},
		{name: "empty host", url: connectionURL("app", "nonempty-value", "", "/orders"), wantFinding: false},
		{name: "raw embedded at is ambiguous", url: connectionURL("app", "part@rest", "localhost", "/orders"), wantFinding: false},
	}
}

// TestConnectionStringCredentialMatrix pins extraction, exact-placeholder, and
// local-host behavior before the matcher implementation changes.
func TestConnectionStringCredentialMatrix(t *testing.T) {
	for _, tt := range connectionCredentialCases() {
		t.Run(tt.name, func(t *testing.T) {
			unit := parser.Unit{
				File:   source.File{Path: "fixture.go", Type: source.FileTypeGo},
				Source: "package fixture\nconst databaseURL = " + strconv.Quote(tt.url) + "\n",
			}
			findings := (ConnectionStringRule{}).AnalyzeUnit(unit, Context{})
			want := 0
			if tt.wantFinding {
				want = 1
			}
			if len(findings) != want {
				t.Fatalf("finding count = %d, want %d", len(findings), want)
			}
			if len(findings) == 1 {
				assertConnectionFindingRedacted(t, findings[0], tt.url, tt.password)
			}
		})
	}
}

// TestConnectionStringRuleChecksEveryCandidateOnLine ensures a username-only
// URI cannot hide a later password-bearing connection string on the same line.
func TestConnectionStringRuleChecksEveryCandidateOnLine(t *testing.T) {
	usernameOnly := "postgres" + "://" + "app@localhost"
	passwordBearing := connectionURL("svc", "prodsecret", "db.internal", "/orders")
	unit := parser.Unit{
		File:   source.File{Path: "fixture.go", Type: source.FileTypeGo},
		Source: "package fixture\nconst endpoints = " + strconv.Quote(usernameOnly+" "+passwordBearing) + "\n",
	}
	findings := (ConnectionStringRule{}).AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want 1; findings = %#v", len(findings), findings)
	}
	assertConnectionFindingRedacted(t, findings[0], passwordBearing, "prodsecret")
}

// assertConnectionFindingRedacted proves neither the complete URI nor its raw
// password is carried by the current finding payload.
func assertConnectionFindingRedacted(t *testing.T, finding any, rawURL, rawPassword string) {
	t.Helper()
	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	payload := string(encoded)
	if strings.Contains(payload, rawURL) {
		t.Fatal("finding payload contains the complete connection URI")
	}
	if rawPassword != "" && strings.Contains(payload, rawPassword) {
		t.Fatal("finding payload contains the complete raw password")
	}
}
