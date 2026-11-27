// Package cli tests hook propagation of deny-by-default sensitive previews.
//
// The fixture writes one file that trips every tracked sensitive-data rule and runs gruff-go hook --format json on it.
// A failure means the hook payload an agent reads could carry a reusable credential fragment instead of a redaction marker.
package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestHookSensitivePreviewPolicy covers all six preview-construction routes under the one unconditional policy.
//
// t checks that each route emits its approved marker and no route leaks a reusable fragment into the hook payload.
// A failure means hook --format json on a secrets file exits non-zero, misses a route, shows an unapproved preview, or leaks a fragment.
func TestHookSensitivePreviewPolicy(t *testing.T) {
	states := []struct {
		name string
	}{
		{name: "unconditional"},
	}

	for _, state := range states {
		t.Run(state.name, func(t *testing.T) {
			root := t.TempDir()
			sourceBody, forbidden := hookSensitiveFixture()
			writeFile(t, root, ".gruff-go.yaml", hookSensitiveConfig())
			writeFile(t, root, "secrets/all.env", sourceBody)
			t.Chdir(root)

			payload, code := runHookReport(t, "hook", "--format", "json", "secrets/all.env")
			// Secret findings must not block the agent: hook stays advisory and exits 0 even when the fixture trips every route.
			if code != 0 {
				t.Fatalf("hook exit = %d, want advisory exit 0", code)
			}
			assertHookSensitiveMarkers(t, payload.Findings)
			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			// The whole encoded payload is searched, so a fragment that leaks through any field, not just a preview, fails the test.
			for _, fragment := range forbidden {
				if strings.Contains(string(encoded), fragment) {
					t.Fatal("hook payload contains a reusable secret fragment")
				}
			}
		})
	}
}

// hookSensitiveConfig enables the opt-in routes the fixture needs.
// It returns fixed, never-empty YAML text that sets the gruff-go schema version and enables seven sensitive-data rules.
func hookSensitiveConfig() string {
	return "schemaVersion: gruff-go.config.v0.1\nrules:\n" +
		"  sensitive-data.aws-access-key:\n    enabled: true\n" +
		"  sensitive-data.connection-string:\n    enabled: true\n" +
		"  sensitive-data.gcp-service-account:\n    enabled: true\n" +
		"  sensitive-data.github-token:\n    enabled: true\n" +
		"  sensitive-data.google-api-key:\n    enabled: true\n" +
		"  sensitive-data.pii-pattern:\n    enabled: true\n" +
		"  sensitive-data.phi-pattern:\n    enabled: true\n"
}

// hookSensitiveFixture returns runtime-built raw source and forbidden legacy preview fragments.
//
// Credential strings are written in pieces so no complete provider credential appears as a single literal in this file.
// The source ends in a newline; the forbidden list is never empty, and any entry found in the hook JSON fails the test.
func hookSensitiveFixture() (string, []string) {
	generic := "abcabcabcabc-" + "defdefdefdef-7890"
	aws := "AKIA" + "Q7W9E2R4T6Y8U1I3"
	password := "db-pass-" + strings.Repeat("R8", 8)
	connection := "postgres" + "://app:" + password + "@db.internal:5432/orders"
	privateKey := "-----BEGIN " + "RSA PRIVATE KEY-----"
	email := "audit.person" + "@" + "realcorp.co"
	ssn := "536-90-4399"
	lines := []string{
		"auth_token = \"" + generic + "\"",
		"aws = \"" + aws + "\"",
		"database = \"" + connection + "\"",
		"\"type\": \"service_account\"",
		"\"private_key\": \"" + privateKey + "\"",
		"email = \"" + email + "\"",
		"ssn = \"" + ssn + "\"",
	}
	forbidden := []string{privateKey, privateKey[:6]}
	// Each secret is forbidden whole and as its first six and last four characters, the fragments a legacy preview would have shown.
	for _, secret := range []string{generic, aws, password, email, ssn} {
		forbidden = append(forbidden, secret, secret[:6], secret[len(secret)-4:])
	}
	return strings.Join(lines, "\n") + "\n", forbidden
}

// assertHookSensitiveMarkers checks route coverage and exact hook metadata.
//
// Each tracked sensitive-data finding in findings must carry a preview equal to hookSensitiveApprovedMarker; other rule IDs are skipped.
// A GCP service-account finding also needs a private-key secondaryPreview marker, and each of the seven tracked rule IDs must appear in findings.
//
// t fails the test with the rule whose preview drifted from its marker, or with the tracked rule the fixture never triggered.
func assertHookSensitiveMarkers(t *testing.T, findings []hookFinding) {
	t.Helper()
	wantRules := map[string]bool{
		"sensitive-data.secret-pattern":      false,
		"sensitive-data.private-key":         false,
		"sensitive-data.aws-access-key":      false,
		"sensitive-data.connection-string":   false,
		"sensitive-data.gcp-service-account": false,
		"sensitive-data.pii-pattern":         false,
		"sensitive-data.phi-pattern":         false,
	}
	for _, item := range findings {
		if _, tracked := wantRules[item.RuleID]; !tracked {
			continue
		}
		wantRules[item.RuleID] = true
		if got, _ := item.Metadata["preview"].(string); got != hookSensitiveApprovedMarker(item) {
			t.Fatalf("%s hook preview does not match approved marker", item.RuleID)
		}
		// A GCP service account carries a second secret field, and section 5 marks it independently.
		if item.RuleID == "sensitive-data.gcp-service-account" {
			if got, _ := item.Metadata["secondaryPreview"].(string); got != "[redacted:private-key]" {
				t.Fatal("GCP hook secondary preview does not match approved marker")
			}
		}
	}
	// A tracked rule the fixture never triggered would leave its preview route untested, so it fails rather than passing quietly.
	for ruleID, found := range wantRules {
		if !found {
			t.Fatalf("hook fixture did not exercise %s", ruleID)
		}
	}
}

// hookSensitiveApprovedMarker returns the closed-vocabulary marker section 5 ratifies for each route.
//
// Only the RuleID of item selects the marker.
// A rule ID with no dedicated case, such as sensitive-data.secret-pattern, gets the generic redacted marker, so the result is never empty.
func hookSensitiveApprovedMarker(item hookFinding) string {
	switch item.RuleID {
	case "sensitive-data.private-key":
		return "[redacted:private-key]"
	case "sensitive-data.aws-access-key":
		return "[redacted:aws-access-key]"
	case "sensitive-data.connection-string":
		return "[redacted:connection-string:postgres]"
	case "sensitive-data.gcp-service-account":
		return "[redacted:gcp-service-account]"
	case "sensitive-data.pii-pattern":
		return "[redacted:email]"
	case "sensitive-data.phi-pattern":
		return "[redacted:ssn]"
	default:
		return "[redacted]"
	}
}
