// Package cli tests hook propagation of deny-by-default sensitive previews.
package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestHookSensitivePreviewPolicy covers all six preview-construction routes under the one unconditional policy.
//
// The three authorization states this used to sweep no longer exist: section 5 removed the key that varied them, so
// what remains to prove is that each route emits its approved marker and no route leaks a reusable fragment.
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
			if code != 0 {
				t.Fatalf("hook exit = %d, want advisory exit 0", code)
			}
			assertHookSensitiveMarkers(t, payload.Findings)
			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			for _, fragment := range forbidden {
				if strings.Contains(string(encoded), fragment) {
					t.Fatal("hook payload contains a reusable secret fragment")
				}
			}
		})
	}
}

// hookSensitiveConfig enables the three opt-in routes the fixture needs.
func hookSensitiveConfig() string {
	return "schemaVersion: gruff-go.config.v0.1\n" +
		"rules:\n" +
		"  sensitive-data.high-entropy-string:\n    enabled: true\n" +
		"  sensitive-data.pii-pattern:\n    enabled: true\n" +
		"  sensitive-data.phi-pattern:\n    enabled: true\n"
}

// hookSensitiveFixture returns runtime-built raw source and forbidden legacy
// preview fragments without embedding a complete provider credential here.
func hookSensitiveFixture() (string, []string) {
	generic := "abcabcabcabc-" + "defdefdefdef-7890"
	aws := "AKIA" + "Q7W9E2R4T6Y8U1I3"
	password := "db-pass-" + strings.Repeat("R8", 8)
	connection := "postgres" + "://app:" + password + "@db.internal:5432/orders"
	privateKey := "-----BEGIN " + "RSA PRIVATE KEY-----"
	entropy := "Zx9KqW2mB7vN4pL8dT3r" + "YcF1gHjS0aQwE4tU7iO5n"
	email := "audit.person" + "@" + "realcorp.co"
	ssn := "536-90-4399"
	lines := []string{
		"auth_token = \"" + generic + "\"",
		"aws = \"" + aws + "\"",
		"database = \"" + connection + "\"",
		"\"type\": \"service_account\"",
		"\"private_key\": \"" + privateKey + "\"",
		"entropy = \"" + entropy + "\"",
		"email = \"" + email + "\"",
		"ssn = \"" + ssn + "\"",
	}
	forbidden := []string{privateKey, privateKey[:6]}
	for _, secret := range []string{generic, aws, password, entropy, email, ssn} {
		forbidden = append(forbidden, secret, secret[:6], secret[len(secret)-4:])
	}
	return strings.Join(lines, "\n") + "\n", forbidden
}

// assertHookSensitiveMarkers checks route coverage and exact hook metadata.
func assertHookSensitiveMarkers(t *testing.T, findings []hookFinding) {
	t.Helper()
	wantRules := map[string]bool{
		"sensitive-data.secret-pattern":      false,
		"sensitive-data.private-key":         false,
		"sensitive-data.aws-access-key":      false,
		"sensitive-data.connection-string":   false,
		"sensitive-data.gcp-service-account": false,
		"sensitive-data.high-entropy-string": false,
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
	for ruleID, found := range wantRules {
		if !found {
			t.Fatalf("hook fixture did not exercise %s", ruleID)
		}
	}
}

// hookSensitiveApprovedMarker returns the closed-vocabulary marker section 5 ratifies for each route.
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
