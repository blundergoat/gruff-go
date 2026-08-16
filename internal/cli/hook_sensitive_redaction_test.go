// Package cli tests hook propagation of deny-by-default sensitive previews.
package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestHookSensitivePreviewPolicy covers all six preview-construction routes at
// empty, nonmatching, and matching authorization states.
func TestHookSensitivePreviewPolicy(t *testing.T) {
	states := []struct {
		name      string
		allowlist []string
		allowed   bool
	}{
		{name: "empty"},
		{name: "nonmatching", allowlist: []string{"other/**"}},
		{name: "matching", allowlist: []string{"secrets/**"}, allowed: true},
	}

	for _, state := range states {
		t.Run(state.name, func(t *testing.T) {
			root := t.TempDir()
			sourceBody, forbidden := hookSensitiveFixture()
			writeFile(t, root, ".gruff-go.yaml", hookSensitiveConfig(state.allowlist))
			writeFile(t, root, "secrets/all.env", sourceBody)
			t.Chdir(root)

			payload, code := runHookReport(t, "hook", "--format", "json", "secrets/all.env")
			if code != 0 {
				t.Fatalf("hook exit = %d, want advisory exit 0", code)
			}
			assertHookSensitiveMarkers(t, payload.Findings, state.allowed)
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

// hookSensitiveConfig enables the opt-in routes and renders one preview list.
func hookSensitiveConfig(allowlist []string) string {
	preview := "  secretPreviews: []\n"
	if len(allowlist) > 0 {
		preview = "  secretPreviews:\n"
		for _, pattern := range allowlist {
			preview += "    - \"" + pattern + "\"\n"
		}
	}
	return "schemaVersion: gruff-go.config.v0.1\nallowlists:\n" + preview +
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
func assertHookSensitiveMarkers(t *testing.T, findings []hookFinding, allowed bool) {
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
		want := "[redacted]"
		if allowed {
			want = hookSensitiveAllowedMarker(item)
		}
		if got, _ := item.Metadata["preview"].(string); got != want {
			t.Fatalf("%s hook preview does not match approved marker", item.RuleID)
		}
		if item.RuleID == "sensitive-data.gcp-service-account" {
			secondaryWant := "[redacted]"
			if allowed {
				secondaryWant = "[redacted:private-key]"
			}
			if got, _ := item.Metadata["secondaryPreview"].(string); got != secondaryWant {
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

// hookSensitiveAllowedMarker returns the approved marker for matching paths.
func hookSensitiveAllowedMarker(item hookFinding) string {
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
