// Package rule defines gruff-go's rule registry and analysers.
//
// This file tests how the secret-pattern check in SensitiveDataRule treats non-Go config files such as config.example.toml.
// A failure means users scanning example configs would see credential findings for comments or placeholders, or lose a real one.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// TestSensitiveDataRuleSkipsConfigCommentsAndPlaceholders protects example configs from false credential findings.
//
// Commented-out assignments, even a ; comment with a real-looking token, and your-, changeme- or replace-me- placeholders must not flag.
// A real uncommented credential still gives one finding; secretPatternFixtureValue() keeps the dogfood scan from flagging this file.
func TestSensitiveDataRuleSkipsConfigCommentsAndPlaceholders(t *testing.T) {
	skip := []struct{ name, line string }{
		{"toml comment placeholder", `# api_key = "your-minimax-api-key"`},
		{"toml comment token", `#   token = "your-telegram-bot-token"`},
		{"slash comment", `// client_secret = "your-dingtalk-client-secret"`},
		{"semicolon comment real value", `; access_token = "` + secretPatternFixtureValue() + `"`},
		{"uncommented your- placeholder", `api_key = "your-minimax-api-key"`},
		{"changeme placeholder", `client_secret = "changeme-please-before-deploy"`},
		{"replace-me placeholder", `auth_token = "replace-me-with-a-real-token"`},
	}
	for _, tt := range skip {
		t.Run(tt.name, func(t *testing.T) {
			unit := parser.Unit{
				File:   source.File{Path: "config.example.toml", Type: source.FileTypeText},
				Source: tt.line + "\n",
			}
			if got := (SensitiveDataRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
				t.Fatalf("config comment/placeholder should not flag, got %#v", got)
			}
		})
	}

	realCredential := parser.Unit{
		File:   source.File{Path: "config.example.toml", Type: source.FileTypeText},
		Source: `api_key = "` + secretPatternFixtureValue() + "\"\n",
	}
	if got := (SensitiveDataRule{}).AnalyzeUnit(realCredential, Context{}); len(got) != 1 {
		t.Fatalf("real uncommented credential should still flag, got %#v", got)
	}
}

// TestSensitiveDataRuleFlagsSecretContainingPlaceholderSubstring ensures the placeholder skip is prefix-anchored.
//
// A real secret that merely contains a placeholder word such as dummy mid-value still gives one finding.
// The value is built across literals so the dogfood scan never reads this file as a credential.
func TestSensitiveDataRuleFlagsSecretContainingPlaceholderSubstring(t *testing.T) {
	value := "aB3xK9" + "dummy" + "Qz7Mn4Pl2Vr8Wt6Yh"
	unit := parser.Unit{
		File:   source.File{Path: "config.toml", Type: source.FileTypeText},
		Source: "api_key = \"" + value + "\"\n",
	}
	if got := (SensitiveDataRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
		t.Fatalf("a real secret merely containing a placeholder word should still flag, got %#v", got)
	}
}
