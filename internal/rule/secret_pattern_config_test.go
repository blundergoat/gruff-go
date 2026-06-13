// Package rule tests the generic secret-pattern rule on non-Go config files.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// TestSensitiveDataRuleSkipsConfigCommentsAndPlaceholders covers the config-file
// false positives surfaced by corpus calibration: commented-out example
// assignments and your-/CHANGEME-style placeholder values must not flag, while a
// real uncommented credential in the same file still does. Real-token cases use
// secretPatternFixtureValue() so the dogfood scan never reads this file as
// carrying a credential.
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
