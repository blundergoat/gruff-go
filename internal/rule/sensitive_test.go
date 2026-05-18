package rule

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// Constants long enough that the redaction helper keeps its
// "<prefix>...<suffix>" form rather than collapsing the entire match to
// "[redacted]". The match must be at least 13 characters for that branch.
const (
	rawAWSKey        = "AKIAIOSFODNN7EXAMPLE"
	rawJWT           = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	rawPrivateKey    = "-----BEGIN RSA PRIVATE KEY-----"
	rawConnectionURL = "postgres://app:supersecretpassword@db.internal:5432/orders"
)

func TestPrivateKeyRuleDetectsPEMHeader(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "tls_key = \"" + rawPrivateKey + "\\n...\"\n",
	}
	findings := PrivateKeyRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawPrivateKey)
}

func TestAWSAccessKeyRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "aws_access_key_id = " + rawAWSKey + "\n",
	}
	findings := AWSAccessKeyRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawAWSKey)
}

func TestJWTTokenRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "session_token = \"" + rawJWT + "\"\n",
	}
	findings := JWTTokenRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertNoRawSecret(t, findings[0], rawJWT)
}

func TestConnectionStringRuleDetectsAndRedacts(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "DATABASE_URL=" + rawConnectionURL + "\n",
	}
	findings := ConnectionStringRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1; got %#v", len(findings), findings)
	}
	assertNoRawSecret(t, findings[0], "supersecretpassword")
}

func TestSensitiveDetectorsAreDefaultEnabled(t *testing.T) {
	for _, definition := range []Definition{
		PrivateKeyRule{}.Definition(),
		AWSAccessKeyRule{}.Definition(),
		JWTTokenRule{}.Definition(),
		ConnectionStringRule{}.Definition(),
	} {
		if !definition.DefaultEnabled {
			t.Errorf("rule %q must be default-enabled", definition.ID)
		}
	}
}

func TestSensitiveDetectorsAreCleanOnInnocuousInput(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "ok.env", Type: source.FileTypeText},
		Source: "greeting = \"hello world\"\nport = 5432\n",
	}
	for _, rule := range []UnitRule{
		PrivateKeyRule{},
		AWSAccessKeyRule{},
		JWTTokenRule{},
		ConnectionStringRule{},
	} {
		if got := rule.AnalyzeUnit(unit, Context{}); len(got) != 0 {
			t.Errorf("rule %q produced findings on clean input: %#v", rule.Definition().ID, got)
		}
	}
}

func assertNoRawSecret(t *testing.T, item finding.Finding, raw string) {
	t.Helper()
	if strings.Contains(item.Message, raw) {
		t.Errorf("rule message leaks raw secret: %q", item.Message)
	}
	if preview, ok := item.Metadata["preview"].(string); ok {
		if preview == raw || strings.Contains(preview, raw) {
			t.Errorf("rule preview leaks raw secret: %q", preview)
		}
	}
}
