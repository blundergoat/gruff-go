// Package rule defines gruff-go's rule registry and analysers.
// This file implements a parser-only check for logging credential-bearing values.
package rule

import (
	"go/ast"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// loggingSecretSubstrings are the high-precision identifier fragments that mark a
// logged value as a credential. Token and key are intentionally omitted because
// their bare forms (tokenizer, sortKey) are too noisy; request tokens are caught
// through auth-header/cookie reads and env-secret reads instead.
var loggingSecretSubstrings = []string{"password", "passwd", "passphrase", "secret", "credential", "bearer"}

// loggingEnvSecretSubstrings mark an os.Getenv/LookupEnv key as a secret read.
var loggingEnvSecretSubstrings = []string{"secret", "token", "password", "passwd", "apikey", "api_key", "privatekey", "private_key", "credential", "passphrase"}

// loggingRedactionWords name calls that neutralise a value before logging, so a
// wrapped value is not reported.
var loggingRedactionWords = []string{"redact", "mask", "scrub", "sanit", "obfuscat", "truncat", "hash", "sum", "sha", "hmac"}

// SensitiveDataLoggingRule flags logging or print calls whose arguments carry
// credential-bearing values.
type SensitiveDataLoggingRule struct{}

// Definition declares the security.sensitive-data-logging rule for bounded
// same-function evidence of credentials reaching log output.
func (SensitiveDataLoggingRule) Definition() Definition {
	return Definition{
		ID:               "security.sensitive-data-logging",
		Title:            "Sensitive data in logging",
		Description:      "Flags logging and print calls whose arguments are credential-bearing: secret-named identifiers, secret-named environment reads, or request auth headers and cookies. Static text-only messages and redaction-wrapped values are ignored. Candidate wording, bounded same-function evidence.",
		Pillar:           finding.PillarSecurity,
		SecondaryPillars: []finding.Pillar{finding.PillarSensitiveData},
		Severity:         finding.SeverityAdvisory,
		Confidence:       finding.ConfidenceMedium,
		DefaultEnabled:   true,
		Tags:             []string{"logging", "security", "sensitive-data"},
		Remediation:      "Remove the secret from the log call or log a redacted/masked placeholder instead of the raw credential.",
	}
}

// AnalyzeUnit emits findings for logging calls that receive credential-bearing arguments.
func (SensitiveDataLoggingRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	sinks := loggingSinkPackages{
		log:  packageImportNames(unit.AST, "log", "log"),
		fmt:  packageImportNames(unit.AST, "fmt", "fmt"),
		slog: packageImportNames(unit.AST, "log/slog", "slog"),
	}
	osPackages := packageImportNames(unit.AST, "os", "os")
	httpPackages := packageImportNames(unit.AST, "net/http", "http")
	findings := []finding.Finding{}
	visitFunc := func(funcType *ast.FuncType, body *ast.BlockStmt) {
		if body == nil {
			return
		}
		var scope *requestTaintScope
		if len(httpPackages) > 0 {
			if built, ok := newRequestTaintScope(unit.AST, funcType, body, httpPackages); ok {
				scope = built
			}
		}
		ast.Inspect(body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			sink, ok := loggingSinkName(call, sinks)
			if !ok {
				return true
			}
			reason, arg, ok := firstSensitiveArg(call.Args, scope, osPackages)
			if !ok {
				return true
			}
			position := unit.FileSet.Position(arg.Pos())
			findings = append(findings, finding.Finding{
				Message:  "logging call may write a sensitive value to output",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Metadata: map[string]any{"sink": sink, "reason": reason},
			})
			return true
		})
	}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		switch fn := node.(type) {
		case *ast.FuncDecl:
			visitFunc(fn.Type, fn.Body)
		case *ast.FuncLit:
			visitFunc(fn.Type, fn.Body)
		}
		return true
	})
	return findings
}

// loggingSinkPackages groups the imported aliases of the logging/print packages.
type loggingSinkPackages struct {
	log  map[string]bool
	fmt  map[string]bool
	slog map[string]bool
}

// firstSensitiveArg returns the first non-literal argument that carries a
// credential, its classification reason, and the argument expression. Pure string
// literals (format strings, static keys) are skipped. Redaction and hashing calls
// no longer disqualify the whole argument: each detector prunes a redaction call's
// own subtree, so a hashed sibling value (e.g. a checksum logged next to a raw
// password) does not mask a credential elsewhere in the same argument.
func firstSensitiveArg(args []ast.Expr, scope *requestTaintScope, osPackages map[string]bool) (string, ast.Expr, bool) {
	for _, arg := range args {
		if isStringLiteral(arg) {
			continue
		}
		if scope != nil {
			if reason, ok := scope.requestSensitiveRead(arg); ok {
				return reason, arg, true
			}
		}
		if isSecretEnvRead(arg, osPackages) {
			return "env-secret", arg, true
		}
		if hasSecretIdentifier(arg) {
			return "secret-identifier", arg, true
		}
	}
	return "", nil, false
}

// loggingSinkName reports a sink label when call is a recognised logging or print
// call: the log/fmt/slog packages, or a method on a logger-named receiver.
func loggingSinkName(call *ast.CallExpr, sinks loggingSinkPackages) (string, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	if receiver, ok := selector.X.(*ast.Ident); ok {
		switch {
		case sinks.log[receiver.Name] && logFuncNames[selector.Sel.Name]:
			return receiver.Name + "." + selector.Sel.Name, true
		case sinks.fmt[receiver.Name] && fmtPrintNames[selector.Sel.Name]:
			return receiver.Name + "." + selector.Sel.Name, true
		case sinks.slog[receiver.Name] && slogFuncNames[selector.Sel.Name]:
			return receiver.Name + "." + selector.Sel.Name, true
		}
	}
	if logVerbNames[selector.Sel.Name] && receiverLooksLikeLogger(selector.X) {
		return "logger." + selector.Sel.Name, true
	}
	return "", false
}

// receiverLooksLikeLogger reports whether the call receiver names a logger, so a
// structured logging method on it counts as a sink.
func receiverLooksLikeLogger(expr ast.Expr) bool {
	return strings.Contains(strings.ToLower(receiverTrailingName(expr)), "log")
}

// receiverTrailingName returns the trailing identifier of a receiver chain
// (logger, h.log, h.Logger()) for logger-name heuristics.
func receiverTrailingName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.CallExpr:
		return receiverTrailingName(e.Fun)
	}
	return ""
}

// requestSensitiveRead reports whether arg reads a request auth header or cookie,
// the request-borne credentials worth keeping out of logs.
func (s *requestTaintScope) requestSensitiveRead(arg ast.Expr) (string, bool) {
	reason := ""
	ast.Inspect(arg, func(node ast.Node) bool {
		if reason != "" {
			return false
		}
		if isRedactionCall(node) {
			return false // a masked/hashed request read is already neutralised; skip its subtree
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if selector.Sel.Name == "Cookie" {
			if ident, ok := selector.X.(*ast.Ident); ok && s.isRequestIdentifier(ident) {
				reason = "cookie"
				return false
			}
		}
		if selector.Sel.Name == "Get" && len(call.Args) >= 1 {
			if inner, ok := selector.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "Header" {
				if ident, ok := inner.X.(*ast.Ident); ok && s.isRequestIdentifier(ident) {
					if literal, ok := stringLiteral(call.Args[0]); ok && isAuthHeaderName(literal) {
						reason = "auth-header"
						return false
					}
				}
			}
		}
		return true
	})
	return reason, reason != ""
}

// isSecretEnvRead reports whether arg reads a secret-named environment variable
// via os.Getenv or os.LookupEnv.
func isSecretEnvRead(arg ast.Expr, osPackages map[string]bool) bool {
	found := false
	ast.Inspect(arg, func(node ast.Node) bool {
		if found {
			return false
		}
		if isRedactionCall(node) {
			return false // a masked/hashed env read is already neutralised; skip its subtree
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !selectorCallMatches(call, osPackages, "Getenv") && !selectorCallMatches(call, osPackages, "LookupEnv") {
			return true
		}
		if len(call.Args) >= 1 {
			if literal, ok := stringLiteral(call.Args[0]); ok && containsAnySubstring(strings.ToLower(literal), loggingEnvSecretSubstrings) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// hasSecretIdentifier reports whether any identifier or selector inside arg has a
// credential-suggesting name.
func hasSecretIdentifier(arg ast.Expr) bool {
	found := false
	ast.Inspect(arg, func(node ast.Node) bool {
		if found {
			return false
		}
		if isRedactionCall(node) {
			return false // a masked/hashed value is already neutralised; skip its subtree
		}
		name := ""
		switch value := node.(type) {
		case *ast.Ident:
			name = value.Name
		case *ast.SelectorExpr:
			name = value.Sel.Name
		}
		if name != "" && containsAnySubstring(strings.ToLower(name), loggingSecretSubstrings) {
			found = true
			return false
		}
		return true
	})
	return found
}

// isRedactionCall reports whether node is a call whose name matches a redaction or
// hashing word (mask, hash, sha, hmac, ...). The secret scans prune such a call's
// subtree, treating only that wrapped sub-expression as neutralised. Scoping to the
// subtree — rather than disqualifying the whole logging argument — keeps a hashed
// sibling (e.g. a checksum) from masking a raw credential interpolated alongside it.
func isRedactionCall(node ast.Node) bool {
	call, ok := node.(*ast.CallExpr)
	return ok && callNameMatchesAny(call, loggingRedactionWords)
}

// isStringLiteral reports whether expr is a string literal, used to skip format
// strings and static keys when scanning logging arguments.
func isStringLiteral(expr ast.Expr) bool {
	_, ok := stringLiteral(expr)
	return ok
}

// isAuthHeaderName reports whether a header name denotes credentials.
func isAuthHeaderName(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token", "x-amz-security-token":
		return true
	}
	return strings.Contains(lower, "authorization") || strings.Contains(lower, "auth-token") ||
		strings.Contains(lower, "api-key") || strings.Contains(lower, "apikey")
}

// containsAnySubstring reports whether value contains any of the substrings.
func containsAnySubstring(value string, substrings []string) bool {
	for _, sub := range substrings {
		if strings.Contains(value, sub) {
			return true
		}
	}
	return false
}

// logFuncNames are stdlib log package functions that emit to a log destination.
var logFuncNames = map[string]bool{
	"Print": true, "Printf": true, "Println": true,
	"Fatal": true, "Fatalf": true, "Fatalln": true,
	"Panic": true, "Panicf": true, "Panicln": true, "Output": true,
}

// fmtPrintNames are fmt package functions that print to stdout or a writer.
var fmtPrintNames = map[string]bool{
	"Print": true, "Printf": true, "Println": true,
	"Fprint": true, "Fprintf": true, "Fprintln": true,
}

// slogFuncNames are log/slog package functions that emit a structured record.
var slogFuncNames = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true,
	"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
	"Log": true, "LogAttrs": true,
}

// logVerbNames are method names that count as logging when called on a
// logger-named receiver (covering common structured-logging libraries).
var logVerbNames = map[string]bool{
	"Print": true, "Printf": true, "Println": true,
	"Debug": true, "Debugf": true, "Debugw": true,
	"Info": true, "Infof": true, "Infow": true,
	"Warn": true, "Warnf": true, "Warnw": true, "Warning": true, "Warningf": true,
	"Error": true, "Errorf": true, "Errorw": true,
	"Fatal": true, "Fatalf": true, "Panic": true, "Panicf": true,
	"Log": true, "Logf": true, "Trace": true, "Tracef": true,
}
