// Package rule defines gruff-go's rule registry and analysers.

// This file implements a parser-only check for logging credential-bearing values.
// A configured file path can stay out of the results when the same file proves its public role.
package rule

import (
	"go/ast"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// loggingSecretSubstrings mark credential-looking names in logged values.
// Token and key stay out because bare names like tokenizer and sortKey are noisy; request and environment reads are checked separately.
var loggingSecretSubstrings = []string{"password", "passwd", "passphrase", "secret", "credential", "bearer"}

// loggingEnvSecretSubstrings mark an os.Getenv/LookupEnv key as a secret read.
var loggingEnvSecretSubstrings = []string{
	"secret", "token", "password", "passwd", "apikey", "api_key", "privatekey", "private_key", "credential", "passphrase",
}

// loggingRedactionWords name calls that neutralise a value before logging, so a
// wrapped value is not reported.
var loggingRedactionWords = []string{"redact", "mask", "scrub", "sanit", "obfuscat", "truncat", "hash", "sum", "sha", "hmac"}

// SensitiveDataLoggingRule flags logging or print calls with credential-bearing values.
//
// A user sees the risky argument's location and classification.
// A configured file path stays quiet only when its source and read role are proved.
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
// Sibling package files can prove a logged storage prefix is fixed when the user scans one file.
func (SensitiveDataLoggingRule) AnalyzeUnit(unit parser.Unit, context Context) []finding.Finding {
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
			reason, arg, ok := firstSensitiveArg(loggingArgContext{
				unit:         unit,
				projectUnits: context.ProjectUnits,
				body:         body,
				requestScope: scope,
				osPackages:   osPackages,
			}, call.Args)
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

// loggingSinkPackages holds imported names for packages that print or log values.
//
// A project can rename log, fmt or slog during import.
// The rule uses those names to recognize where a user's values are sent.
type loggingSinkPackages struct {
	log  map[string]bool
	fmt  map[string]bool
	slog map[string]bool
}

// loggingArgContext holds the source facts used to explain one user's log call.
// It keeps local request and environment checks beside optional sibling proof.
// Empty sibling context cannot certify a fixed storage prefix.
type loggingArgContext struct {
	unit         parser.Unit
	projectUnits []parser.Unit
	body         *ast.BlockStmt
	requestScope *requestTaintScope
	osPackages   map[string]bool
}

// firstSensitiveArg returns the first credential-bearing log argument and its reason, so a user sees the risky value's location.
// Static text and proven metadata stay quiet; request and environment reads keep priority over those exceptions.
func firstSensitiveArg(context loggingArgContext, args []ast.Expr) (string, ast.Expr, bool) {
	// Check every argument because a safe path can appear beside a password in one log record.
	for index, arg := range args {
		// A format string or structured key is static text, not the value the user chose to log.
		if isStringLiteral(arg) {
			continue
		}
		// A request header or cookie remains sensitive even in a record with a public path.
		if context.requestScope != nil {
			// A sensitive request read takes priority over a public metadata role.
			if reason, ok := context.requestScope.requestSensitiveRead(arg); ok {
				return reason, arg, true
			}
		}
		// A secret-named environment read is still a warning before any path-role check.
		if isSecretEnvRead(arg, context.osPackages) {
			return "env-secret", arg, true
		}
		// A path read from configuration and later used to open the file is metadata, not the file contents.
		if isConfiguredPasswordFilePath(context.unit.AST, context.body, args, index, context.osPackages) {
			continue
		}
		// A seal's required share count is progress metadata when this function proves its source and result role.
		if isProvenSealShareThreshold(context.body, args, index) {
			continue
		}
		// A fixed package constant used to list storage is metadata, while any unproved prefix still warns.
		if isProvenFixedStorageListPrefix(context, args, index) {
			continue
		}
		// A secret-looking name with no path proof remains visible in scan results.
		if hasSecretIdentifier(arg) {
			return "secret-identifier", arg, true
		}
	}
	return "", nil, false
}

// isConfiguredPasswordFilePath accepts the structured path value only when its local origin and later file-read role both match.
// A user can log the path used for auth setup; any missing or changed proof keeps the warning.
func isConfiguredPasswordFilePath(file *ast.File, body *ast.BlockStmt, args []ast.Expr, index int, osPackages map[string]bool) bool {
	// Only the observed structured key can identify the following value as a password-file path.
	if index == 0 {
		return false
	}
	key, ok := stringLiteral(args[index-1])
	if !ok || key != "password_file_path" {
		return false
	}
	path, ok := args[index].(*ast.SelectorExpr)
	if !ok || path.Sel.Name != "passwordFilePath" {
		return false
	}
	receiver, ok := path.X.(*ast.Ident)
	if !ok || receiver.Obj == nil {
		return false
	}
	methodType := locallyConstructedMethodType(body, receiver.Obj)
	// A different or reassigned receiver could hold a secret under the same field name.
	if methodType == "" || !fieldComesFromPathConfig(file, body, receiver.Obj) {
		return false
	}
	return methodReadsPasswordFile(file, methodType, osPackages)
}

// locallyConstructedMethodType returns the one local struct type created for the logged receiver.
// A second assignment leaves its value unclear to a user reviewing the log record.
func locallyConstructedMethodType(body *ast.BlockStmt, receiver *ast.Object) string {
	methodType := ""
	writes := 0
	seededWithPassword := false
	ast.Inspect(body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		// Count every reassignment so a later object cannot inherit the earlier path proof.
		for index, target := range assignment.Lhs {
			name, ok := target.(*ast.Ident)
			if !ok || name.Obj != receiver {
				continue
			}
			writes++
			// The receiver starts as a fresh method object, as in Vault's auth setup.
			if index >= len(assignment.Rhs) {
				continue
			}
			address, ok := assignment.Rhs[index].(*ast.UnaryExpr)
			if !ok || address.Op.String() != "&" {
				continue
			}
			literal, ok := address.X.(*ast.CompositeLit)
			if !ok {
				continue
			}
			// A constructor that already holds a password can reach the log if later config assignment is conditional.
			for _, element := range literal.Elts {
				field, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				name, ok := field.Key.(*ast.Ident)
				if ok && name.Name == "passwordFilePath" {
					seededWithPassword = true
				}
			}
			kind, ok := literal.Type.(*ast.Ident)
			if ok {
				methodType = kind.Name
			}
		}
		return true
	})
	// A missing constructor or multiple receiver writes cannot prove the logged field's origin.
	if writes != 1 || seededWithPassword {
		return ""
	}
	return methodType
}

// fieldComesFromPathConfig requires the only field write to unwrap the exact path configuration entry.
// This keeps a password or a later overwrite from borrowing the path's safe role.
func fieldComesFromPathConfig(file *ast.File, body *ast.BlockStmt, receiver *ast.Object) bool {
	writes := 0
	var rawPath *ast.Object
	ast.Inspect(file, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		// Any same-named field write in this file makes the path proof ambiguous.
		for index, target := range assignment.Lhs {
			field, ok := target.(*ast.SelectorExpr)
			if !ok || field.Sel.Name != "passwordFilePath" {
				continue
			}
			writes++
			owner, ok := field.X.(*ast.Ident)
			if !ok || owner.Obj != receiver || index >= len(assignment.Rhs) {
				continue
			}
			assertion, ok := assignment.Rhs[index].(*ast.TypeAssertExpr)
			if !ok {
				continue
			}
			kind, ok := assertion.Type.(*ast.Ident)
			if !ok || kind.Name != "string" {
				continue
			}
			alias, ok := assertion.X.(*ast.Ident)
			if ok {
				rawPath = alias.Obj
			}
		}
		return true
	})
	// A configured path needs one field write and one resolvable local source value.
	if writes != 1 || rawPath == nil {
		return false
	}
	return aliasComesFromPathConfig(body, rawPath)
}

// aliasComesFromPathConfig checks the raw config lookup that a user supplied during auth setup.
// A secret from another key, request or environment cannot satisfy this exact source proof.
func aliasComesFromPathConfig(body *ast.BlockStmt, alias *ast.Object) bool {
	writes := 0
	fromPathKey := false
	ast.Inspect(body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		// An alias overwritten before logging no longer carries a proven path value.
		for index, target := range assignment.Lhs {
			name, ok := target.(*ast.Ident)
			if !ok || name.Obj != alias {
				continue
			}
			writes++
			if index >= len(assignment.Rhs) {
				continue
			}
			lookup, ok := assignment.Rhs[index].(*ast.IndexExpr)
			if !ok {
				continue
			}
			key, ok := stringLiteral(lookup.Index)
			if !ok || key != "password_file_path" {
				continue
			}
			config, ok := lookup.X.(*ast.SelectorExpr)
			if !ok || config.Sel.Name != "Config" {
				continue
			}
			owner, ok := config.X.(*ast.Ident)
			fromPathKey = ok && owner.Obj != nil
		}
		return true
	})
	return writes == 1 && fromPathKey
}

// methodReadsPasswordFile requires the same struct type to pass its field to the imported os.ReadFile.
// The bytes returned by that call remain a separate secret value if they are logged.
func methodReadsPasswordFile(file *ast.File, methodType string, osPackages map[string]bool) bool {
	// Check methods declared in this file; an unrelated receiver cannot prove the path's role.
	for _, declaration := range file.Decls {
		method, ok := declaration.(*ast.FuncDecl)
		if !ok || method.Recv == nil || len(method.Recv.List) != 1 || method.Body == nil {
			continue
		}
		receiver := method.Recv.List[0]
		pointer, ok := receiver.Type.(*ast.StarExpr)
		if !ok || len(receiver.Names) != 1 {
			continue
		}
		kind, ok := pointer.X.(*ast.Ident)
		if !ok || kind.Name != methodType {
			continue
		}
		found := false
		ast.Inspect(method.Body, func(node ast.Node) bool {
			// Once this method proves the path role, later reads on another receiver cannot undo it.
			if found {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "ReadFile" {
				return true
			}
			packageName, ok := selector.X.(*ast.Ident)
			// A locally shadowed os name cannot establish a real filesystem read.
			if !ok || packageName.Obj != nil || !osPackages[packageName.Name] {
				return true
			}
			path, ok := call.Args[0].(*ast.SelectorExpr)
			if !ok || path.Sel.Name != "passwordFilePath" {
				return true
			}
			owner, ok := path.X.(*ast.Ident)
			found = ok && owner.Obj == receiver.Names[0].Obj
			return !found
		})
		// The path was used to read the password file, matching the user's configuration role.
		if found {
			return true
		}
	}
	return false
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

// isRedactionCall identifies a masking or hashing wrapper so its value stays quiet in scan results.
// Only that wrapped value is skipped; a raw password beside a hash still warns.
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
