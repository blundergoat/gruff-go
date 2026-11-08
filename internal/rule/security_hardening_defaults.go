// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements additional parser-only security hardening checks: security.http-server-no-timeout and security.permissive-file-mode.
// A timeout assigned after the http.Server literal still draws a finding, and a mode held in a named constant draws none.
package rule

import (
	"fmt"
	"go/ast"
	"strconv"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// HTTPServerNoTimeoutRule flags production HTTP servers without explicit timeout controls.
//
// Its findings carry the rule ID security.http-server-no-timeout with advisory severity by default, and the rule is enabled by default.
// Setting ReadHeaderTimeout, ReadTimeout, or WriteTimeout in an http.Server literal clears that literal's finding.
// ListenAndServe on a server value draws no finding unless the variable shares a net/http import name, such as one named http.
type HTTPServerNoTimeoutRule struct{}

// Definition declares the security.http-server-no-timeout rule for static server timeout evidence.
// It returns the same Definition every call: security pillar, advisory severity, high confidence, enabled by default.
func (HTTPServerNoTimeoutRule) Definition() Definition {
	return Definition{
		ID:             "security.http-server-no-timeout",
		Title:          "HTTP server without timeout",
		Description:    "Flags production http.Server literals and ListenAndServe helpers that do not set explicit timeout controls.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"http", "security"},
		Remediation:    "Configure ReadHeaderTimeout, ReadTimeout, or WriteTimeout on http.Server and call ListenAndServe on that server value.",
	}
}

// AnalyzeUnit emits findings for production HTTP servers without local timeout evidence.
//
// unit supplies the parsed AST, file set, and path; ctx is only passed to shouldSkipGeneratedUnit for the generated-code skip.
// It returns one finding for each http.Server literal that sets none of ReadHeaderTimeout, ReadTimeout, or WriteTimeout.
// Each ListenAndServe or ListenAndServeTLS call made through a net/http import name adds one finding as well.
//
// A literal's finding points at its http.Server type name, and a helper's finding points at the start of the call.
// The result is nil when unit has no AST or file set, is not a production path, is skipped as generated, or has no usable net/http import name.
// Otherwise it is empty, not nil, when nothing is flagged.
func (HTTPServerNoTimeoutRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) || shouldSkipGeneratedUnit(unit, ctx) {
		return nil
	}
	httpPackages := packageImportNames(unit.AST, "net/http", "http")
	if len(httpPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		// A timeout assigned after the literal, such as srv.ReadTimeout = d on a later line, is not seen, so that server is still flagged.
		if literal, ok := node.(*ast.CompositeLit); ok && isHTTPServerLiteral(literal, httpPackages) && !httpServerLiteralHasTimeout(literal) {
			position := unit.FileSet.Position(literal.Type.Pos())
			findings = append(findings, finding.Finding{
				Message:  "http.Server starts without explicit timeout controls",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Metadata: map[string]any{"type": "http.Server"},
			})
			return true
		}
		// A ListenAndServe on a server value is skipped unless the variable is named like a net/http import, such as http, which still matches.
		call, ok := node.(*ast.CallExpr)
		if !ok || !isHTTPListenAndServeHelper(call, httpPackages) {
			return true
		}
		position := unit.FileSet.Position(call.Pos())
		findings = append(findings, finding.Finding{
			Message:  "http server helper starts without explicit timeout controls",
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Metadata: map[string]any{"call": formatExpr(call.Fun)},
		})
		return true
	})
	return findings
}

// PermissiveFileModeRule flags world-writable or executable file modes in os filesystem calls.
//
// Its findings carry the rule ID security.permissive-file-mode with advisory severity by default, and the rule is enabled by default.
// Only integer literal modes and ModePerm are read, so a mode held in a named constant or variable draws no finding.
type PermissiveFileModeRule struct{}

// Definition declares the security.permissive-file-mode rule for literal file mode hazards.
// It returns the same Definition every call: security pillar, advisory severity, high confidence, enabled by default.
func (PermissiveFileModeRule) Definition() Definition {
	return Definition{
		ID:             "security.permissive-file-mode",
		Title:          "Permissive file mode",
		Description:    "Flags os file and directory calls that use world-writable or overly permissive literal modes.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"filesystem", "security"},
		Remediation:    "Use the least permissive mode needed, such as 0600 for private files, 0644 for public files, or 0755 for directories.",
	}
}

// AnalyzeUnit emits findings for obvious permissive modes passed to os filesystem helpers.
//
// unit supplies the parsed AST, file set, and path; ctx is only passed to shouldSkipGeneratedUnit for the generated-code skip.
// It returns one finding per os.OpenFile, os.Chmod, os.Mkdir, or os.MkdirAll call whose literal or ModePerm mode permissiveModeReason flags.
// OpenFile calls whose flags decode fully to os.O_* selectors without O_CREATE are skipped, because the mode is then ignored.
//
// Each finding points at the mode argument, and its metadata holds the call name, the mode as written, and the reason.
// The result is nil when unit has no AST or file set, is not a production code path, is skipped as generated, or does not import os.
func (PermissiveFileModeRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) || shouldSkipGeneratedUnit(unit, ctx) {
		return nil
	}
	osPackages := packageImportNames(unit.AST, "os", "os")
	fsPackages := packageImportNames(unit.AST, "io/fs", "fs")
	if len(osPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		shape, ok := fileModeCallShape(call, osPackages)
		if !ok || len(call.Args) <= shape.modeIndex {
			return true
		}
		// The OS ignores the mode unless the flags include O_CREATE, so os.OpenFile(p, os.O_RDONLY, 0o777) draws no finding.
		// Flags held in a variable or built by a call cannot be decoded, so their mode is still checked rather than risk a missed finding.
		if shape.creationFlagsIndex >= 0 && shape.creationFlagsIndex < len(call.Args) {
			if hasCreate, decoded := openFileFlagsCanCreate(call.Args[shape.creationFlagsIndex], osPackages); decoded && !hasCreate {
				return true
			}
		}
		// A mode written as a named constant or a conversion such as os.FileMode(0o777) is not read, so that call draws no finding.
		mode, rendered, ok := literalFileMode(call.Args[shape.modeIndex], osPackages, fsPackages)
		if !ok {
			return true
		}
		reason, ok := permissiveModeReason(mode, shape.fileCreation)
		if !ok {
			return true
		}
		position := unit.FileSet.Position(call.Args[shape.modeIndex].Pos())
		findings = append(findings, finding.Finding{
			Message:  "filesystem call uses a permissive file mode",
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Metadata: map[string]any{
				"call":   shape.operation,
				"mode":   rendered,
				"reason": reason,
			},
		})
		return true
	})
	return findings
}

// isHTTPServerLiteral reports whether literal has type net/http.Server.
// httpPackages holds the file's local names for net/http; a Server type on any other package name, or an unqualified type, reports false.
func isHTTPServerLiteral(literal *ast.CompositeLit, httpPackages map[string]bool) bool {
	selector, ok := literal.Type.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Server" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && httpPackages[receiver.Name]
}

// httpServerLiteralHasTimeout reports whether literal sets ReadHeaderTimeout, ReadTimeout, or WriteTimeout by field name.
//
// literal is an http.Server composite literal; one with only IdleTimeout, or with positional fields, reports false and is flagged.
// Any value counts, so ReadTimeout: 0, which disables the timeout, still clears the finding.
func httpServerLiteralHasTimeout(literal *ast.CompositeLit) bool {
	for _, element := range literal.Elts {
		keyValue, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := keyValue.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "ReadHeaderTimeout", "ReadTimeout", "WriteTimeout":
			return true
		}
	}
	return false
}

// isHTTPListenAndServeHelper reports whether call selects ListenAndServe or ListenAndServeTLS from a net/http import name.
// httpPackages holds the file's local names for net/http; the receiver is matched by spelling, so a variable named like the import also counts.
func isHTTPListenAndServeHelper(call *ast.CallExpr, httpPackages map[string]bool) bool {
	return selectorCallMatches(call, httpPackages, "ListenAndServe") ||
		selectorCallMatches(call, httpPackages, "ListenAndServeTLS")
}

// fileModeCallInfo captures the shape of an os filesystem call that takes a mode argument.
//
// operation is the call with the file's own os import name, such as os.Chmod, and becomes the finding's call metadata.
// modeIndex is the mode argument's position; creationFlagsIndex is the flags argument whose O_CREATE bit gates whether the OS applies the mode.
// creationFlagsIndex is -1 when the mode is always honoured, and fileCreation marks os.OpenFile, where a world-execute bit is also reported.
type fileModeCallInfo struct {
	operation          string
	modeIndex          int
	creationFlagsIndex int
	fileCreation       bool
}

// fileModeCallShape returns the call name and mode argument offset for os helpers with file modes.
//
// osPackages holds the file's local import names for os, and call must select OpenFile, Chmod, Mkdir, or MkdirAll from one of them.
// Any other call gives a zero fileModeCallInfo and false; only OpenFile has a flags index and counts as file creation.
func fileModeCallShape(call *ast.CallExpr, osPackages map[string]bool) (fileModeCallInfo, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return fileModeCallInfo{}, false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !osPackages[receiver.Name] {
		return fileModeCallInfo{}, false
	}
	// os.WriteFile also takes a mode, but this rule does not check it and produces no finding for that call.
	switch selector.Sel.Name {
	case "OpenFile":
		return fileModeCallInfo{operation: receiver.Name + ".OpenFile", modeIndex: 2, creationFlagsIndex: 1, fileCreation: true}, true
	case "Chmod":
		return fileModeCallInfo{operation: receiver.Name + ".Chmod", modeIndex: 1, creationFlagsIndex: -1, fileCreation: false}, true
	case "Mkdir", "MkdirAll":
		return fileModeCallInfo{operation: receiver.Name + "." + selector.Sel.Name, modeIndex: 1, creationFlagsIndex: -1, fileCreation: false}, true
	default:
		return fileModeCallInfo{}, false
	}
}

// openFileFlagsCanCreate walks an os.OpenFile flags expression, usually an OR-chain of os.O_* selectors, and reports whether O_CREATE appears.
//
// expr is the flags argument: parentheses are unwrapped and | operands are walked, while any other operator leaves both results false.
// osPackages holds the file's local import names for os; a selector on another name, or one whose name lacks the O_ prefix, is undecoded.
//
// It returns hasCreate true when an O_CREATE leaf is present, and decoded true only when every leaf is an os.O_* selector.
// A variable, number, function call, or foreign package leaf gives decoded false, and the caller then assumes the file may be created.
func openFileFlagsCanCreate(expr ast.Expr, osPackages map[string]bool) (hasCreate, decoded bool) {
	switch node := expr.(type) {
	case *ast.ParenExpr:
		return openFileFlagsCanCreate(node.X, osPackages)
	case *ast.BinaryExpr:
		if node.Op.String() != "|" {
			return false, false
		}
		xCreate, xDecoded := openFileFlagsCanCreate(node.X, osPackages)
		yCreate, yDecoded := openFileFlagsCanCreate(node.Y, osPackages)
		return xCreate || yCreate, xDecoded && yDecoded
	case *ast.SelectorExpr:
		receiver, ok := node.X.(*ast.Ident)
		if !ok || !osPackages[receiver.Name] {
			return false, false
		}
		if len(node.Sel.Name) < 2 || node.Sel.Name[:2] != "O_" {
			return false, false
		}
		return node.Sel.Name == "O_CREATE", true
	}
	return false, false
}

// literalFileMode extracts a literal or ModePerm value from an expression.
//
// expr is the mode argument; osPackages and fsPackages hold the local import names for os and io/fs, whose ModePerm counts as 0o777.
// It returns the numeric mode, its source spelling, and true when expr is such a ModePerm or an integer literal that strconv.ParseInt accepts.
// Any other expression, such as a named constant or a conversion, yields 0, an empty string, and false.
func literalFileMode(expr ast.Expr, osPackages, fsPackages map[string]bool) (int64, string, bool) {
	if selector, ok := expr.(*ast.SelectorExpr); ok && selector.Sel.Name == "ModePerm" {
		receiver, ok := selector.X.(*ast.Ident)
		if ok && (osPackages[receiver.Name] || fsPackages[receiver.Name]) {
			return 0o777, formatExpr(expr), true
		}
	}
	literal, ok := expr.(*ast.BasicLit)
	if !ok {
		return 0, "", false
	}
	value, err := strconv.ParseInt(literal.Value, 0, 64)
	if err != nil {
		return 0, "", false
	}
	return value, literal.Value, true
}

// permissiveModeReason classifies world-writable modes and executable file-creation modes.
//
// mode is the numeric permission; fileCreation marks calls that create files, where the world-execute bit also counts.
// It returns a world-writable or world-executable file reason with the mode in octal, and true; otherwise an empty string and false.
func permissiveModeReason(mode int64, fileCreation bool) (string, bool) {
	// Any world-write bit is reported for every checked call, including os.MkdirAll(dir, 0o777), because the process umask is not known here.
	if mode&0o002 != 0 {
		return fmt.Sprintf("world-writable (%#o)", mode), true
	}
	// Only os.OpenFile sets fileCreation, so os.Mkdir(dir, 0o755) stays clean while a file created with 0o755 is reported.
	if fileCreation && mode&0o001 != 0 {
		return fmt.Sprintf("world-executable file (%#o)", mode), true
	}
	return "", false
}
