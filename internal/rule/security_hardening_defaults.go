// Package rule defines gruff-go's rule registry and analysers.
// This file implements additional parser-only security hardening checks.
package rule

import (
	"fmt"
	"go/ast"
	"strconv"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// HTTPServerNoTimeoutRule flags production HTTP servers without explicit timeout controls.
type HTTPServerNoTimeoutRule struct{}

// Definition declares the security.http-server-no-timeout rule for static server timeout evidence.
func (HTTPServerNoTimeoutRule) Definition() Definition {
	return Definition{
		ID:             "security.http-server-no-timeout",
		Title:          "HTTP server without timeout",
		Description:    "Flags production http.Server literals and ListenAndServe helpers that do not set explicit timeout controls.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"http", "security"},
		Remediation:    "Configure ReadHeaderTimeout, ReadTimeout, or WriteTimeout on http.Server and call ListenAndServe on that server value.",
	}
}

// AnalyzeUnit emits findings for production HTTP servers without local timeout evidence.
func (HTTPServerNoTimeoutRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) || hasGeneratedHeader(unit.Source) {
		return nil
	}
	httpPackages := packageImportNames(unit.AST, "net/http", "http")
	if len(httpPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
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
type PermissiveFileModeRule struct{}

// Definition declares the security.permissive-file-mode rule for literal file mode hazards.
func (PermissiveFileModeRule) Definition() Definition {
	return Definition{
		ID:             "security.permissive-file-mode",
		Title:          "Permissive file mode",
		Description:    "Flags os file and directory calls that use world-writable or overly permissive literal modes.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"filesystem", "security"},
		Remediation:    "Use the least permissive mode needed, such as 0600 for private files, 0644 for public files, or 0755 for directories.",
	}
}

// AnalyzeUnit emits findings for obvious permissive modes passed to os filesystem helpers.
func (PermissiveFileModeRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) || hasGeneratedHeader(unit.Source) {
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
		// The kernel ignores the mode argument unless the flags include O_CREATE,
		// so flagging "permissive" modes on a read-only OpenFile is a false positive.
		// Only skip when we can statically prove O_CREATE is absent; opaque flag
		// expressions fall through to the existing mode check to avoid false negatives.
		if shape.creationFlagsIndex >= 0 && shape.creationFlagsIndex < len(call.Args) {
			if hasCreate, decoded := openFileFlagsCanCreate(call.Args[shape.creationFlagsIndex], osPackages); decoded && !hasCreate {
				return true
			}
		}
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
func isHTTPServerLiteral(literal *ast.CompositeLit, httpPackages map[string]bool) bool {
	selector, ok := literal.Type.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Server" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && httpPackages[receiver.Name]
}

// httpServerLiteralHasTimeout reports whether a server literal sets any core timeout field.
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

// isHTTPListenAndServeHelper reports whether call invokes net/http's direct server helper.
func isHTTPListenAndServeHelper(call *ast.CallExpr, httpPackages map[string]bool) bool {
	return selectorCallMatches(call, httpPackages, "ListenAndServe") ||
		selectorCallMatches(call, httpPackages, "ListenAndServeTLS")
}

// fileModeCallInfo captures the shape of an os filesystem call that takes a mode argument.
// creationFlagsIndex is the position of a flags argument whose O_CREATE bit gates whether
// the OS applies the mode at all; it is -1 when the mode is always honoured.
type fileModeCallInfo struct {
	operation          string
	modeIndex          int
	creationFlagsIndex int
	fileCreation       bool
}

// fileModeCallShape returns the call name and mode argument offset for os helpers with file modes.
func fileModeCallShape(call *ast.CallExpr, osPackages map[string]bool) (fileModeCallInfo, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return fileModeCallInfo{}, false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !osPackages[receiver.Name] {
		return fileModeCallInfo{}, false
	}
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

// openFileFlagsCanCreate walks an os.OpenFile flags expression (typically an OR-chain
// of os.O_* selectors) and reports whether O_CREATE appears. The second return value is
// true only when every leaf in the expression is a recognisable os.O_* selector; an
// unrecognised leaf (variable, function call, foreign package) flips decoded to false
// so the caller falls back to assuming creation is possible.
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
func permissiveModeReason(mode int64, fileCreation bool) (string, bool) {
	if mode&0o002 != 0 {
		return fmt.Sprintf("world-writable (%#o)", mode), true
	}
	if fileCreation && mode&0o001 != 0 {
		return fmt.Sprintf("world-executable file (%#o)", mode), true
	}
	return "", false
}
