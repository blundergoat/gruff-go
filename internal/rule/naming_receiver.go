// Package rule defines gruff-go's rule registry and analysers.
// This file implements the naming.receiver-consistency rule.
package rule

import (
	"fmt"
	"go/ast"
	"path"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// receiverMethod captures one method's receiver name and pointer/value form for cross-method comparison.
type receiverMethod struct {
	unit       parser.Unit
	function   *ast.FuncDecl
	packageDir string
	typeName   string
	name       string
	form       string
}

// receiverGroup aggregates the methods declared on a single named type plus tallies of receiver names and forms.
type receiverGroup struct {
	methods []receiverMethod
	names   map[string]int
	forms   map[string]int
}

// ReceiverConsistencyRule flags inconsistent method receiver names or forms.
type ReceiverConsistencyRule struct {
	// AllowMixed lists receiver type names that may deliberately mix pointer and value forms without firing.
	AllowMixed []string
	// InspectGroup selects which axis the rule checks: "name", "pointer", or "both".
	InspectGroup string
}

// Definition declares the naming.receiver-consistency rule that flags methods on one type that mix receiver names or pointer/value forms.
func (r ReceiverConsistencyRule) Definition() Definition {
	return Definition{
		ID:             "naming.receiver-consistency",
		Title:          "Receiver consistency",
		Description:    "Flags methods on the same type that use inconsistent receiver names or pointer/value forms.",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Tags:           []string{"go-style", "naming", "opt-in"},
		Options:        map[string]any{"allowMixed": []string{}, "inspectGroup": "both"},
		Remediation:    "Use one receiver name and one receiver pointer/value form per type, or explicitly allow a deliberate mixed form.",
	}
}

// AnalyzeProject scans every method across the project for receiver name or form inconsistencies.
func (r ReceiverConsistencyRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	groups := collectReceiverGroups(units)
	inspectName, inspectPointer := receiverInspectModes(r.InspectGroup)
	allowMixed := exactStringSet(r.AllowMixed)
	findings := receiverConsistencyFindings(groups, inspectName, inspectPointer, allowMixed)
	slices.SortFunc(findings, CompareFindings)
	return findings
}

// collectReceiverGroups buckets methods across units by their receiver type,
// scoped per package directory so two unrelated types named e.g. "Service" in
// different packages do not pollute each other's dominant receiver tally.
func collectReceiverGroups(units []parser.Unit) map[string]*receiverGroup {
	groups := map[string]*receiverGroup{}
	for _, unit := range units {
		if unit.AST == nil || unit.FileSet == nil {
			continue
		}
		for _, decl := range unit.AST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			method, ok := receiverMethodFromFunc(unit, fn)
			if !ok {
				continue
			}
			key := receiverGroupKey(method.packageDir, method.typeName)
			group := groups[key]
			if group == nil {
				group = &receiverGroup{names: map[string]int{}, forms: map[string]int{}}
				groups[key] = group
			}
			group.methods = append(group.methods, method)
			if method.name != "" {
				group.names[method.name]++
			}
			group.forms[method.form]++
		}
	}
	return groups
}

// receiverGroupKey produces the per-package, per-type bucket key. Package dir
// is preserved so the joined key cannot collide across directories whose names
// happen to differ only by a literal "\x00".
func receiverGroupKey(packageDir, typeName string) string {
	return packageDir + "\x00" + typeName
}

// receiverConsistencyFindings emits findings for every receiver group whose conventions diverge.
func receiverConsistencyFindings(groups map[string]*receiverGroup, inspectName bool, inspectPointer bool, allowMixed map[string]bool) []finding.Finding {
	findings := []finding.Finding{}
	for _, group := range groups {
		if len(group.methods) == 0 {
			continue
		}
		typeName := group.methods[0].typeName
		findings = append(findings, receiverGroupFindings(typeName, group, inspectName, inspectPointer, allowMixed)...)
	}
	return findings
}

// receiverGroupFindings reports each method in a group whose receiver name or form does not match the dominant choice.
func receiverGroupFindings(typeName string, group *receiverGroup, inspectName bool, inspectPointer bool, allowMixed map[string]bool) []finding.Finding {
	dominantName := dominantReceiverValue(group.names)
	dominantForm := dominantReceiverValue(group.forms)
	nameMixed := inspectName && len(group.names) > 1 && dominantName != ""
	formMixed := inspectPointer && len(group.forms) > 1 && !allowMixed[typeName]
	if !nameMixed && !formMixed {
		return nil
	}
	findings := []finding.Finding{}
	for _, method := range group.methods {
		nameMismatch := nameMixed && method.name != "" && method.name != dominantName
		formMismatch := formMixed && method.form != dominantForm
		if nameMismatch || formMismatch {
			findings = append(findings, makeReceiverFinding(method, dominantName, dominantForm, nameMismatch, formMismatch))
		}
	}
	return findings
}

// receiverMethodFromFunc extracts the receiver name, type, and pointer form from a FuncDecl.
func receiverMethodFromFunc(unit parser.Unit, fn *ast.FuncDecl) (receiverMethod, bool) {
	field := fn.Recv.List[0]
	typeName, pointer := receiverType(field.Type)
	if typeName == "" {
		return receiverMethod{}, false
	}
	name := ""
	if len(field.Names) > 0 {
		name = field.Names[0].Name
	}
	form := "value"
	if pointer {
		form = "pointer"
	}
	return receiverMethod{
		unit:       unit,
		function:   fn,
		packageDir: path.Dir(unit.File.Path),
		typeName:   typeName,
		name:       name,
		form:       form,
	}, true
}

// receiverType resolves a receiver expression to its underlying type name and pointer flag.
func receiverType(expr ast.Expr) (string, bool) {
	switch item := expr.(type) {
	case *ast.Ident:
		return item.Name, false
	case *ast.StarExpr:
		name, _ := receiverType(item.X)
		return name, true
	case *ast.IndexExpr:
		return receiverType(item.X)
	case *ast.IndexListExpr:
		return receiverType(item.X)
	}
	return "", false
}

// dominantReceiverValue picks the most common value in counts, breaking ties alphabetically.
func dominantReceiverValue(counts map[string]int) string {
	type candidate struct {
		value string
		count int
	}
	best := candidate{}
	for value, count := range counts {
		if count > best.count || (count == best.count && (best.value == "" || value < best.value)) {
			best = candidate{value: value, count: count}
		}
	}
	return best.value
}

// receiverInspectModes maps the InspectGroup option to (inspectName, inspectPointer) flags.
func receiverInspectModes(input string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "name":
		return true, false
	case "pointer":
		return false, true
	default:
		return true, true
	}
}

// makeReceiverFinding constructs a Finding describing a receiver name or form mismatch.
func makeReceiverFinding(method receiverMethod, dominantName string, dominantForm string, nameMismatch bool, formMismatch bool) finding.Finding {
	position := method.unit.FileSet.Position(method.function.Name.Pos())
	reason := "receiver differs from dominant convention"
	message := fmt.Sprintf("receiver for type %q differs from dominant convention", method.typeName)
	if nameMismatch && !formMismatch {
		reason = "name"
		message = fmt.Sprintf("receiver name %q differs from dominant receiver name %q for type %q", method.name, dominantName, method.typeName)
	}
	if formMismatch && !nameMismatch {
		reason = "form"
		message = fmt.Sprintf("receiver form %q differs from dominant receiver form %q for type %q", method.form, dominantForm, method.typeName)
	}
	metadata := map[string]any{
		"type":         method.typeName,
		"receiverName": method.name,
		"receiverForm": method.form,
		"reason":       reason,
	}
	if dominantName != "" {
		metadata["dominantName"] = dominantName
	}
	if dominantForm != "" {
		metadata["dominantForm"] = dominantForm
	}
	return finding.Finding{
		Message:  message,
		File:     method.unit.File.Path,
		Location: &finding.Location{Line: position.Line, Column: position.Column},
		Symbol:   method.function.Name.Name,
		Metadata: metadata,
	}
}
