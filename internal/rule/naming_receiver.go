// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements the naming.receiver-consistency rule, which is off by default and compares methods across the whole project.
// It flags a method whose receiver name or pointer/value form differs from the most common choice for its type in the same directory.
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
//
// An empty AllowMixed exempts no type, and an empty InspectGroup checks both receiver names and pointer/value forms.
type ReceiverConsistencyRule struct {
	// AllowMixed lists receiver type names that may deliberately mix pointer and value forms without firing.
	AllowMixed []string
	// InspectGroup selects which axis the rule checks: "name", "pointer", or "both"; any other value, a typo included, checks both.
	InspectGroup string
}

// Definition declares the naming.receiver-consistency rule that flags methods on one type that mix receiver names or pointer/value forms.
// It returns the definition of an advisory parser rule that is off by default, with allowMixed empty and inspectGroup both as option defaults.
func (r ReceiverConsistencyRule) Definition() Definition {
	return Definition{
		ID:             "naming.receiver-consistency",
		Title:          "Receiver consistency",
		Description:    "Flags methods on the same type that use inconsistent receiver names or pointer/value forms.",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Tags:           []string{"go-style", "naming"},
		Options:        map[string]any{"allowMixed": []string{}, "inspectGroup": "both"},
		Remediation:    "Use one receiver name and one receiver pointer/value form per type, or explicitly allow a deliberate mixed form.",
	}
}

// AnalyzeProject scans every method across the project for receiver name or form inconsistencies.
//
// units are the parsed files whose methods are grouped by package directory and receiver type, then checked per InspectGroup and AllowMixed.
// It returns the mismatch findings sorted by CompareFindings, or an empty slice when every group is consistent.
func (r ReceiverConsistencyRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	groups := collectReceiverGroups(units)
	inspectName, inspectPointer := receiverInspectModes(r.InspectGroup)
	allowMixed := exactStringSet(r.AllowMixed)
	findings := receiverConsistencyFindings(groups, inspectName, inspectPointer, allowMixed)
	slices.SortFunc(findings, CompareFindings)
	return findings
}

// collectReceiverGroups buckets methods across units by receiver type, scoped per package directory.
//
// Two unrelated types named Service in different directories therefore never pollute each other's dominant receiver tally.
// No test-file or generated-file filter is applied here, so every such unit passed in counts toward the tally.
//
// It returns a map keyed by receiverGroupKey whose groups tally named receivers and forms; units without an AST or file set are skipped.
// Methods whose receiver type cannot be resolved are dropped, and the map is empty but non-nil when no methods remain.
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
			// An unnamed receiver, as in func (T) M(), skips the name tally and is never flagged for its name, only for its form.
			if method.name != "" {
				group.names[method.name]++
			}
			group.forms[method.form]++
		}
	}
	return groups
}

// receiverGroupKey produces the per-package, per-type bucket key.
//
// packageDir is the method file's directory and typeName the receiver's base type name; it returns packageDir, a NUL byte, then typeName.
// Neither a path nor a Go identifier can hold a NUL byte, so two different directory and type pairs never join to the same key.
func receiverGroupKey(packageDir, typeName string) string {
	return packageDir + "\x00" + typeName
}

// receiverConsistencyFindings emits findings for every receiver group whose conventions diverge.
//
// groups holds the receiver groups; inspectName and inspectPointer pick the checked axes, and allowMixed names types exempt from form checks.
// It returns every group's findings unsorted, in map iteration order, or an empty slice when no group diverges.
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

// receiverGroupFindings reports methods differing from the dominant receiver name or form, exempting unnamed receivers from name checks.
//
// typeName is the receiver type looked up in allowMixed to exempt form checks; group holds the methods and their name and form tallies.
// inspectName and inspectPointer enable the name and form checks, and the result is nil when neither axis is mixed.
//
// allowMixed is keyed by the bare type name, so listing Service exempts every Service type in every directory.
func receiverGroupFindings(typeName string, group *receiverGroup, inspectName bool, inspectPointer bool, allowMixed map[string]bool) []finding.Finding {
	// On a tie the lexically smaller value wins, so between one r and one s receiver the s method is flagged, and pointer beats value.
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
//
// unit supplies the file path whose directory scopes the method, and fn must declare a receiver, since its first field is read unchecked.
// It returns the method record and true, or a zero record and false when the receiver type is not a plain, pointer or generic named type.
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
//
// expr is a receiver field's type; it returns the base type name, type arguments stripped, and true only when a star wraps it.
// Any other form gives an empty name and false, or an empty name and true under a star.
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
// It returns the value with the highest count, the lexically smallest on a tie, or an empty string when counts is empty.
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
// inspectGroup is trimmed and lowercased; it returns inspectName alone for name, inspectPointer alone for pointer, and both otherwise.
func receiverInspectModes(inspectGroup string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(inspectGroup)) {
	case "name":
		return true, false
	case "pointer":
		return false, true
	default:
		return true, true
	}
}

// makeReceiverFinding constructs a Finding describing a receiver name or form mismatch.
//
// method places the finding at its function name; dominantName and dominantForm are the group's most frequent values, ties broken lexically.
// nameMismatch and formMismatch pick the reason, name or form when only one is set, and a generic convention message otherwise.
//
// It returns the finding with the method's file, position and function symbol, plus type, receiver name, form and reason metadata.
// Non-empty dominantName and dominantForm values are added to that metadata too.
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
