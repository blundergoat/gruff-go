// Package baseline reads, writes, applies, and migrates the reviewed-finding baseline a user keeps beside their code.
//
// A developer runs gruff-go baseline --out gruff-baseline.json after reviewing a scan, then gruff-go analyse --baseline gruff-baseline.json later.
// Each current finding is new, unchanged, collision, or not eligible; reviewed surplus counts as resolved unless its identity collided.
// Matching uses line-free identities and reviewed counts, so code movement keeps a match and surplus occurrences stay visible.
package baseline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// SchemaVersion identifies the on-disk baseline schema accepted by this package.
const SchemaVersion = "gruff.baseline.v3"

// LegacySchemaVersion is the 0.5 schema an explicit migration reads and nothing else does.
//
// Version 0.5 never reads v3 and v3 never writes 0.5; a dual writer would keep two identity rules alive and defer the break forever.
const LegacySchemaVersion = "gruff-go.baseline.v0.1"

// sensitiveReason is stored beside the sensitive counts so a reader of the file
// learns why no sensitive occurrence has an entry.
const sensitiveReason = "Sensitive findings are never baseline-eligible; a stored identity would be a durable suppression of a secret."

// identityPattern is the sixteen lowercase hex characters the identity contract yields.
var identityPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// toolLanguages are the five ports a baseline may name; a typo cannot invent a sixth.
var toolLanguages = []string{"go", "php", "py", "rs", "ts"}

// Status is one of the classifications a current finding receives against a baseline.
type Status string

const (
	// StatusNew marks a finding whose identity is absent from the baseline or exceeds its recorded count.
	//
	// Never suppressed: this is the sibling a reviewed occurrence must not hide.
	StatusNew Status = "new"
	// StatusUnchanged marks a finding within its identity's reviewed count.
	StatusUnchanged Status = "unchanged"
	// StatusCollision marks findings on distinct declarations that share one
	// identity, so the identity cannot separate them. Never suppressed.
	StatusCollision Status = "collision"
	// StatusNotEligible marks a finding with no identity: a sensitive one, or one whose symbol carries the ordinal separator.
	//
	// It has no entry and no suppression whatever the baseline says.
	StatusNotEligible Status = "notEligible"
)

// File is the JSON document containing findings a user has reviewed, in the
// shape contracts/core/baseline.v3.json ratifies.
type File struct {
	// SchemaVersion identifies the on-disk baseline schema; must match SchemaVersion.
	SchemaVersion string `json:"schemaVersion"`
	// ToolLanguage names the one port whose findings this file records. A run by
	// another port refuses the file rather than reporting every entry resolved.
	ToolLanguage string `json:"toolLanguage"`
	// GeneratedAt is an RFC 3339 timestamp for human review only; it never enters identity or matching.
	// Regenerating with no code change keeps the occurrences array unchanged, but this timestamp can still differ.
	GeneratedAt string `json:"generatedAt"`
	// Occurrences lists reviewed ordinary occurrences, ascending by identity.
	Occurrences []Occurrence `json:"occurrences"`
	// Sensitive records non-identifying counts for findings that are never eligible.
	Sensitive SensitiveSummary `json:"sensitive"`
}

// Occurrence is one reviewed identity and how many occurrences of it were reviewed.
//
// Count-aware matching, not set membership, is what keeps one reviewed occurrence from covering a second one on the same declaration.
type Occurrence struct {
	// Identity is the sixteen-hex matching key; Count limits how many current occurrences the entry can cover.
	Identity string `json:"identity"`
	// Count is how many occurrences of Identity were reviewed.
	Count int `json:"count"`
	// RuleID is descriptive, so a human can read the file; it never matches.
	RuleID string `json:"ruleId,omitempty"`
	// Path is descriptive, same rule as RuleID.
	Path string `json:"path,omitempty"`
	// Subject is the identity's own subject, so a reviewer sees what was reviewed.
	Subject string `json:"subject,omitempty"`
}

// SensitiveSummary holds the counts and status the file keeps for sensitive findings instead of occurrence entries.
//
// It carries no identity, path, line, message, or symbol, because each of those is an occurrence-level record.
type SensitiveSummary struct {
	// Eligible is always false; it is stored rather than assumed so a file
	// claiming otherwise fails loudly instead of being trusted.
	Eligible bool `json:"eligible"`
	// Reason explains to a reader why sensitive findings have no entries.
	Reason string `json:"reason"`
	// Counts is the audit view of how many sensitive findings the run had.
	Counts SensitiveCounts `json:"counts"`
}

// SensitiveCounts tallies sensitive findings by rule and in total.
type SensitiveCounts struct {
	// Total is the number of sensitive findings in the recorded run.
	Total int `json:"total"`
	// ByRule maps each sensitive rule id to its count; Marshal writes a nil map as an empty object, though Parse can leave it nil.
	ByRule map[string]int `json:"byRule"`
}

// ResolvedEntry is a reviewed identity whose recorded count exceeds what the current run found.
//
// It is a baseline record, not a finding: it has no live line, severity, or message to render.
type ResolvedEntry struct {
	// Identity is the reviewed identity that lost occurrences.
	Identity string
	// RuleID, Path, and Subject are the entry's descriptive fields.
	RuleID  string
	Path    string
	Subject string
	// Count is how many reviewed occurrences of Identity are no longer present.
	Count int
}

// Collision is one identity that covers findings on more than one declaration in a single run.
//
// The identity contract's declaration ordinal exists to prevent this, so every finding in it is reported and none is suppressed.
type Collision struct {
	// Identity is the shared identity.
	Identity string
	// RuleID and Path locate the colliding findings.
	RuleID string
	Path   string
	// Subjects lists the distinct identity subjects that collided.
	Subjects []string
}

// ApplyResult summarises how a baseline classified one scan's findings.
//
// Findings is the gated set the exit code fails on: new, collision, and not-eligible findings in scan order.
// Applying a baseline may only ever remove unchanged ordinary findings from that set.
type ApplyResult struct {
	// Findings holds the surviving findings after baseline suppression.
	Findings []finding.Finding
	// Unchanged holds the current findings within their reviewed counts.
	Unchanged []finding.Finding
	// Resolved holds reviewed identities whose counts exceed what is present.
	Resolved []ResolvedEntry
	// Collisions holds every identity that could not separate two declarations.
	Collisions []Collision
	// Statuses holds one Status per input finding, in input order.
	Statuses []Status
	// NewFindings counts findings absent from the baseline or beyond its count.
	NewFindings int
	// UnchangedFindings counts findings the baseline suppressed.
	UnchangedFindings int
	// ResolvedFindings counts reviewed occurrences no longer present.
	ResolvedFindings int
	// CollisionFindings counts findings reported because their identity collided.
	CollisionFindings int
	// NotEligibleFindings counts the findings the baseline may not touch because they have no identity.
	NotEligibleFindings int
	// SuppressedFindings equals UnchangedFindings; retained for ADR-012 consumers.
	SuppressedFindings int
	// StaleEntries equals ResolvedFindings; retained for ADR-012 consumers.
	StaleEntries int
	// Entries is the number of occurrence entries the baseline contained.
	Entries int
}

// NewCount returns how many findings are classified new; zero can still come with collision or not-eligible findings that stay visible.
func (result ApplyResult) NewCount() int { return result.NewFindings }

// UnchangedCount returns how many current findings sit within their reviewed counts and are hidden; zero means the baseline hid nothing.
func (result ApplyResult) UnchangedCount() int { return result.UnchangedFindings }

// ResolvedCount returns how many reviewed occurrences are counted resolved; collided identities are left out, so zero means none outside them.
func (result ApplyResult) ResolvedCount() int { return result.ResolvedFindings }

// GatedCount returns how many findings the baseline left visible, the set exit codes and scores are computed over; zero means none remain.
func (result ApplyResult) GatedCount() int { return len(result.Findings) }

// FromFindings builds the baseline for the current run, stamped with the current time; sensitive findings become counts rather than entries.
//
// It returns the File that FromFindingsAt builds from currentFindings, with no occurrences when no finding has a baseline identity.
// It fails with an error when a finding's baseline identity cannot be computed.
func FromFindings(currentFindings []finding.Finding) (File, error) {
	return FromFindingsAt(currentFindings, time.Now().UTC())
}

// FromFindingsAt builds a baseline stamped with an explicit time, so tests can compare whole files.
//
// Two runs over one unchanged tree produce an identical occurrences array; only GeneratedAt follows the generatedAt argument.
// The currentFindings get symbol ordinals first; sensitive ones only add to the counts, and ones without a baseline identity are skipped.
//
// The generatedAt time is stored in RFC 3339 form, and an error is returned when a finding's identity cannot be computed.
// It returns the File with one occurrence per identity in identity order, and an empty occurrence list when no finding yields an identity.
func FromFindingsAt(currentFindings []finding.Finding, generatedAt time.Time) (File, error) {
	currentFindings = finding.EnsureSymbolOrdinals(currentFindings)
	occurrenceByIdentity := map[string]*Occurrence{}
	sensitive := SensitiveSummary{Eligible: false, Reason: sensitiveReason, Counts: SensitiveCounts{ByRule: map[string]int{}}}
	for _, currentFinding := range currentFindings {
		// A sensitive finding contributes a count and nothing that could name it.
		if !currentFinding.IsBaselineEligible() {
			sensitive.Counts.Total++
			sensitive.Counts.ByRule[currentFinding.RuleID]++
			continue
		}
		// A symbol carrying the ordinal separator has no identity to store, and it is not a secret to count.
		if !currentFinding.HasBaselineIdentity() {
			continue
		}
		identity, err := currentFinding.ComputeBaselineIdentity()
		// A finding with a rule and path but neither a symbol nor a message lands here, and the whole build fails.
		if err != nil {
			return File{}, err
		}
		if existing, ok := occurrenceByIdentity[identity]; ok {
			existing.Count++
			continue
		}
		subject, _ := currentFinding.BaselineSubject()
		occurrenceByIdentity[identity] = &Occurrence{
			Identity: identity,
			Count:    1,
			RuleID:   currentFinding.RuleID,
			Path:     currentFinding.File,
			Subject:  subject,
		}
	}
	occurrences := make([]Occurrence, 0, len(occurrenceByIdentity))
	for _, occurrence := range occurrenceByIdentity {
		occurrences = append(occurrences, *occurrence)
	}
	// Stable identity ordering keeps the occurrences array unchanged across identical scans; the GeneratedAt timestamp can still change.
	slices.SortFunc(occurrences, func(left, right Occurrence) int { return strings.Compare(left.Identity, right.Identity) })
	return File{
		SchemaVersion: SchemaVersion,
		ToolLanguage:  finding.BaselineToolLanguage,
		GeneratedAt:   generatedAt.Format(time.RFC3339),
		Occurrences:   occurrences,
		Sensitive:     sensitive,
	}, nil
}

// Load reads the baseline path selected by the user and validates its JSON.
//
// The baselinePath file is read from disk and handed to Parse.
// It returns the parsed File, or a zero File and an error when the file cannot be read or Parse rejects it.
func Load(baselinePath string) (File, error) {
	// #nosec G304 -- CLI intentionally reads an explicit user-provided baseline path.
	baselineJSON, err := os.ReadFile(baselinePath)
	// A mistyped baseline path, or a file deleted mid-run, lands here with the operating system's error.
	if err != nil {
		return File{}, err
	}
	return Parse(baselineJSON)
}

// Parse decodes strict baseline JSON and rejects anything that is not a valid v3 file.
//
// A 0.5 file is named as such and pointed at the migration command rather than misread.
// The five 0.5 shapes carried four different identity rules, and guessing at one would suppress the wrong findings.
//
// The baselineJSON bytes must decode with schemaVersion gruff.baseline.v3, no unknown fields, and a passing Validate.
// It returns the decoded File, or a zero File and an error for malformed JSON, any other schemaVersion, an unknown field, or a Validate failure.
func Parse(baselineJSON []byte) (File, error) {
	var probe struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal(baselineJSON, &probe); err != nil {
		return File{}, err
	}
	// Any schemaVersion other than v3 is refused with the migration hint, whether it is a 0.5 token, missing, mistyped or unrecognised.
	if probe.SchemaVersion != SchemaVersion {
		return File{}, fmt.Errorf("baseline schemaVersion %q is not %q; migrate it to a separate file with `gruff-go baseline --migrate-baseline <old path> --out <new path>` (the original is preserved)", probe.SchemaVersion, SchemaVersion)
	}
	var baselineFile File
	decoder := json.NewDecoder(bytes.NewReader(baselineJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&baselineFile); err != nil {
		return File{}, err
	}
	if err := Validate(baselineFile); err != nil {
		return File{}, err
	}
	return baselineFile, nil
}

// Validate checks one parsed file against the contract; every rule here is a way a stored baseline could expire, leak, or reorder.
//
// The baselineFile needs the v3 SchemaVersion, one of the five port toolLanguage values, a non-empty generatedAt, and sensitive.eligible false.
// Occurrences must have lowercase 16-hex identities in strictly ascending order with positive counts, and byRule must sum to the sensitive total.
// It returns an error describing the first violation found, and nil when the file meets the contract.
func Validate(baselineFile File) error {
	if baselineFile.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion must be %q, found %q", SchemaVersion, baselineFile.SchemaVersion)
	}
	if !slices.Contains(toolLanguages, baselineFile.ToolLanguage) {
		return fmt.Errorf("toolLanguage must name one of %s, found %q", strings.Join(toolLanguages, ", "), baselineFile.ToolLanguage)
	}
	if baselineFile.GeneratedAt == "" {
		return fmt.Errorf("generatedAt must be a non-empty timestamp")
	}
	previous := ""
	for index, occurrence := range baselineFile.Occurrences {
		if !identityPattern.MatchString(occurrence.Identity) {
			return fmt.Errorf("occurrences[%d] identity must be 16 lowercase hex characters", index)
		}
		if occurrence.Count < 1 {
			return fmt.Errorf("occurrences[%d] count must be a positive integer", index)
		}
		// A hand-merged baseline that lists one identity twice lands here; merge the counts into one entry.
		if occurrence.Identity == previous {
			return fmt.Errorf("occurrences[%d] duplicates identity %s; counts must be merged into one entry", index, occurrence.Identity)
		}
		if occurrence.Identity < previous {
			return fmt.Errorf("occurrences[%d] breaks the ascending identity order", index)
		}
		previous = occurrence.Identity
	}
	// A hand-edited file claiming sensitive findings are eligible is refused here rather than trusted.
	if baselineFile.Sensitive.Eligible {
		return fmt.Errorf("sensitive.eligible must be false")
	}
	summed := 0
	for _, count := range baselineFile.Sensitive.Counts.ByRule {
		summed += count
	}
	if summed != baselineFile.Sensitive.Counts.Total {
		return fmt.Errorf("sensitive.counts.total is %d but byRule sums to %d", baselineFile.Sensitive.Counts.Total, summed)
	}
	return nil
}

// Write saves a baseline, creating a missing file with owner-only permissions.
//
// The baselineFile is rendered by Marshal and written to baselinePath; an existing file is truncated and keeps its current mode.
// It returns an error when marshalling or writing fails, and nil once the file is written.
func Write(baselinePath string, baselineFile File) error {
	baselineJSON, err := Marshal(baselineFile)
	if err != nil {
		return err
	}
	return os.WriteFile(baselinePath, baselineJSON, 0o600)
}

// Marshal renders readable baseline JSON with a trailing newline.
//
// A nil byRule map or Occurrences list in baselineFile is written as an empty object or array, never null, with two-space indentation.
// It returns the JSON bytes, or nil and an error when encoding fails.
func Marshal(baselineFile File) ([]byte, error) {
	if baselineFile.Sensitive.Counts.ByRule == nil {
		baselineFile.Sensitive.Counts.ByRule = map[string]int{}
	}
	if baselineFile.Occurrences == nil {
		baselineFile.Occurrences = []Occurrence{}
	}
	baselineJSON, err := json.MarshalIndent(baselineFile, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(baselineJSON, '\n'), nil
}

// identityGroup collects one run's findings that share an identity.
type identityGroup struct {
	identity  string
	indexes   []int
	positions map[string]bool
	subjects  []string
	ruleID    string
	path      string
}

// identityGroups is one run's eligible findings bucketed by identity, in first-seen order.
type identityGroups struct {
	byIdentity map[string]*identityGroup
	order      []string
}

// Apply classifies one scan's current findings against a reviewed baseline.
//
// Explicit section 13 exclusions are removed before this point, so the precedence left is not-eligible, then collision, then new, then unchanged.
//
// The currentFindings are one run's findings in scan order; with none, every reviewed occurrence in baselineFile is reported resolved.
// It returns the ApplyResult holding one status per finding, the surviving and unchanged findings, resolved entries, collisions and counts.
// It fails with an error, and a zero ApplyResult, when baselineFile names another toolLanguage or a finding's identity cannot be computed.
func Apply(currentFindings []finding.Finding, baselineFile File) (ApplyResult, error) {
	// A foreign baseline is refused before matching: reporting every entry
	// resolved and every finding new would invite a destructive regenerate.
	if baselineFile.ToolLanguage != finding.BaselineToolLanguage {
		return ApplyResult{}, fmt.Errorf("baseline was written by %s and this run is %s; baselines are not shared across languages", baselineFile.ToolLanguage, finding.BaselineToolLanguage)
	}
	currentFindings = finding.EnsureSymbolOrdinals(currentFindings)
	statuses := make([]Status, len(currentFindings))
	groups, err := groupEligibleFindings(currentFindings, statuses)
	if err != nil {
		return ApplyResult{}, err
	}
	result := ApplyResult{Statuses: statuses, Entries: len(baselineFile.Occurrences)}
	collided := classifyGroups(currentFindings, groups, baselineFile, statuses, &result)
	resolveSurplus(groups, baselineFile, collided, &result)
	assembleResult(currentFindings, statuses, &result)
	return result, nil
}

// groupEligibleFindings marks findings without a baseline identity not eligible and groups the remaining findings by identity.
//
// Ineligibility is decided before any lookup, so no baseline entry can reach a secret.
// Findings without an identity are sensitive ones and ones whose symbol carries the ordinal separator.
//
// The statuses slice must have one slot per entry in currentFindings; slots for findings without an identity are set to StatusNotEligible.
// It returns the identity groups in first-seen order, empty when no finding has an identity, or an error when one cannot be computed.
func groupEligibleFindings(currentFindings []finding.Finding, statuses []Status) (identityGroups, error) {
	groups := identityGroups{byIdentity: map[string]*identityGroup{}}
	for index, currentFinding := range currentFindings {
		// A sensitive finding, or one whose symbol carries the ordinal separator, has no identity to look up.
		if !currentFinding.HasBaselineIdentity() {
			statuses[index] = StatusNotEligible
			continue
		}
		identity, err := currentFinding.ComputeBaselineIdentity()
		if err != nil {
			return identityGroups{}, err
		}
		subject, _ := currentFinding.BaselineSubject()
		group, ok := groups.byIdentity[identity]
		if !ok {
			group = &identityGroup{identity: identity, positions: map[string]bool{}, ruleID: currentFinding.RuleID, path: currentFinding.File}
			groups.byIdentity[identity] = group
			groups.order = append(groups.order, identity)
		}
		group.indexes = append(group.indexes, index)
		group.positions[declarationKey(currentFinding)] = true
		if !slices.Contains(group.subjects, subject) {
			group.subjects = append(group.subjects, subject)
		}
	}
	return groups, nil
}

// classifyGroups spends each identity's reviewed count over its occurrences and reports any identity that cannot separate two declarations.
//
// It returns the collided identities so they are not also counted resolved.
// Reviewed counts come from baselineFile, groups index currentFindings for positions, and each grouped finding gets its status in statuses.
// Each collision is appended to result, and the returned map is empty, not nil, when no identity collided.
func classifyGroups(currentFindings []finding.Finding, groups identityGroups, baselineFile File, statuses []Status, result *ApplyResult) map[string]bool {
	reviewedByIdentity := map[string]int{}
	for _, occurrence := range baselineFile.Occurrences {
		reviewedByIdentity[occurrence.Identity] += occurrence.Count
	}
	collided := map[string]bool{}
	for _, identity := range groups.order {
		group := groups.byIdentity[identity]
		// One identity over two declarations cannot separate them, so neither is
		// suppressed and the run says so by name.
		if len(group.positions) > 1 {
			collided[identity] = true
			for _, index := range group.indexes {
				statuses[index] = StatusCollision
			}
			result.Collisions = append(result.Collisions, Collision{Identity: identity, RuleID: group.ruleID, Path: group.path, Subjects: group.subjects})
			continue
		}
		// The reviewed count is spent by line then column, so two ports classify
		// the same occurrences for identical input rather than merely the same number.
		spendOrder := slices.Clone(group.indexes)
		slices.SortStableFunc(spendOrder, func(left, right int) int {
			return comparePosition(currentFindings[left], currentFindings[right])
		})
		unchanged := min(reviewedByIdentity[identity], len(spendOrder))
		for position, index := range spendOrder {
			statuses[index] = StatusNew
			if position < unchanged {
				statuses[index] = StatusUnchanged
			}
		}
	}
	return collided
}

// resolveSurplus records every reviewed occurrence the run no longer has.
//
// A collided identity is accounted for by the collision; counting it resolved as well would double-report it.
//
// Each baselineFile occurrence not in collided is compared with the size of its identity's entry in groups, zero when absent.
// Any positive surplus is appended to result as a ResolvedEntry and added to its ResolvedFindings count.
func resolveSurplus(groups identityGroups, baselineFile File, collided map[string]bool, result *ApplyResult) {
	for _, occurrence := range baselineFile.Occurrences {
		if collided[occurrence.Identity] {
			continue
		}
		present := 0
		if group, ok := groups.byIdentity[occurrence.Identity]; ok {
			present = len(group.indexes)
		}
		if surplus := occurrence.Count - present; surplus > 0 {
			result.Resolved = append(result.Resolved, ResolvedEntry{Identity: occurrence.Identity, RuleID: occurrence.RuleID, Path: occurrence.Path, Subject: occurrence.Subject, Count: surplus})
			result.ResolvedFindings += surplus
		}
	}
}

// assembleResult splits current findings in scan order, increments their status counts, and sets the suppression and stale-count aliases.
//
// It copies the ResolvedFindings that resolveSurplus already counted into StaleEntries, keeping the ADR-012 aliases in step.
// The statuses slice holds one Status per entry of currentFindings, and result receives non-nil Findings, Unchanged and Resolved lists.
func assembleResult(currentFindings []finding.Finding, statuses []Status, result *ApplyResult) {
	result.Findings = []finding.Finding{}
	result.Unchanged = []finding.Finding{}
	for index, currentFinding := range currentFindings {
		switch statuses[index] {
		case StatusUnchanged:
			result.Unchanged = append(result.Unchanged, currentFinding)
			result.UnchangedFindings++
		case StatusNew:
			result.Findings = append(result.Findings, currentFinding)
			result.NewFindings++
		case StatusCollision:
			result.Findings = append(result.Findings, currentFinding)
			result.CollisionFindings++
		case StatusNotEligible:
			result.Findings = append(result.Findings, currentFinding)
			result.NotEligibleFindings++
		}
	}
	if result.Resolved == nil {
		result.Resolved = []ResolvedEntry{}
	}
	result.SuppressedFindings = result.UnchangedFindings
	result.StaleEntries = result.ResolvedFindings
}

// declarationKey names the declaration a finding sits on, for collision detection only.
//
// Repeated findings on one declaration share a key, and symbol-less findings share one file key and are matched by count.
// Keying file-level findings by line or message would report two measurements of one file as an unresolvable collision.
//
// It returns declaration:file when currentFinding has no Symbol, and otherwise declaration: followed by its DeclarationPosition.
func declarationKey(currentFinding finding.Finding) string {
	if currentFinding.Symbol == "" {
		return "declaration:file"
	}
	return fmt.Sprintf("declaration:%d", currentFinding.DeclarationPosition)
}

// comparePosition orders two occurrences of one identity by their position in the file.
//
// Only the spend order depends on it; no position enters an identity.
// It returns a negative number when left comes before right by line then column, a positive one when after, and zero for the same position.
func comparePosition(left, right finding.Finding) int {
	leftLine, leftColumn := positionOf(left)
	rightLine, rightColumn := positionOf(right)
	if leftLine != rightLine {
		return leftLine - rightLine
	}
	return leftColumn - rightColumn
}

// positionOf returns a finding's line and column, placing an unlocated finding after every located one rather than ahead of them.
//
// A currentFinding with no Location, or a line below 1, gets the largest int as its line and column zero.
func positionOf(currentFinding finding.Finding) (int, int) {
	if currentFinding.Location == nil || currentFinding.Location.Line <= 0 {
		return int(^uint(0) >> 1), 0
	}
	return currentFinding.Location.Line, currentFinding.Location.Column
}

// DefaultFilename is the one baseline name every port writes and auto-discovers.
const DefaultFilename = "gruff-baseline.json"

// RequireOverwritableDefaultPath refuses to write a baseline over a 0.5 file at the shared default path.
//
// All five ports write and auto-discover the same filename, so without this an ordinary upgrade-then-generate
// destroys the 0.5 baseline that is the user's documented retreat path, before they know they need it.
// Regenerating v3 over v3 is not destructive, because v3 is what the tool now reads.
//
// The check is skipped when force is true or outputPath's base name is not gruff-baseline.json, and a file that cannot be read or decoded passes.
// It returns an error naming the found schemaVersion when outputPath holds JSON whose schemaVersion is not v3, and nil otherwise.
func RequireOverwritableDefaultPath(outputPath string, force bool) error {
	if force || filepath.Base(outputPath) != DefaultFilename {
		return nil
	}
	// #nosec G304 -- the caller's own explicit output path, read only to classify what is already there.
	existing, err := os.ReadFile(outputPath)
	if err != nil {
		// A read failure skips this protection, whether the output is missing, the usual first-generate case, or exists but cannot be read.
		return nil
	}
	var document struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	// A file that is not JSON, or is already v3, passes here and is overwritten.
	if err := json.Unmarshal(existing, &document); err != nil || document.SchemaVersion == SchemaVersion {
		return nil
	}
	return fmt.Errorf("%s is a %s baseline, not %s; generating over it would destroy the retreat path. Migrate it with `gruff-go baseline --migrate %s --out <new path>`, or pass --force to overwrite it",
		outputPath, document.SchemaVersion, SchemaVersion, outputPath)
}

// LegacyFile is the 0.5 on-disk shape an explicit migration reads.
type LegacyFile struct {
	// SchemaVersion must equal LegacySchemaVersion.
	SchemaVersion string `json:"schemaVersion"`
	// Findings lists the reviewed rows of the 0.5 file.
	Findings []LegacyEntry `json:"findings"`
}

// LegacyEntry is one reviewed row of a 0.5 file; its digests are read and discarded, and the identity is rebuilt from the current run.
type LegacyEntry struct {
	// RuleID is the rule whose finding was reviewed.
	RuleID string `json:"ruleId"`
	// File is the repo-relative path the reviewed finding targeted.
	File string `json:"file"`
	// Fingerprint is the 0.5 line-bearing digest, read and discarded.
	Fingerprint string `json:"fingerprint"`
	// StableIdentity is the 0.5 line-free digest, read and discarded.
	StableIdentity string `json:"stableIdentity,omitempty"`
}

// legacyRowContainers are the three keys the five 0.5 writers used for their row list.
//
// go and py wrote findings, php wrote groups, and rs and ts wrote entries.
// A file naming two of them cannot be read the same way twice, so a migration refuses it.
var legacyRowContainers = []string{"findings", "groups", "entries"}

// ParseLegacy decodes a 0.5 baseline for migration and nothing else.
//
// The baselineJSON must name at most one row container, carry no unknown field, and use the LegacySchemaVersion.
// It returns the decoded LegacyFile, or a zero LegacyFile and an error when any check fails or a row lacks its ruleId or file.
func ParseLegacy(baselineJSON []byte) (LegacyFile, error) {
	if err := requireOneRowContainer(baselineJSON); err != nil {
		return LegacyFile{}, err
	}
	var legacyFile LegacyFile
	decoder := json.NewDecoder(bytes.NewReader(baselineJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&legacyFile); err != nil {
		return LegacyFile{}, err
	}
	if legacyFile.SchemaVersion != LegacySchemaVersion {
		return LegacyFile{}, fmt.Errorf("baseline schemaVersion %q is not readable as a 0.5 baseline; expected %q", legacyFile.SchemaVersion, LegacySchemaVersion)
	}
	for index, entry := range legacyFile.Findings {
		if entry.RuleID == "" || entry.File == "" {
			return LegacyFile{}, fmt.Errorf("findings[%d] must include ruleId and file", index)
		}
	}
	return legacyFile, nil
}

// requireOneRowContainer refuses a 0.5 input naming more than one recognised row container.
//
// The five 0.5 writers used three container keys, so a file carrying two of them migrates
// differently in different ports; refusing it is the only reading that is the same everywhere.
//
// The baselineJSON is decoded as a top-level object and checked for the findings, groups and entries keys.
// It returns an error when decoding baselineJSON fails or it names two or more of those keys, and nil otherwise.
func requireOneRowContainer(baselineJSON []byte) error {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(baselineJSON, &document); err != nil {
		return err
	}
	present := make([]string, 0, len(legacyRowContainers))
	for _, container := range legacyRowContainers {
		if _, ok := document[container]; ok {
			present = append(present, container)
		}
	}
	if len(present) > 1 {
		return fmt.Errorf("baseline carries more than one row container (%s); a migration input must name exactly one", strings.Join(present, ", "))
	}
	return nil
}

// Accepts reports whether a 0.5 row has the same rule and path as currentFinding; Fingerprint and StableIdentity are ignored.
//
// A shape that recorded less is not made to mean more, so one row covers every finding of that rule in that file.
// The currentFinding is covered when any row's ruleId and file equal its RuleID and File exactly; with no rows the result is false.
func (legacyFile LegacyFile) Accepts(currentFinding finding.Finding) bool {
	for _, entry := range legacyFile.Findings {
		if entry.RuleID == currentFinding.RuleID && entry.File == currentFinding.File {
			return true
		}
	}
	return false
}

// MigrationResult reports what an explicit migration wrote.
type MigrationResult struct {
	// Accepted is how many current findings the 0.5 rows covered.
	Accepted int
	// Occurrences is how many v3 entries were written.
	Occurrences int
	// Sensitive is how many accepted findings became counts rather than entries.
	Sensitive int
	// File is the v3 document that was written.
	File File
}

// Migrate carries a 0.5 baseline's reviews into a separate v3 file, for `gruff-go baseline --migrate old.json --out new.json`.
//
// The reviewed findings are re-identified from the current run, never translated from 0.5 digests.
// The input is never written to, renamed, or deleted, and an output that is the input by spelling, link, or inode is refused.
//
// The 0.5 rows at inputPath select currentFindings for outputPath; FromFindingsAt turns them into the v3 file, stamped with generatedAt.
// Covered sensitive findings add counts, covered ordinary findings with an identity add entries, and other covered findings are omitted.
// It returns the accepted, occurrence and sensitive counts with the written File, which has no occurrences when no row covers a current finding.
//
// It returns an error when a path is empty or both name the same file, or when the input cannot be read or parsed.
// It also fails when a covered finding's identity cannot be computed, writing fails, or the input changed during the run.
func Migrate(inputPath, outputPath string, currentFindings []finding.Finding, generatedAt time.Time) (MigrationResult, error) {
	if inputPath == "" || outputPath == "" {
		return MigrationResult{}, fmt.Errorf("migration needs both a 0.5 input path and a separate output path")
	}
	if err := requireDistinctPaths(inputPath, outputPath); err != nil {
		return MigrationResult{}, err
	}
	// #nosec G304 -- CLI intentionally reads an explicit user-provided baseline path.
	before, err := os.ReadFile(inputPath)
	if err != nil {
		return MigrationResult{}, err
	}
	legacyFile, err := ParseLegacy(before)
	if err != nil {
		return MigrationResult{}, err
	}
	accepted := make([]finding.Finding, 0)
	for _, currentFinding := range currentFindings {
		if legacyFile.Accepts(currentFinding) {
			accepted = append(accepted, currentFinding)
		}
	}
	migrated, err := FromFindingsAt(accepted, generatedAt)
	if err != nil {
		return MigrationResult{}, err
	}
	if err := Write(outputPath, migrated); err != nil {
		return MigrationResult{}, err
	}
	// The input is the retreat path; prove it survived rather than assume it.
	after, err := os.ReadFile(inputPath) // #nosec G304 -- same explicit path as above.
	if err != nil {
		return MigrationResult{}, err
	}
	// Another process editing the 0.5 file during the run lands here, after the v3 output has already been written.
	if !bytes.Equal(before, after) {
		return MigrationResult{}, fmt.Errorf("migration changed the 0.5 input %s; the retreat path is no longer intact", inputPath)
	}
	return MigrationResult{
		Accepted:    len(accepted),
		Occurrences: len(migrated.Occurrences),
		Sensitive:   migrated.Sensitive.Counts.Total,
		File:        migrated,
	}, nil
}

// requireDistinctPaths refuses an output that is the input by spelling, resolved link target, or inode.
//
// A spelling check alone lets a symlink turn an out-of-place migration into an in-place one and destroy the retreat copy.
// It returns an error when inputPath and outputPath match by absolute spelling or os.SameFile, or cannot be checked; a missing output passes.
func requireDistinctPaths(inputPath, outputPath string) error {
	absoluteInput, err := filepath.Abs(inputPath)
	if err != nil {
		return err
	}
	absoluteOutput, err := filepath.Abs(outputPath)
	if err != nil {
		return err
	}
	if absoluteInput == absoluteOutput {
		return fmt.Errorf("migration input and output path are the same file: %s; choose a separate output path", absoluteInput)
	}
	inputInfo, err := os.Stat(absoluteInput)
	// A missing input, or one whose file information cannot be read, stops the migration before any output is written.
	if err != nil {
		return err
	}
	outputInfo, err := os.Stat(absoluteOutput)
	if err != nil {
		// A missing output is the ordinary case: nothing exists to collide with.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if os.SameFile(inputInfo, outputInfo) {
		return fmt.Errorf("migration output path resolves to the input path: %s; choose a separate output path", absoluteOutput)
	}
	return nil
}
