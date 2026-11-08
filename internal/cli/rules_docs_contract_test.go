// rules_docs_contract_test.go verifies the machine-readable markers in the public rule catalogue.
//
// The parser deliberately understands only the summary, catalog rows, rule headings, and metadata bullets that authors maintain.
// Ordinary explanatory Markdown remains outside the test contract.
// Parse errors name the broken marker, and most carry its line number, so a failing go test points at the text to fix.
package cli

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Exact marker patterns for the rules catalogue: the summary sentence, a catalog rule-ID cell, a rule heading and one Threshold entry.
//
// Only lines with a recognized prefix reach these patterns, where a miss is a malformed error; a line with a changed prefix is ignored.
var (
	rulesDocsHeaderPattern = regexp.MustCompile("^`gruff-go` ships \\*\\*(\\d+) rules\\*\\* across \\*\\*(\\d+) pillars\\*\\*\\. \\*\\*(\\d+) rules are enabled by default\\*\\* and (\\d+) rules are opt-in\\.")
	rulesDocsCatalogID     = regexp.MustCompile("^\\s*\\[`([^`]+)`\\]\\(#[^)]+\\)\\s*$")
	rulesDocsHeading       = regexp.MustCompile("^### `([^`]+)`$")
	rulesDocsThreshold     = regexp.MustCompile("`([^`]+)` \\(default `([-+]?(?:[0-9]+(?:\\.[0-9]+)?|\\.[0-9]+))`(?: [^)]*)?\\)")
)

// rulesDocsHeader is the structured release summary above the catalog table, including the exact set of rules that require an explicit opt-in.
type rulesDocsHeader struct {
	RuleCount    int
	PillarCount  int
	DefaultCount int
	OptInCount   int
	OptInIDs     []string
}

// rulesDocsCatalogRecord is the compact metadata declared by one table row.
type rulesDocsCatalogRecord struct {
	ID         string
	Pillar     string
	Severity   string
	Capability string
	Thresholds map[string]float64
}

// rulesDocsSectionRecord is the richer metadata beneath one rule heading.
// seen distinguishes a missing required bullet from its zero value.
type rulesDocsSectionRecord struct {
	ID             string
	Pillar         string
	Severity       string
	DefaultEnabled bool
	Confidence     string
	Capability     string
	Thresholds     map[string]float64
	Tags           []string
	seen           map[string]bool
}

// rulesDocsContract keeps the summary, table, and per-rule sections separate.
// The registry comparison then validates each public surface independently.
type rulesDocsContract struct {
	Header   rulesDocsHeader
	Catalog  map[string]rulesDocsCatalogRecord
	Sections map[string]rulesDocsSectionRecord
}

// rulesDocsParserState carries the current section while the narrow parser walks author-maintained markers line by line.
type rulesDocsParserState struct {
	parsed     rulesDocsContract
	headerSeen bool
	optInSeen  bool
	section    *rulesDocsSectionRecord
}

// parseRulesDocsContract reads only the exact authoring markers whose values must agree with list-rules.
//
// Prose, descriptions, examples, and remediation paragraphs are intentionally ignored.
// body is the full Markdown catalogue, split on newlines and numbered from one for error messages.
//
// It returns the parsed summary, opt-in IDs, catalog rows and rule sections, plus the partial contract read so far when parsing fails.
// It returns an error when any marker is malformed or duplicated, a section lacks a required bullet, or the summary or opt-in list is missing.
func parseRulesDocsContract(body string) (rulesDocsContract, error) {
	state := rulesDocsParserState{
		parsed: rulesDocsContract{
			Catalog:  map[string]rulesDocsCatalogRecord{},
			Sections: map[string]rulesDocsSectionRecord{},
		},
	}
	for index, line := range strings.Split(body, "\n") {
		if err := state.consumeLine(line, index+1); err != nil {
			return state.parsed, err
		}
	}
	// If the catalogue ends inside an open rule section, it is validated and stored here so missing final bullets still fail go test.
	if err := storeRulesDocsSection(&state.parsed, state.section); err != nil {
		return state.parsed, err
	}
	// A changed summary prefix is ignored, so go test reports missing rules summary rather than a malformed-summary error.
	if !state.headerSeen {
		return state.parsed, fmt.Errorf("missing rules summary")
	}
	// The summary gives only the opt-in count, so without the Opt-in rules line go test reports a missing opt-in list.
	if !state.optInSeen {
		return state.parsed, fmt.Errorf("missing opt-in list")
	}
	return state.parsed, nil
}

// consumeLine routes one line to an exact marker parser and ignores every unrelated prose line.
//
// line is one Markdown line routed by prefix to the summary, opt-in, catalog row or rule heading parser, or to the open section's bullets.
// A level-two heading stores and closes the open section, and a bullet error also names the section's rule ID.
// It returns an error prefixed with the one-based lineNumber when the chosen parser fails, and nil for every accepted or ignored line.
func (state *rulesDocsParserState) consumeLine(line string, lineNumber int) error {
	var err error
	switch {
	case strings.HasPrefix(line, "`gruff-go` ships **"):
		err = state.consumeHeader(line)
	case strings.HasPrefix(line, "Opt-in rules:"):
		err = state.consumeOptIns(line)
	case strings.HasPrefix(line, "| [`"):
		err = state.consumeCatalogRow(line)
	case strings.HasPrefix(line, "### "):
		err = state.consumeRuleHeading(line)
	case strings.HasPrefix(line, "## "):
		err = storeRulesDocsSection(&state.parsed, state.section)
		state.section = nil
	case state.section != nil:
		err = parseRulesDocsMetadataLine(state.section, line)
		if err != nil {
			err = fmt.Errorf("rule %q: %w", state.section.ID, err)
		}
	}
	if err != nil {
		return fmt.Errorf("line %d: %w", lineNumber, err)
	}
	return nil
}

// consumeHeader records the one exact summary marker.
//
// line is the summary sentence, whose counts fill the parsed header before the summary is marked seen.
// It returns an error when a summary was already seen or parseRulesDocsHeader rejects line, and nil once it is recorded.
func (state *rulesDocsParserState) consumeHeader(line string) error {
	if state.headerSeen {
		return fmt.Errorf("duplicate rules summary")
	}
	header, err := parseRulesDocsHeader(line)
	if err != nil {
		return err
	}
	state.parsed.Header = header
	state.headerSeen = true
	return nil
}

// consumeOptIns records the one exact opt-in ID marker.
//
// line is the Opt-in rules sentence, whose IDs fill the header's OptInIDs before the list is marked seen.
// It returns an error when an opt-in list was already seen or parseRulesDocsOptInIDs rejects line, and nil once it is recorded.
func (state *rulesDocsParserState) consumeOptIns(line string) error {
	if state.optInSeen {
		return fmt.Errorf("duplicate opt-in list")
	}
	ids, err := parseRulesDocsOptInIDs(line)
	if err != nil {
		return err
	}
	state.parsed.Header.OptInIDs = ids
	state.optInSeen = true
	return nil
}

// consumeCatalogRow parses and deduplicates one compact rule record.
//
// line is one catalog table row, stored in the parsed catalog under its rule ID.
// It returns an error when parseRulesDocsCatalogRow rejects line or that rule ID already has a row, and nil once the row is stored.
func (state *rulesDocsParserState) consumeCatalogRow(line string) error {
	record, err := parseRulesDocsCatalogRow(line)
	if err != nil {
		return err
	}
	if _, exists := state.parsed.Catalog[record.ID]; exists {
		return fmt.Errorf("duplicate catalog row %q", record.ID)
	}
	state.parsed.Catalog[record.ID] = record
	return nil
}

// consumeRuleHeading closes the previous record and opens one exact rule section for subsequent metadata bullets.
//
// line is a level-three heading that must hold exactly one backticked rule ID, which opens a section with empty Thresholds and seen maps.
// It returns an error when storing the previous section fails or line is not an exact rule heading, and nil once the new section is open.
func (state *rulesDocsParserState) consumeRuleHeading(line string) error {
	if err := storeRulesDocsSection(&state.parsed, state.section); err != nil {
		return err
	}
	match := rulesDocsHeading.FindStringSubmatch(line)
	// Every level-three heading in the catalogue must be a rule heading, so a prose ### heading fails here.
	if match == nil {
		return fmt.Errorf("malformed rule heading %q", line)
	}
	state.section = &rulesDocsSectionRecord{ID: match[1], Thresholds: map[string]float64{}, seen: map[string]bool{}}
	return nil
}

// parseRulesDocsHeader extracts the four registry counts from the exact first summary sentence.
//
// Prose variants that would weaken the marker are rejected.
// line must begin with the exact summary sentence, and any text after that sentence is ignored.
//
// It returns a header holding the rule, pillar, default and opt-in counts, with OptInIDs left nil.
// It fails with a zero header and an error when line does not match the summary pattern or a count cannot be converted.
func parseRulesDocsHeader(line string) (rulesDocsHeader, error) {
	match := rulesDocsHeaderPattern.FindStringSubmatch(line)
	if match == nil {
		return rulesDocsHeader{}, fmt.Errorf("malformed rules summary")
	}
	values := [4]int{}
	for index := range values {
		value, err := strconv.Atoi(match[index+1])
		if err != nil {
			return rulesDocsHeader{}, fmt.Errorf("invalid rules summary count %q", match[index+1])
		}
		values[index] = value
	}
	return rulesDocsHeader{RuleCount: values[0], PillarCount: values[1], DefaultCount: values[2], OptInCount: values[3]}, nil
}

// parseRulesDocsOptInIDs reads the exact backticked rule-ID list after the summary.
//
// It normalizes the existing comma/and punctuation and checks item length and outer backticks, without validating rule-ID syntax.
// line must end with a full stop; its "Opt-in rules: " prefix and the stop are dropped, and the first ", and " then the first " and " become ", ".
//
// It returns the rule IDs in written order with their backticks removed.
// It fails with a nil list and an error when line lacks the full stop, the list is empty, or any item is not a backticked value.
func parseRulesDocsOptInIDs(line string) ([]string, error) {
	if !strings.HasSuffix(line, ".") {
		return nil, fmt.Errorf("malformed opt-in list")
	}
	content := strings.TrimSuffix(strings.TrimPrefix(line, "Opt-in rules: "), ".")
	content = strings.Replace(content, ", and ", ", ", 1)
	content = strings.Replace(content, " and ", ", ", 1)
	return parseRulesDocsCodeList(content)
}

// parseRulesDocsCatalogRow extracts the declared fields from one exact table row.
//
// The row's link target and human description stay outside the contract.
// line must split into eight cells, the six columns plus the text outside the outer pipes.
//
// It returns a record holding the linked rule ID, the trimmed pillar, severity and capability cells, and the parsed thresholds.
// It fails with a zero record and an error when the cell count differs, the ID cell is not a backticked anchor link, or a threshold is malformed.
func parseRulesDocsCatalogRow(line string) (rulesDocsCatalogRecord, error) {
	cells := splitRulesDocsCatalogCells(line)
	// An unescaped pipe inside a description adds a cell and lands here; escape it with a backslash.
	if len(cells) != 8 {
		return rulesDocsCatalogRecord{}, fmt.Errorf("malformed catalog row")
	}
	idMatch := rulesDocsCatalogID.FindStringSubmatch(cells[1])
	if idMatch == nil {
		return rulesDocsCatalogRecord{}, fmt.Errorf("malformed catalog rule ID")
	}
	thresholds, err := parseRulesDocsCatalogThresholds(strings.TrimSpace(cells[5]))
	if err != nil {
		return rulesDocsCatalogRecord{}, err
	}
	return rulesDocsCatalogRecord{
		ID:         idMatch[1],
		Pillar:     strings.TrimSpace(cells[2]),
		Severity:   strings.TrimSpace(cells[3]),
		Capability: strings.TrimSpace(cells[4]),
		Thresholds: thresholds,
	}, nil
}

// splitRulesDocsCatalogCells separates the six exact table columns, keeping escaped pipes inside descriptions such as `(sk\|pk\|rk)`.
//
// line is split at every pipe a backslash does not escape, and escaped characters stay in their cell along with the backslash.
// It returns every cell in order, including the text before the first pipe and after the last, so a line without pipes gives one cell.
func splitRulesDocsCatalogCells(line string) []string {
	cells := []string{}
	start := 0
	escaped := false
	for index := 0; index < len(line); index++ {
		if escaped {
			escaped = false
			continue
		}
		if line[index] == '\\' {
			escaped = true
			continue
		}
		if line[index] == '|' {
			cells = append(cells, line[start:index])
			start = index + 1
		}
	}
	cells = append(cells, line[start:])
	return cells
}

// parseRulesDocsCatalogThresholds converts the table's sorted `key: value` cells into numeric values.
//
// value is the trimmed threshold cell with items joined by a comma and a space, and a dash represents a rule with no threshold.
// It returns a map from each threshold key to its number, empty but non-nil for a dash.
// It fails with a nil map and an error when an item is not backticked, lacks a key and a number joined by a colon, or repeats a key.
func parseRulesDocsCatalogThresholds(value string) (map[string]float64, error) {
	thresholds := map[string]float64{}
	if value == "-" {
		return thresholds, nil
	}
	for _, item := range strings.Split(value, ", ") {
		if len(item) < 3 || item[0] != '`' || item[len(item)-1] != '`' {
			return nil, fmt.Errorf("malformed catalog threshold %q", item)
		}
		parts := strings.SplitN(item[1:len(item)-1], ": ", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, fmt.Errorf("malformed catalog threshold %q", item)
		}
		number, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			return nil, fmt.Errorf("malformed catalog threshold %q", item)
		}
		if _, exists := thresholds[parts[0]]; exists {
			return nil, fmt.Errorf("duplicate catalog threshold %q", parts[0])
		}
		thresholds[parts[0]] = number
	}
	return thresholds, nil
}

// parseRulesDocsMetadataLine consumes only the seven contracted bullet prefixes.
//
// Other bullets, such as Options or Secondary pillar, remain prose.
// section is the open rule record, updated in place with each bullet marked seen, and line is one line beneath its heading.
//
// It returns an error when a contracted bullet is malformed or repeated, Default-enabled is not yes, no or no (opt-in), or Threshold or Tags fails.
// Any other line gives nil and leaves section unchanged.
func parseRulesDocsMetadataLine(section *rulesDocsSectionRecord, line string) error {
	prefixes := []string{"Pillar", "Default severity", "Default-enabled", "Threshold", "Confidence", "Capability", "Tags"}
	for _, name := range prefixes {
		prefix := "- **" + name + ":** "
		if !strings.HasPrefix(line, "- **"+name) {
			continue
		}
		// A bullet that starts like a contracted one but drifts, such as a missing colon, fails here instead of passing as prose.
		if !strings.HasPrefix(line, prefix) {
			return fmt.Errorf("malformed %s metadata marker %q", name, line)
		}
		if section.seen[name] {
			return fmt.Errorf("duplicate %s metadata", name)
		}
		section.seen[name] = true
		value := strings.TrimPrefix(line, prefix)
		switch name {
		case "Pillar":
			section.Pillar = value
		case "Default severity":
			section.Severity = value
		case "Default-enabled":
			if value != "yes" && value != "no" && value != "no (opt-in)" {
				return fmt.Errorf("malformed Default-enabled metadata %q", value)
			}
			section.DefaultEnabled = value == "yes"
		case "Threshold":
			thresholds, err := parseRulesDocsSectionThresholds(value)
			if err != nil {
				return err
			}
			section.Thresholds = thresholds
		case "Confidence":
			section.Confidence = value
		case "Capability":
			section.Capability = value
		case "Tags":
			tags, err := parseRulesDocsCodeList(value)
			if err != nil {
				return fmt.Errorf("malformed Tags metadata: %w", err)
			}
			section.Tags = tags
		}
		return nil
	}
	return nil
}

// parseRulesDocsSectionThresholds accepts one or more exact `key` (default `number`) entries and rejects unmatched text.
//
// A unit or other note may follow the number, after a space, inside the parentheses.
// value is the Threshold bullet text after its prefix, holding entries joined by a comma and a space with no other text.
//
// It returns a map from each backticked key to its default number.
// It fails with a nil map and an error when value has no entry, holds unmatched text, or repeats a key.
func parseRulesDocsSectionThresholds(value string) (map[string]float64, error) {
	thresholds := map[string]float64{}
	matches := rulesDocsThreshold.FindAllStringSubmatchIndex(value, -1)
	position := 0
	for index, match := range matches {
		separator := ""
		if index > 0 {
			separator = ", "
		}
		if value[position:match[0]] != separator {
			return nil, fmt.Errorf("malformed Threshold metadata %q", value)
		}
		name := value[match[2]:match[3]]
		number, err := strconv.ParseFloat(value[match[4]:match[5]], 64)
		if err != nil || name == "" {
			return nil, fmt.Errorf("malformed Threshold metadata %q", value)
		}
		if _, exists := thresholds[name]; exists {
			return nil, fmt.Errorf("duplicate Threshold metadata %q", name)
		}
		thresholds[name] = number
		position = match[1]
	}
	if len(matches) == 0 || position != len(value) {
		return nil, fmt.Errorf("malformed Threshold metadata %q", value)
	}
	return thresholds, nil
}

// parseRulesDocsCodeList reads a comma-separated sequence of inline-code values.
//
// It is shared by tags and the opt-in rule-ID marker.
// value is the list text, split wherever a comma is followed by a space.
//
// It returns the items in order with their backticks removed.
// It fails with a nil list and an error when value is empty or any item is shorter than three characters or not wrapped in backticks.
func parseRulesDocsCodeList(value string) ([]string, error) {
	if value == "" {
		return nil, fmt.Errorf("empty inline-code list")
	}
	items := strings.Split(value, ", ")
	for index, item := range items {
		if len(item) < 3 || item[0] != '`' || item[len(item)-1] != '`' {
			return nil, fmt.Errorf("malformed inline-code value %q", item)
		}
		items[index] = item[1 : len(item)-1]
	}
	return items, nil
}

// storeRulesDocsSection validates required bullets and records a completed section at the next heading or the end of the catalogue.
//
// parsed receives a copy of section under its rule ID, and a nil section, meaning no rule is open, changes nothing.
// It returns an error when a required Pillar, Default severity, Default-enabled, Confidence or Capability bullet is missing.
// It also returns an error when that rule ID is already stored, and nil once the copy is recorded.
func storeRulesDocsSection(parsed *rulesDocsContract, section *rulesDocsSectionRecord) error {
	if section == nil {
		return nil
	}
	// Threshold and Tags are optional bullets, so they are left out of this required list.
	for _, name := range []string{"Pillar", "Default severity", "Default-enabled", "Confidence", "Capability"} {
		if !section.seen[name] {
			return fmt.Errorf("rule %q missing %s metadata", section.ID, name)
		}
	}
	if _, exists := parsed.Sections[section.ID]; exists {
		return fmt.Errorf("duplicate rule section %q", section.ID)
	}
	parsed.Sections[section.ID] = *section
	return nil
}
