// rules_docs_contract_test.go verifies the machine-readable markers in the
// public rule catalogue. The parser deliberately understands only the summary,
// catalog rows, rule headings, and metadata bullets that authors maintain;
// ordinary explanatory Markdown remains outside the test contract.
package cli

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	rulesDocsHeaderPattern = regexp.MustCompile("^`gruff-go` ships \\*\\*(\\d+) rules\\*\\* across \\*\\*(\\d+) pillars\\*\\*\\. \\*\\*(\\d+) rules are enabled by default\\*\\* and (\\d+) rules are opt-in\\.")
	rulesDocsCatalogID     = regexp.MustCompile("^\\s*\\[`([^`]+)`\\]\\(#[^)]+\\)\\s*$")
	rulesDocsHeading       = regexp.MustCompile("^### `([^`]+)`$")
	rulesDocsThreshold     = regexp.MustCompile("`([^`]+)` \\(default `([-+]?(?:[0-9]+(?:\\.[0-9]+)?|\\.[0-9]+))`(?: [^)]*)?\\)")
)

// rulesDocsHeader is the structured release summary above the catalog table,
// including the exact set of rules that require an explicit opt-in.
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

// rulesDocsContract keeps the summary, table, and per-rule sections separate
// so the registry comparison validates each public surface independently.
type rulesDocsContract struct {
	Header   rulesDocsHeader
	Catalog  map[string]rulesDocsCatalogRecord
	Sections map[string]rulesDocsSectionRecord
}

// rulesDocsParserState carries the current section while the narrow parser
// walks author-maintained markers line by line.
type rulesDocsParserState struct {
	parsed     rulesDocsContract
	headerSeen bool
	optInSeen  bool
	section    *rulesDocsSectionRecord
}

// parseRulesDocsContract reads only the exact authoring markers whose values
// must agree with list-rules; prose, descriptions, examples, and remediation
// paragraphs are intentionally ignored.
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
	if err := storeRulesDocsSection(&state.parsed, state.section); err != nil {
		return state.parsed, err
	}
	if !state.headerSeen {
		return state.parsed, fmt.Errorf("missing rules summary")
	}
	if !state.optInSeen {
		return state.parsed, fmt.Errorf("missing opt-in list")
	}
	return state.parsed, nil
}

// consumeLine routes one line to an exact marker parser and ignores every
// unrelated prose line.
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

// consumeRuleHeading closes the previous record and opens one exact rule
// section for subsequent metadata bullets.
func (state *rulesDocsParserState) consumeRuleHeading(line string) error {
	if err := storeRulesDocsSection(&state.parsed, state.section); err != nil {
		return err
	}
	match := rulesDocsHeading.FindStringSubmatch(line)
	if match == nil {
		return fmt.Errorf("malformed rule heading %q", line)
	}
	state.section = &rulesDocsSectionRecord{ID: match[1], Thresholds: map[string]float64{}, seen: map[string]bool{}}
	return nil
}

// parseRulesDocsHeader extracts the four registry counts from the exact first
// summary sentence, rejecting prose variants that would weaken the marker.
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

// parseRulesDocsOptInIDs reads the exact backticked rule-ID list after the
// summary; it accepts the existing comma/and punctuation but no free-form text.
func parseRulesDocsOptInIDs(line string) ([]string, error) {
	if !strings.HasSuffix(line, ".") {
		return nil, fmt.Errorf("malformed opt-in list")
	}
	content := strings.TrimSuffix(strings.TrimPrefix(line, "Opt-in rules: "), ".")
	content = strings.Replace(content, ", and ", ", ", 1)
	content = strings.Replace(content, " and ", ", ", 1)
	return parseRulesDocsCodeList(content)
}

// parseRulesDocsCatalogRow extracts the declared fields from one exact table
// row while leaving its link target and human description outside the contract.
func parseRulesDocsCatalogRow(line string) (rulesDocsCatalogRecord, error) {
	cells := splitRulesDocsCatalogCells(line)
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

// splitRulesDocsCatalogCells separates the six exact table columns while
// retaining escaped pipes used inside descriptions such as `(sk\|pk\|rk)`.
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

// parseRulesDocsCatalogThresholds converts the table's sorted `key: value`
// cells into numeric values; a dash represents a rule with no threshold.
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

// parseRulesDocsMetadataLine consumes only the seven contracted bullet
// prefixes. Other bullets, such as Options or Secondary pillar, remain prose.
func parseRulesDocsMetadataLine(section *rulesDocsSectionRecord, line string) error {
	prefixes := []string{"Pillar", "Default severity", "Default-enabled", "Threshold", "Confidence", "Capability", "Tags"}
	for _, name := range prefixes {
		prefix := "- **" + name + ":** "
		if !strings.HasPrefix(line, "- **"+name) {
			continue
		}
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

// parseRulesDocsSectionThresholds accepts one or more exact
// `key` (default `number` [unit]) entries and rejects unmatched text.
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

// parseRulesDocsCodeList reads a comma-separated sequence of inline-code
// values. It is shared by tags and the opt-in rule-ID marker.
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

// storeRulesDocsSection validates required bullets and records a completed
// section before the parser advances to the next Markdown heading.
func storeRulesDocsSection(parsed *rulesDocsContract, section *rulesDocsSectionRecord) error {
	if section == nil {
		return nil
	}
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
