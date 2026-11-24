// Package cli's migrate-config command carries a 0.5 configuration forward to the 0.6 schema, out of place.
//
// In 0.6.0 the per-command exit gate moved from minimumSeverity to failOn. Preview allowlists and retired rule blocks were removed.
// This command rewrites those keys so the loader can accept the rest of the user's configuration.
//
// The rewrite is line-oriented rather than a parse-and-re-render, so every line it does not touch passes through verbatim.
// Removed spans, a header the removal empties, and a rewritten schemaVersion line lose any comment or value they carried.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// configMigration holds the candidate configuration and a list of changes a developer can review.
//
// A dry run prints the changes without writing a file.
// A successful write uses the candidate text. An empty change list means the input was already current.
type configMigration struct {
	text    string
	changes []string
}

// runMigrateConfig validates a 0.5 config and prepares a separate file when a developer upgrades with gruff-go migrate-config.
// args accepts -config, -output, and -dry-run. Positional paths are refused because the flags identify the source and destination.
//
// stdout receives changes and confirmation. stderr receives flag, read, validation, or write errors.
// Returns 0 after a valid dry run or write, and 2 if the requested migration cannot be completed.
func runMigrateConfig(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("migrate-config", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inputPath := flags.String("config", "", "the 0.5 config to read; it is never modified")
	outputPath := flags.String("output", "", "new file for the migrated config; required unless -dry-run")
	dryRun := flags.Bool("dry-run", false, "print what would change and write nothing")
	// An unknown or malformed flag, such as -ouput typed for -output, lands here and the run exits 2.
	if err := parseCommandArguments(flags, args); err != nil {
		return 2
	}
	// Every input is named by a flag, so an operand here is a path the user expected the command to use.
	if flags.NArg() > 0 {
		fmt.Fprintln(stderr, "migrate-config takes no positional arguments; name the files with -config and -output")
		return 2
	}

	// Without an input there is nothing to migrate, and guessing at the project config would be a different command.
	if *inputPath == "" {
		fmt.Fprintln(stderr, "migrate-config needs -config <path> naming the 0.5 config to read")
		return 2
	}
	original, err := os.ReadFile(*inputPath)
	// A typo in -config, or a file the user cannot read, lands here and the run exits 2 with nothing written.
	if err != nil {
		fmt.Fprintf(stderr, "config to migrate does not exist or could not be read: %s\n", *inputPath)
		return 2
	}

	migration := migrateConfigText(string(original))
	defaults := rule.Defaults()
	// A field the current CLI still cannot load stops both the dry run and the write, leaving the source file in place.
	if _, err := config.Parse([]byte(migration.text), defaults.Definitions()); err != nil {
		fmt.Fprintf(stderr, "cannot migrate %s: %v (original kept)\n", *inputPath, err)
		return 2
	}
	// An already-current file is still copied byte for byte to -output unless -dry-run is set.
	if len(migration.changes) == 0 {
		fmt.Fprintf(stdout, "%s is already current; no changes.\n", *inputPath)
	} else {
		fmt.Fprintln(stdout, "Migration changes:")
		// List each rewrite so the developer can review the migration before replacing their project config.
		for _, change := range migration.changes {
			fmt.Fprintf(stdout, "  - %s\n", change)
		}
	}

	// With -dry-run the change list above is the whole result, so -output may be left out and nothing is written.
	if *dryRun {
		fmt.Fprintln(stdout, "Dry run: nothing written.")
		return 0
	}
	return writeMigratedConfig(*inputPath, *outputPath, migration.text, stdout, stderr)
}

// writeMigratedConfig publishes migrated at a new outputPath while keeping inputPath available as the rollback copy.
//
// An empty outputPath or any existing destination is refused. stdout confirms success and stderr explains a failed write.
// Returns 0 once the file is closed, or 2 if it cannot be safely created or written.
func writeMigratedConfig(inputPath, outputPath, migrated string, stdout, stderr io.Writer) int {
	// Only a dry run can omit a destination.
	if outputPath == "" {
		fmt.Fprintln(stderr, "migrate-config needs -output <path>, or -dry-run to print the changes")
		return 2
	}
	// #nosec G304 -- The destination is the CLI's explicit output operand.
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	// A destination already linked to the source, or a directory the developer cannot write, leaves the original available.
	if err != nil {
		fmt.Fprintf(stderr, "unable to create %s: %v; choose a new output file\n", outputPath, err)
		return 2
	}
	_, writeErr := io.WriteString(output, migrated)
	closeErr := output.Close()
	// If storage fills during the write, remove the incomplete destination so it cannot be mistaken for valid output.
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(outputPath)
		fmt.Fprintf(stderr, "unable to finish writing %s: write=%v close=%v\n", outputPath, writeErr, closeErr)
		return 2
	}
	fmt.Fprintf(stdout, "Wrote %s; %s is unchanged.\n", outputPath, inputPath)
	return 0
}

// migrateConfigText returns original with the legacy keys rewritten before migrate-config validates it.
// The result includes the changes a developer sees in a dry run. An empty change list means the original bytes can be copied.
func migrateConfigText(original string) configMigration {
	normalized := strings.ReplaceAll(original, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	root := firstConfigLine(lines, 0)
	rootIndent := 0
	// Use the first setting's column so comments above it do not change the structure of the rewritten config.
	if root < len(lines) {
		rootIndent = lineIndent(lines[root])
	}
	migrated, changes := []string{}, []string{}
	// Copy supported settings in place so the developer can compare the migrated text with the original.
	for index := 0; index < len(lines); {
		line := lines[index]
		switch {
		case lineIndent(line) == rootIndent && keyIs(line, "minimumSeverity") && isLegacyMinimumSeverityMap(lines, index):
			_, tail, _ := strings.Cut(line, ":")
			migrated = append(migrated, line[:rootIndent]+"failOn:"+tail)
			changes = append(changes, "minimumSeverity map renamed to failOn")
		case lineIndent(line) == rootIndent && opensConfigBlock(lines, index) &&
			(keyIs(line, "allowlists") || keyIs(line, "sensitiveData") || keyIs(line, "rules")):
			end := configBlockEnd(lines, index)
			block, removedKeys := migrateConfigBlock(lines[index:end])
			migrated = append(migrated, block...)
			changes = append(changes, removedKeys...)
			index = end
			continue
		case lineIndent(line) == rootIndent && (keyIs(line, "select") || keyIs(line, "excludeRules")):
			end := index + 1
			if opensConfigBlock(lines, index) {
				end = configBlockEnd(lines, index)
			}
			block, removedKeys := migrateRuleListSection(lines[index:end])
			migrated = append(migrated, block...)
			changes = append(changes, removedKeys...)
			index = end
			continue
		case lineIndent(line) == rootIndent && keyIs(line, "selection") && opensConfigBlock(lines, index):
			end := configBlockEnd(lines, index)
			block, removedKeys := migrateSelectionBlock(lines[index:end])
			migrated = append(migrated, block...)
			changes = append(changes, removedKeys...)
			index = end
			continue
		default:
			migrated = append(migrated, line)
		}
		index++
	}
	return withSchemaVersion(migrated, changes, original)
}

// isLegacyMinimumSeverityMap reports whether lines[index] holds a 0.5 minimumSeverity mapping (block, empty, or flow) rather than a 0.6 scalar floor.
func isLegacyMinimumSeverityMap(lines []string, index int) bool {
	if opensConfigBlock(lines, index) {
		return true
	}
	_, tail, ok := strings.Cut(lines[index], ":")
	if !ok {
		return false
	}
	value := stripInlineYAMLComment(tail)
	return value == "" || strings.HasPrefix(value, "{")
}

// stripInlineYAMLComment removes a trailing # comment outside quotes from raw and returns the trimmed scalar value.
// Returns an empty string when raw is empty, whitespace-only, or begins directly with a # comment.
func stripInlineYAMLComment(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}
	for _, marker := range []string{" #", "\t#"} {
		if idx := strings.Index(trimmed, marker); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
	}
	return trimmed
}

// migrateSelectionBlock strips retired rule IDs from selection.rules and selection.excludeRules inside block while keeping other keys intact.
//
// block holds the raw YAML lines of one top-level selection: section.
// It returns the kept YAML lines (dropping the selection: header if removals leave it empty) and a slice of change notes for the CLI summary.
func migrateSelectionBlock(block []string) ([]string, []string) {
	keptLines, removedKeys := []string{block[0]}, []string{}
	child := firstConfigLine(block, 1)
	if child >= len(block) {
		return keptLines, removedKeys
	}
	childIndent := lineIndent(block[child])
	for index := 1; index < len(block); {
		line := block[index]
		// Only rule-ID list keys under selection can hold retired rule IDs; pillar and other keys pass through verbatim.
		if lineIndent(line) == childIndent && (keyIs(line, "rules") || keyIs(line, "excludeRules")) {
			end := index + 1
			if opensConfigBlock(block, index) {
				end = configBlockEnd(block, index)
			}
			section, removed := migrateRuleListSection(block[index:end])
			keptLines = append(keptLines, section...)
			removedKeys = append(removedKeys, removed...)
			index = end
			continue
		}
		keptLines = append(keptLines, line)
		index++
	}
	// Drop an empty selection: header only when our removals emptied it, preserving a user's intentionally empty block.
	if firstConfigLine(keptLines, 1) == len(keptLines) && len(removedKeys) > 0 {
		return keptLines[1:], removedKeys
	}
	return keptLines, removedKeys
}

// migrateRuleListSection removes retired rule IDs from a YAML block list or inline flow list inside block (such as select or excludeRules).
//
// It returns the updated YAML lines (dropping the key header when removals leave it empty) and human-readable change notes for each removed rule ID.
// Returns block unchanged and a nil note slice when no retired rule ID appears in block.
func migrateRuleListSection(block []string) ([]string, []string) {
	header := block[0]
	// A single-line block carries an inline YAML flow list such as `excludeRules: [a, b]` rather than indented dash items.
	if len(block) == 1 {
		keyPart, tail, ok := strings.Cut(header, ":")
		if !ok {
			return block, nil
		}
		value := stripInlineYAMLComment(tail)
		if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
			return block, nil
		}
		inner := strings.TrimSpace(value[1 : len(value)-1])
		if inner == "" {
			return block, nil
		}
		keptItems, removed := []string{}, []string{}
		for _, rawItem := range strings.Split(inner, ",") {
			item := strings.TrimSpace(rawItem)
			if item == "" {
				continue
			}
			if isRetiredRuleID(item) {
				removed = append(removed, "removed "+trimYAMLQuotes(item))
				continue
			}
			keptItems = append(keptItems, item)
		}
		if len(removed) == 0 {
			return block, nil
		}
		// If every item in the inline list was retired, omit the entire key line so migration leaves clean YAML.
		if len(keptItems) == 0 {
			return nil, removed
		}
		return []string{keyPart + ": [" + strings.Join(keptItems, ", ") + "]"}, removed
	}
	keptLines, removed := []string{header}, []string{}
	for index := 1; index < len(block); index++ {
		line := block[index]
		trimmed := strings.TrimSpace(line)
		if rest, isItem := strings.CutPrefix(trimmed, "-"); isItem && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
			candidate := stripInlineYAMLComment(rest)
			if isRetiredRuleID(candidate) {
				removed = append(removed, "removed "+trimYAMLQuotes(candidate))
				continue
			}
		}
		keptLines = append(keptLines, line)
	}
	// Drop the list header when removals emptied it so the migrated config does not retain a dangling empty key.
	if firstConfigLine(keptLines, 1) == len(keptLines) && len(removed) > 0 {
		return keptLines[1:], removed
	}
	return keptLines, removed
}

// trimYAMLQuotes removes one matching pair of single or double quotes around raw after trimming whitespace and returns the unquoted string.
// Returns an empty string when raw is empty or contains only quotes and whitespace.
func trimYAMLQuotes(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) >= 2 && ((trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"') || (trimmed[0] == '\'' && trimmed[len(trimmed)-1] == '\'')) {
		return trimmed[1 : len(trimmed)-1]
	}
	return trimmed
}

// isRetiredRuleID reports whether raw names one of the 8 rules retired in 0.6.0, in either canonical dotted form or legacy hyphenated form.
func isRetiredRuleID(raw string) bool {
	switch trimYAMLQuotes(raw) {
	case "design.hotspot-file", "design-hotspot-file",
		"maintainability.production-panic", "maintainability-production-panic",
		"naming.negated-boolean", "naming-negated-boolean",
		"security.sensitive-data-logging", "security-sensitive-data-logging",
		"security.sql-string-query", "security-sql-string-query",
		"sensitive-data.high-entropy-string", "sensitive-data-high-entropy-string",
		"test-quality.no-failure-path", "test-quality-no-failure-path",
		"test-quality.skipped-test", "test-quality-skipped-test":
		return true
	}
	return false
}

// migrateConfigBlock returns block with retired preview and rule entries removed while keeping supported settings.
// The second result names what was removed so the developer can inspect the dry run. An empty list means the block needed no changes.
func migrateConfigBlock(block []string) ([]string, []string) {
	header, keptLines, removedKeys := block[0], []string{block[0]}, []string{}
	child := firstConfigLine(block, 1)
	if child >= len(block) {
		return keptLines, removedKeys
	}
	childIndent := lineIndent(block[child])
	// Keep other entries in the same order when a retired setting shares their section.
	for index := 1; index < len(block); {
		line := block[index]
		// Remove a retired entry and its child values together so none can attach to the next setting.
		if lineIndent(line) == childIndent && retiredConfigKey(header, line) {
			key, _, _ := strings.Cut(strings.TrimSpace(line), ":")
			removedKeys = append(removedKeys, "removed "+key)
			index = configBlockEnd(block, index)
			continue
		}
		keptLines = append(keptLines, line)
		index++
	}
	// If only removed settings used the section, drop its header so the current loader sees no empty legacy section.
	if firstConfigLine(keptLines, 1) == len(keptLines) && len(removedKeys) > 0 {
		return keptLines[1:], removedKeys
	}
	return keptLines, removedKeys
}

// retiredConfigKey reports whether line names a retired direct child of header.
func retiredConfigKey(header, line string) bool {
	switch {
	case keyIs(header, "allowlists"):
		return keyIs(line, "secretPreviews")
	case keyIs(header, "sensitiveData"):
		return keyIs(line, "previewAllowlist")
	case keyIs(header, "rules"):
		key, _, _ := strings.Cut(strings.TrimSpace(line), ":")
		return isRetiredRuleID(key)
	}
	return false
}

// opensConfigBlock reports whether lines has an indented block after index, ignoring comments and blank lines.
func opensConfigBlock(lines []string, index int) bool {
	_, _, tailPresent := strings.Cut(lines[index], ":")
	next := firstConfigLine(lines, index+1)
	return tailPresent && next < len(lines) && lineIndent(lines[next]) > lineIndent(lines[index])
}

// configBlockEnd returns the index past the children of lines[index], leaving trailing comments outside the block.
func configBlockEnd(lines []string, index int) int {
	indent, end := lineIndent(lines[index]), index+1
	// Take the retired setting's indented values with it while leaving comments that lead into the next section.
	for next := firstConfigLine(lines, end); next < len(lines) && lineIndent(lines[next]) > indent; next = firstConfigLine(lines, end) {
		end = next + 1
	}
	return end
}

// firstConfigLine returns the index of the first value line at or after start, or len(lines).
func firstConfigLine(lines []string, start int) int {
	// Skip whitespace and notes to find the next setting that determines the block's structure.
	for index := start; index < len(lines); index++ {
		text := strings.TrimSpace(lines[index])
		// An actual setting can start or end a block. A blank line or comment cannot.
		if text != "" && !strings.HasPrefix(text, "#") {
			return index
		}
	}
	return len(lines)
}

// keyIs reports whether a line is exactly the named key followed by a colon, so a comment or longer name is not it.
func keyIs(line, key string) bool {
	rest, found := strings.CutPrefix(strings.TrimSpace(line), key)
	return found && strings.HasPrefix(strings.TrimLeft(rest, " \t"), ":")
}

// lineIndent reports how many leading spaces and tabs a line carries, counting a tab as one, the same as a space.
// A result of 0 means the line starts at the left margin, which is how a root-level key is recognised.
func lineIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

// withSchemaVersion pins the schema version, inserting it at the top when the 0.5 file never named one.
//
// Only a root-level schemaVersion key counts; unless it already matches the pinned line, it is replaced whole, trailing comment included.
// A quoted key such as "schemaVersion" is not recognised, so it stays and a second, pinned line is added at the top.
//
// lines is the migrated text split into lines, changes the rewrites so far, and original the input text kept when nothing changed.
// It returns the newline-joined lines and changes, plus an entry when schemaVersion was added or rewritten; with no changes, text is original.
func withSchemaVersion(lines, changes []string, original string) configMigration {
	existing := -1
	rootIndent := 0
	// Match the existing indentation so a new schema line belongs to the same config.
	if first := firstConfigLine(lines, 0); first < len(lines) {
		rootIndent = lineIndent(lines[first])
	}
	pinned := strings.Repeat(" ", rootIndent) + fmt.Sprintf("schemaVersion: %q", config.SchemaVersion)
	for position, line := range lines {
		// Use only the top-level version. A nested setting with the same name belongs to its own section.
		if lineIndent(line) == rootIndent && keyIs(line, "schemaVersion") {
			existing = position
			break
		}
	}

	switch {
	case existing < 0:
		changes = append(changes, fmt.Sprintf("line 1: schemaVersion added as %s; every 0.6 loader requires it", config.SchemaVersion))
		lines = append([]string{pinned}, lines...)
	// The reported line number counts lines of the migrated output, so it is off from the input when lines above it were removed.
	case lines[existing] != pinned:
		changes = append(changes, fmt.Sprintf("line %d: schemaVersion pinned to %s", existing+1, config.SchemaVersion))
		lines[existing] = pinned
	}

	if len(changes) == 0 {
		return configMigration{text: original, changes: changes}
	}
	return configMigration{text: strings.Join(lines, "\n"), changes: changes}
}
