// Package cli's migrate-config command carries a 0.5 configuration forward to the 0.6 schema, out of place.
//
// Two keys moved in 0.6.0: the per-command exit gate left minimumSeverity for failOn, and allowlists.secretPreviews was removed outright.
// The second went because FAMILY-CONTRACT.md section 5 makes category markers unconditional.
// A file carrying either is refused by the loader, so a user upgrading needs a way across that does not mean re-typing their configuration.
//
// The rewrite is line-oriented rather than a parse-and-re-render, so every line it does not touch passes through verbatim.
// Removed spans, a header the removal empties, and a rewritten schemaVersion line lose any comment or value they carried.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/blundergoat/gruff-go/internal/config"
)

// configMigration is what one migration produced: the destination's text, and one readable line per rewrite.
// An empty changes slice means no rewrite matched and text is the input byte for byte; nothing checks that the loader accepts it.
type configMigration struct {
	text    string
	changes []string
}

// runMigrateConfig runs gruff-go migrate-config: it reads the named config, rewrites it, and puts the result where the user asked.
//
// The input is only read here; writeMigratedConfig refuses an output with the same absolute path, but not a symlink or hard link to the input.
// args holds the migrate-config arguments, parsed as the -config, -output and -dry-run flags; a positional operand is refused.
//
// Change lists and confirmations go to stdout; the flag parser's output and every refusal or failure message go to stderr.
// It returns the exit code: 0 after a dry run or a written file, and 2 for unusable arguments, an unreadable input, or a refused or failed write.
func runMigrateConfig(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("migrate-config", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inputPath := flags.String("config", "", "the 0.5 config to read; it is never modified")
	outputPath := flags.String("output", "", "where to write the migrated config; required unless -dry-run")
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
	// An already-current file is still copied byte for byte to -output unless -dry-run is set.
	if len(migration.changes) == 0 {
		fmt.Fprintf(stdout, "%s is already current; no changes.\n", *inputPath)
	} else {
		fmt.Fprintln(stdout, "Migration changes:")
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

// writeMigratedConfig writes the migrated text to the destination the user named, refusing an output whose absolute path matches the input.
//
// A symlink or hard link to the input passes that check, so the write can still replace the input's contents.
// inputPath names the config that was read, outputPath the destination file, and migrated the text written there with mode 0600 for a new file.
//
// The confirmation goes to stdout and each refusal or write failure goes to stderr.
// It returns 0 once the file is written, and 2 when outputPath is empty, has the same absolute path as inputPath, or cannot be written.
func writeMigratedConfig(inputPath, outputPath, migrated string, stdout, stderr io.Writer) int {
	// Reached when the user runs migrate-config without -output or -dry-run; the run exits 2 rather than pick a destination the user did not name.
	if outputPath == "" {
		fmt.Fprintln(stderr, "migrate-config needs -output <path>, or -dry-run to print the changes")
		return 2
	}
	// Only identical absolute path strings are refused; a symlink or hard link can still point -output at the -config file and overwrite it.
	if sameConfigFile(inputPath, outputPath) {
		fmt.Fprintf(stderr, "-output must name a different file from -config; %s is the copy you may want back\n", inputPath)
		return 2
	}

	// A destination gruff cannot write is reported rather than swallowed, so the user does not believe it migrated.
	if err := os.WriteFile(outputPath, []byte(migrated), 0o600); err != nil {
		fmt.Fprintf(stderr, "unable to write %s: %v\n", outputPath, err)
		return 2
	}
	fmt.Fprintf(stdout, "Wrote %s; %s is unchanged.\n", outputPath, inputPath)
	return 0
}

// sameConfigFile reports whether two paths have the same absolute form, the check that refuses a migration output naming its own input path.
//
// left and right are made absolute with filepath.Abs and compared as strings, so a symlink or hard link to the same file is not detected.
// It reports false when either path cannot be made absolute.
func sameConfigFile(left, right string) bool {
	resolvedLeft, leftErr := filepath.Abs(left)
	resolvedRight, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return resolvedLeft == resolvedRight
}

// migrateConfigText rewrites one configuration's text for the current schema, leaving alone every line the migration does not recognise.
//
// A comment inside a removed block or on a rewritten schemaVersion line is lost, as is a header the removal empties.
// original is the whole file text; an indented secretPreviews key and its contiguous deeper lines are dropped, so a blank line ends the removal.
// A minimumSeverity key becomes failOn only when nothing follows its colon and the next line is nonblank and deeper.
//
// It returns the migrated text with a change line per removed key, renamed key, or schemaVersion fix.
// When nothing changed, changes is empty and text is original byte for byte.
func migrateConfigText(original string) configMigration {
	lines := strings.Split(original, "\n")
	migrated := make([]string, 0, len(lines))
	changes := []string{}

	for index := 0; index < len(lines); {
		// Removing secretPreviews drops its contiguous deeper lines; a blank line ends the span, so later children stay in the output without their key.
		if skipped := removedKeyBlockLength(lines, index); skipped > 0 {
			changes = append(changes, fmt.Sprintf("line %d: allowlists.secretPreviews removed; section 5 makes category markers unconditional", index+1))
			index += skipped
			migrated = dropEmptiedParent(migrated, lines, index)
			continue
		}
		// A per-command map under the old key is the exit gate, which now has its own name.
		if renamed, ok := renamedGateLine(lines, index); ok {
			changes = append(changes, fmt.Sprintf("line %d: minimumSeverity: renamed to failOn:, the key that gates the exit code in 0.6", index+1))
			migrated = append(migrated, renamed)
			index++
			continue
		}
		migrated = append(migrated, lines[index])
		index++
	}
	return withSchemaVersion(migrated, changes, original)
}

// removedKeyBlockLength reports how many lines the removed redaction key occupies, counting the contiguous deeper lines under it.
//
// lines is the config split into lines and index the line to test; only an indented secretPreviews key matches, not a root-level one.
// The count includes the key line and stops at the first blank line or line no deeper than the key; it is 0 when index is not that key.
func removedKeyBlockLength(lines []string, index int) int {
	indent := lineIndent(lines[index])
	// Any indented secretPreviews key is removed without checking its parent; a root-level key is left for the loader to refuse.
	if indent == 0 || !keyIs(lines[index], "secretPreviews") {
		return 0
	}
	length := 1
	for index+length < len(lines) && isDeeperThan(lines[index+length], indent) {
		length++
	}
	return length
}

// renamedGateLine rewrites the old gate key when it introduces a per-command block, leaving the scalar floor alone.
//
// lines is the config split into lines and index the line to test; any nonblank deeper next line opens a block, even an indented comment.
// It returns the failOn: line at the same indent and true, or an empty string and false for a scalar, another key, or no deeper next line.
func renamedGateLine(lines []string, index int) (string, bool) {
	if !keyIs(lines[index], "minimumSeverity") {
		return "", false
	}
	// A key with a value on the same line is the 0.6 display floor and keeps its name.
	// A trailing comment counts as text after the colon too, so a commented gate header is not migrated.
	_, tail, _ := strings.Cut(strings.TrimSpace(lines[index]), ":")
	if strings.TrimSpace(tail) != "" {
		return "", false
	}
	indent := lineIndent(lines[index])
	// An empty block would be a key with nothing under it, which the loader reads as neither shape.
	// A block whose first child follows a blank line also keeps the old name, since a blank next line does not count as deeper.
	if index+1 >= len(lines) || !isDeeperThan(lines[index+1], indent) {
		return "", false
	}
	return lines[index][:indent] + "failOn:", true
}

// dropEmptiedParent removes a header line left just before a removed block when the line at index is absent, blank, or no deeper than it.
//
// Only that line is checked, so a child that follows a blank line does not keep the header.
// The candidate header is just the previous output line ending in a colon, so an empty sibling key right before the removed key is dropped too.
//
// migrated is the output built so far, whose last line is the candidate header, and it is returned unchanged unless that header is dropped.
// lines is the input split into lines and index the first line after the removed block, checked for a child deeper than the header.
// It returns migrated without its last line when that line ends in a colon, is not a bare colon or a comment, and has no deeper line at index.
func dropEmptiedParent(migrated, lines []string, index int) []string {
	if len(migrated) == 0 {
		return migrated
	}
	header := migrated[len(migrated)-1]
	trimmed := strings.TrimSpace(header)
	// A comment, blank line or bare colon is kept; any other line ending in a colon is treated as an empty header.
	// So a value line that happens to end in a colon can be removed as well.
	if len(trimmed) < 2 || strings.HasPrefix(trimmed, "#") || !strings.HasSuffix(trimmed, ":") {
		return migrated
	}
	// Only the line right after the removed span is checked, so a child after a blank line does not save the header.
	if index < len(lines) && isDeeperThan(lines[index], lineIndent(header)) {
		return migrated
	}
	return migrated[:len(migrated)-1]
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

// isDeeperThan reports whether line is nonblank and indented deeper than indent, meaning it sits inside a block opened at indent.
// A blank line gives false: it ends a removed key's span, and it never counts as a child that keeps a header or opens a gate block.
func isDeeperThan(line string, indent int) bool {
	return strings.TrimSpace(line) != "" && lineIndent(line) > indent
}

// withSchemaVersion pins the schema version, inserting it at the top when the 0.5 file never named one.
//
// Only a root-level schemaVersion key counts; unless it already matches the pinned line, it is replaced whole, trailing comment included.
// A quoted key such as "schemaVersion" is not recognised, so it stays and a second, pinned line is added at the top.
//
// lines is the migrated text split into lines, changes the rewrites so far, and original the input text kept when nothing changed.
// It returns the newline-joined lines and changes, plus an entry when schemaVersion was added or rewritten; with no changes, text is original.
func withSchemaVersion(lines, changes []string, original string) configMigration {
	pinned := fmt.Sprintf("schemaVersion: %q", config.SchemaVersion)
	existing := -1
	for position, line := range lines {
		if lineIndent(line) == 0 && keyIs(line, "schemaVersion") {
			existing = position
			break
		}
	}

	switch {
	case existing < 0:
		changes = append(changes, fmt.Sprintf("line 1: schemaVersion added as %s; every 0.6 loader requires it", config.SchemaVersion))
		lines = append([]string{pinned}, lines...)
	// The reported line number counts lines of the migrated output, so it is off from the input when lines above it were removed.
	case strings.TrimSpace(lines[existing]) != pinned:
		changes = append(changes, fmt.Sprintf("line %d: schemaVersion pinned to %s", existing+1, config.SchemaVersion))
		lines[existing] = pinned
	}

	if len(changes) == 0 {
		return configMigration{text: original, changes: changes}
	}
	return configMigration{text: strings.Join(lines, "\n"), changes: changes}
}
