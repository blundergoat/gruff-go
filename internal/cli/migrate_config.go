// Package cli's migrate-config command carries a 0.5 configuration forward to the 0.6 schema, out of place.
//
// Two keys moved in 0.6.0 and a user's committed file still spells them the old way: the per-command exit gate left
// minimumSeverity for failOn, and allowlists.secretPreviews was removed outright because FAMILY-CONTRACT.md section
// 5 makes category markers unconditional. A file carrying either is refused by the loader, so a user upgrading
// needs a way across that does not mean re-typing their configuration.
//
// The rewrite is line-oriented rather than a parse-and-re-render, which keeps every comment, blank line, and value
// the user wrote exactly as written; anything the migration does not understand passes through untouched.
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
// An empty changes slice means the input was already current and text is the input byte for byte.
type configMigration struct {
	text    string
	changes []string
}

// runMigrateConfig reads the named config, rewrites it, and puts the result where the user asked.
// The input is only ever read, so a user who regrets the migration still has the configuration they started with.
func runMigrateConfig(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("migrate-config", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inputPath := flags.String("config", "", "the 0.5 config to read; it is never modified")
	outputPath := flags.String("output", "", "where to write the migrated config; required unless -dry-run")
	dryRun := flags.Bool("dry-run", false, "print what would change and write nothing")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	// Without an input there is nothing to migrate, and guessing at the project config would be a different command.
	if *inputPath == "" {
		fmt.Fprintln(stderr, "migrate-config needs -config <path> naming the 0.5 config to read")
		return 2
	}
	original, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintf(stderr, "config to migrate does not exist or could not be read: %s\n", *inputPath)
		return 2
	}

	migration := migrateConfigText(string(original))
	if len(migration.changes) == 0 {
		fmt.Fprintf(stdout, "%s is already current; no changes.\n", *inputPath)
	} else {
		fmt.Fprintln(stdout, "Migration changes:")
		for _, change := range migration.changes {
			fmt.Fprintf(stdout, "  - %s\n", change)
		}
	}

	if *dryRun {
		fmt.Fprintln(stdout, "Dry run: nothing written.")
		return 0
	}
	return writeMigratedConfig(*inputPath, *outputPath, migration.text, stdout, stderr)
}

// writeMigratedConfig writes the migrated text to the destination the user named, refusing to overwrite the input.
func writeMigratedConfig(inputPath, outputPath, migrated string, stdout, stderr io.Writer) int {
	// Without a destination there is nowhere to put the result, and writing over the input is the one thing
	// migration must never do; refusing is better than choosing a path the user did not name.
	if outputPath == "" {
		fmt.Fprintln(stderr, "migrate-config needs -output <path>, or -dry-run to print the changes")
		return 2
	}
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

// sameConfigFile reports whether two paths name the same file, so a migration cannot be pointed at its own input.
func sameConfigFile(left, right string) bool {
	resolvedLeft, leftErr := filepath.Abs(left)
	resolvedRight, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return resolvedLeft == resolvedRight
}

// migrateConfigText rewrites one configuration's text for the current schema, leaving alone every line the
// migration does not recognise, so a user's comments and their own keys survive intact.
func migrateConfigText(original string) configMigration {
	lines := strings.Split(original, "\n")
	migrated := make([]string, 0, len(lines))
	changes := []string{}

	for index := 0; index < len(lines); {
		// The removed key takes its whole indented block with it, or an empty list stays behind meaning nothing.
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

// removedKeyBlockLength reports how many lines the removed redaction key occupies, counting its indented block.
func removedKeyBlockLength(lines []string, index int) int {
	indent := lineIndent(lines[index])
	// Only the nested allowlists entry is removed, so a root key of that name is left for the loader to refuse.
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
func renamedGateLine(lines []string, index int) (string, bool) {
	if !keyIs(lines[index], "minimumSeverity") {
		return "", false
	}
	// A key with a value on the same line is the 0.6 display floor and keeps its name.
	_, tail, _ := strings.Cut(strings.TrimSpace(lines[index]), ":")
	if strings.TrimSpace(tail) != "" {
		return "", false
	}
	indent := lineIndent(lines[index])
	// An empty block would be a key with nothing under it, which the loader reads as neither shape.
	if index+1 >= len(lines) || !isDeeperThan(lines[index+1], indent) {
		return "", false
	}
	return lines[index][:indent] + "failOn:", true
}

// dropEmptiedParent removes the block header the removal just emptied, because a key with nothing under it is not
// a valid mapping. A header whose block still has a child is kept exactly as the user wrote it.
func dropEmptiedParent(migrated, lines []string, index int) []string {
	if len(migrated) == 0 {
		return migrated
	}
	header := migrated[len(migrated)-1]
	trimmed := strings.TrimSpace(header)
	// A header is a bare key followed by a colon; a comment, a value, or a blank line is a line the user wants kept.
	if len(trimmed) < 2 || strings.HasPrefix(trimmed, "#") || !strings.HasSuffix(trimmed, ":") {
		return migrated
	}
	// A block that still has a child is not empty, so its header stays.
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

// lineIndent reports how many leading whitespace characters a line carries.
func lineIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

// isDeeperThan reports whether a line belongs to a block opened at the given indent; a blank line does not end one.
func isDeeperThan(line string, indent int) bool {
	return strings.TrimSpace(line) != "" && lineIndent(line) > indent
}

// withSchemaVersion pins the schema version, inserting it at the top when the 0.5 file never named one.
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
	case strings.TrimSpace(lines[existing]) != pinned:
		changes = append(changes, fmt.Sprintf("line %d: schemaVersion pinned to %s", existing+1, config.SchemaVersion))
		lines[existing] = pinned
	}

	if len(changes) == 0 {
		return configMigration{text: original, changes: changes}
	}
	return configMigration{text: strings.Join(lines, "\n"), changes: changes}
}
