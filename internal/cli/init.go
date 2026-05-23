// Package cli implements the gruff-go command-line interface.
// init writes a default .gruff-go.yaml in the working directory, mirroring the
// registry's per-rule enablement, severity, and threshold defaults so adopters
// have an editable starting point instead of an undocumented opaque baseline.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// defaultConfigFileName is the on-disk path init writes to, matching the only
// auto-discovery entry the config loader recognises.
const defaultConfigFileName = ".gruff-go.yaml"

// defaultBaselineFileName is the onboarding baseline path printed in setup
// hints. The scanner does not auto-load it; users opt in with --baseline.
const defaultBaselineFileName = "gruff-baseline.json"

// errConfigExists is the sentinel returned by writeDefaultConfig when the
// target file is already on disk and force was not set; callers turn it into
// the user-facing "already exists" message.
var errConfigExists = errors.New("config file already exists")

// runInit parses the init subcommand flags and writes the default config file.
func runInit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	force := flags.Bool("force", false, "overwrite the existing config file if present")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintln(stderr, "init takes no positional arguments")
		return 2
	}
	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	target := filepath.Join(root, defaultConfigFileName)
	written, err := writeDefaultConfig(target, *force)
	if err != nil {
		if errors.Is(err, errConfigExists) {
			fmt.Fprintf(stderr, "%s already exists; pass --force to overwrite\n", defaultConfigFileName)
			return 1
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote default config to %s (%d rules)\n", defaultConfigFileName, written)
	writeFreshStartSetupHint(stdout)
	return 0
}

// writeDefaultConfig renders the default config from the live rule registry
// and writes it to path. When force is false and the file already exists the
// call returns errConfigExists so the user can keep their edits.
func writeDefaultConfig(path string, force bool) (int, error) {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return 0, errConfigExists
		} else if !errors.Is(err, fs.ErrNotExist) {
			return 0, err
		}
	}
	defaults := rule.Defaults()
	definitions := defaults.Definitions()
	body := cfgpkg.Render(definitions)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return 0, err
	}
	return len(definitions), nil
}

// writeFreshStartSetupHint points new adopters at the first-run baseline flow
// without creating a baseline implicitly.
func writeFreshStartSetupHint(stdout io.Writer) {
	fmt.Fprintf(stdout, "fresh start for existing findings: gruff-go analyse --generate-baseline %s .\n", defaultBaselineFileName)
	fmt.Fprintf(stdout, "then scan with: gruff-go analyse --baseline %s .\n", defaultBaselineFileName)
}
