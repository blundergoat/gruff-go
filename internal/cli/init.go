// Package cli implements the gruff-go command-line interface.
//
// Running gruff-go init writes a default .gruff-go.yaml in the working directory, mirroring the registry's per-rule defaults.
// Each rule's enablement, severity and thresholds appear as editable values, giving adopters a starting point instead of opaque defaults.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// defaultConfigFileName is the file init and the first-run prompt write, matching the only auto-discovery entry the config loader recognises.
//
// It is also the name shown in the success line, the already-exists refusal, the parse warning and the first-run question.
const defaultConfigFileName = ".gruff-go.yaml"

// defaultBaselineFileName is the baseline path printed in the setup hints after init or the first-run prompt writes a config.
//
// Init never creates the baseline; the user runs the printed analyse --generate-baseline command to make one.
// gruff-go analyse auto-loads a file of this name from the project root when one exists, so --baseline is optional for analyse.
const defaultBaselineFileName = "gruff-baseline.json"

// errConfigExists is the sentinel writeDefaultConfig returns when the target file is already on disk and force was not set.
// runInit turns it into the already-exists message suggesting --force or --force --reset, and exits 1 with the file untouched.
var errConfigExists = errors.New("config file already exists")

// runInit handles gruff-go init: it parses --force and --reset, then writes .gruff-go.yaml in the working directory.
//
// args holds the command-line arguments, parsed as the --force and --reset flags with any positional argument rejected.
// stdout receives the success line and setup hint. stderr receives errors and the preserved-tuning notice.
//
// Returns the process exit code: 0 on success, 1 when the config already exists without --force or writing it fails, and 2 for any other failure,
// such as a flag error, --reset without --force, a positional argument, or an unreadable working directory.
func runInit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	force := flags.Bool("force", false, "regenerate the config; project-specific tuning is preserved across the regenerate (use --reset to clobber instead)")
	reset := flags.Bool("reset", false, "with --force, discard existing tuning and write fresh defaults (destructive)")
	// An unknown flag such as --forse stops init here with exit 2 before anything is written.
	if err := parseCommandArguments(flags, args); err != nil {
		return 2
	}
	// --reset only changes what --force regenerates, so on its own it is a usage error and nothing is written.
	if *reset && !*force {
		fmt.Fprintln(stderr, "--reset requires --force")
		return 2
	}
	// gruff-go init some/dir lands here: init always writes into the working directory, so a target path is refused with exit 2.
	if flags.NArg() > 0 {
		fmt.Fprintln(stderr, "init takes no positional arguments")
		return 2
	}
	root, err := os.Getwd()
	// A shell sitting in a directory that was deleted lands here, and init exits 2 without writing.
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	target := filepath.Join(root, defaultConfigFileName)
	result, err := writeDefaultConfig(target, *force, *reset)
	if err != nil {
		// Running gruff-go init again without --force lands here: the existing file is left as it is and init exits 1.
		if errors.Is(err, errConfigExists) {
			fmt.Fprintf(stderr, "%s already exists; pass --force to regenerate (tuning preserved) or --force --reset to discard\n", defaultConfigFileName)
			return 1
		}
		// A read-only project directory, or init --force over a .gruff-go.yaml the user cannot write, fails here and init exits 1.
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := fmt.Fprintf(stdout, "wrote default config to %s (%d rules)\n", defaultConfigFileName, result.ruleCount); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// init --force prints this notice when the loaded config has non-empty paths.ignore, acceptedAbbreviations, rules or failOn, or a minimumSeverity.
	if result.preservedNotice != "" {
		fmt.Fprintln(stderr, result.preservedNotice)
	}
	if err := writeFreshStartSetupHint(stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}

// writeDefaultConfigResult reports what happened during a write so the caller can render an accurate user-facing notice.
type writeDefaultConfigResult struct {
	// ruleCount is the number of rule blocks in the rendered output.
	ruleCount int
	// preservedNotice names the tuning categories counted in the loaded config; it can count rule overrides that exact-ID rendering then drops.
	preservedNotice string
}

// writeDefaultConfig renders the default config from the live rule registry and writes it to path, for init and the first-run prompt.
//
// With force false an existing file is never touched and errConfigExists comes back; with force true it is overwritten.
// Unless reset is true, an existing config must load successfully before the new file is rendered.
// Returns the rendered rule count and any notice about preserved settings.
//
// The error is errConfigExists for an existing file without force, otherwise any stat, create, write or close failure, with a zero result.
func writeDefaultConfig(path string, force, reset bool) (writeDefaultConfigResult, error) {
	existed := false
	// Only --force looks for an existing file up front, because only a regenerate can carry its tuning over.
	if force {
		if _, err := os.Stat(path); err == nil {
			existed = true
		} else if !errors.Is(err, fs.ErrNotExist) {
			// A stat failure other than not-found, such as a permission error on the directory, stops init --force here and it exits 1.
			return writeDefaultConfigResult{}, err
		}
	}

	defaults := rule.Defaults()
	definitions := defaults.Definitions()
	opts := cfgpkg.RenderOptions{}
	result := writeDefaultConfigResult{ruleCount: len(definitions)}
	// A developer refreshing the template with --force can keep rule choices, ignore paths, audit exclusions, scan budget, and report settings.
	if existed && force && !reset {
		preserved, parseErr := loadConfigForRegeneration(path, definitions)
		// An unknown key or unreadable config makes its tuning unsafe to copy. Leave the original file in place and show the recovery options.
		if parseErr != nil {
			return writeDefaultConfigResult{}, fmt.Errorf("cannot preserve %s: %w (original kept; use migrate-config for a legacy file or --force --reset to discard it)", path, parseErr)
		}
		opts.Existing = preserved
		result.preservedNotice = summarisePreserved(*preserved)
	}
	body := cfgpkg.Render(definitions, opts)
	// Reload the rendered settings before a forced write so a preserved value cannot leave the user with an unusable config.
	if opts.Existing != nil {
		// If a quoted exclusion reason fails to round-trip, report the error while the original is still on disk.
		if _, err := cfgpkg.Parse(body, definitions); err != nil {
			return writeDefaultConfigResult{}, fmt.Errorf("cannot regenerate %s: %w (original kept)", path, err)
		}
	}
	// --force truncates and rewrites any existing file; without it, the exclusive create below refuses to replace one.
	if force {
		if err := os.WriteFile(path, body, 0o644); err != nil {
			return writeDefaultConfigResult{}, err
		}
		return result, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		// The exclusive create turns an existing file into errConfigExists, so plain init and the first-run prompt never overwrite a config.
		if errors.Is(err, fs.ErrExist) {
			return writeDefaultConfigResult{}, errConfigExists
		}
		return writeDefaultConfigResult{}, err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return writeDefaultConfigResult{}, err
	}
	if err := file.Close(); err != nil {
		return writeDefaultConfigResult{}, err
	}
	return result, nil
}

// loadConfigForRegeneration reads the config at path before init --force writes a refreshed template.
//
// definitions validates rules in both reads. The fallback accepts a missing schema and uses rule defaults for unrecognized per-rule severities.
// Returns the loaded settings, or nil with the strict error if both reads fail, for example when invalid YAML prevents preserving the file.
func loadConfigForRegeneration(path string, definitions []rule.Definition) (*cfgpkg.Config, error) {
	cfg, err := cfgpkg.Load(path, definitions)
	// Current valid configs supply the settings as written.
	if err == nil {
		return &cfg, nil
	}
	// A pre-0.2 config with legacy severity names lands here, so init --force can still recover its other supported settings.
	permissive, permissiveErr := cfgpkg.LoadPermissive(path, definitions)
	// If both reads fail, the strict error tells the user what normally blocks a scan with the same file.
	if permissiveErr != nil {
		return nil, err
	}
	return &permissive, nil
}

// summarisePreserved builds the one-line stderr notice init --force prints about tuning carried over from the existing config.
//
// cfg is the existing config being preserved; the notice counts its IgnorePaths, AcceptedAbbreviations, Rules and FailOn entries, and mentions
// MinimumSeverity when its value is non-empty.
//
// Returns the notice, which ends by suggesting --reset, or the empty string when none of those values is set, even if DeepScanBudget or
// SensitiveExclusions carried over, in which case init prints no notice.
func summarisePreserved(cfg cfgpkg.Config) string {
	parts := []string{}
	if n := len(cfg.IgnorePaths); n > 0 {
		parts = append(parts, fmt.Sprintf("%d paths.ignore", n))
	}
	if n := len(cfg.AcceptedAbbreviations); n > 0 {
		parts = append(parts, fmt.Sprintf("%d acceptedAbbreviations", n))
	}
	if n := len(cfg.Rules); n > 0 {
		parts = append(parts, fmt.Sprintf("%d per-rule overrides", n))
	}
	if n := len(cfg.FailOn); n > 0 {
		parts = append(parts, fmt.Sprintf("%d failOn entries", n))
	}
	// The display floor is one value rather than a set, so it is reported as present rather than counted.
	if cfg.MinimumSeverity.Value != "" {
		parts = append(parts, "the minimumSeverity display floor")
	}
	if len(parts) == 0 {
		return ""
	}
	return "preserved existing tuning: " + strings.Join(parts, ", ") + " (pass --reset to discard)"
}

// writeFreshStartSetupHint points new adopters at the first-run baseline flow without creating a baseline implicitly.
//
// stdout receives two lines: the analyse --generate-baseline command and the analyse --baseline scan, both using defaultBaselineFileName.
// Returns an error when either write to stdout fails, and nil once both lines are written.
func writeFreshStartSetupHint(stdout io.Writer) error {
	if _, err := fmt.Fprintf(stdout, "fresh start for existing findings: gruff-go analyse --generate-baseline %s .\n", defaultBaselineFileName); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "then scan with: gruff-go analyse --baseline %s .\n", defaultBaselineFileName); err != nil {
		return err
	}
	return nil
}
