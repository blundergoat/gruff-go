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
	"strings"

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
	force := flags.Bool("force", false, "regenerate the config; project-specific tuning is preserved across the regenerate (use --reset to clobber instead)")
	reset := flags.Bool("reset", false, "with --force, discard existing tuning and write fresh defaults (destructive)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *reset && !*force {
		fmt.Fprintln(stderr, "--reset requires --force")
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
	result, err := writeDefaultConfig(target, *force, *reset)
	if err != nil {
		if errors.Is(err, errConfigExists) {
			fmt.Fprintf(stderr, "%s already exists; pass --force to regenerate (tuning preserved) or --force --reset to discard\n", defaultConfigFileName)
			return 1
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := fmt.Fprintf(stdout, "wrote default config to %s (%d rules)\n", defaultConfigFileName, result.ruleCount); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if result.preservedNotice != "" {
		fmt.Fprintln(stderr, result.preservedNotice)
	}
	if result.parseError != nil {
		fmt.Fprintf(stderr, "warning: existing %s could not be parsed (%v); fresh defaults were written and prior tuning was lost\n", defaultConfigFileName, result.parseError)
	}
	if err := writeFreshStartSetupHint(stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}

// writeDefaultConfigResult reports what happened during a write so the caller
// can render an accurate user-facing notice.
type writeDefaultConfigResult struct {
	// ruleCount is the number of rule blocks in the rendered output.
	ruleCount int
	// preservedNotice describes which tuning categories were carried over.
	preservedNotice string
	// parseError is set when an existing file was present but could not be
	// loaded; the caller falls back to fresh defaults and warns the user.
	parseError error
}

// writeDefaultConfig renders the default config from the live rule registry
// and writes it to path. When force is false and the file already exists the
// call returns errConfigExists so the user can keep their edits. When force is
// true, an existing valid config is parsed and its project-specific tuning
// (paths.ignore, allowlists, per-rule overrides) is preserved across the
// regenerate unless reset is also true.
func writeDefaultConfig(path string, force, reset bool) (writeDefaultConfigResult, error) {
	existed := false
	if force {
		if _, err := os.Stat(path); err == nil {
			existed = true
		} else if !errors.Is(err, fs.ErrNotExist) {
			return writeDefaultConfigResult{}, err
		}
	}

	defaults := rule.Defaults()
	definitions := defaults.Definitions()
	opts := cfgpkg.RenderOptions{}
	result := writeDefaultConfigResult{ruleCount: len(definitions)}
	if existed && force && !reset {
		preserved, parseErr := loadExistingForPreserve(path, definitions)
		if parseErr != nil {
			result.parseError = parseErr
		} else {
			opts.Existing = preserved
			result.preservedNotice = summarisePreserved(*preserved)
		}
	}
	body := cfgpkg.Render(definitions, opts)
	if force {
		if err := os.WriteFile(path, body, 0o644); err != nil {
			return writeDefaultConfigResult{}, err
		}
		return result, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
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

// loadExistingForPreserve reads and parses the existing config at path so its
// tuning can be layered into the regenerated output. Returns the parsed config
// or an error when the file is unreadable, syntactically invalid, or schema-
// incompatible with the current build.
//
// When strict load fails, falls back to a permissive parse that drops any
// per-rule severity override carrying a legacy 5-bucket name. Without this
// fallback, init --force on a pre-0.2 config would print a warning and write
// fresh defaults, losing the user's paths.ignore, allowlists, thresholds, and
// options. The dropped severities re-resolve to registry defaults in the
// rendered output via tryParseSeverity; everything else is preserved.
func loadExistingForPreserve(path string, definitions []rule.Definition) (*cfgpkg.Config, error) {
	cfg, err := cfgpkg.Load(path, definitions)
	if err == nil {
		return &cfg, nil
	}
	permissive, permissiveErr := cfgpkg.LoadPermissive(path, definitions)
	if permissiveErr != nil {
		return nil, err
	}
	return &permissive, nil
}

// summarisePreserved builds a one-line stderr notice describing what tuning
// carried over from the existing config. Returns the empty string when no
// preservable values were present.
func summarisePreserved(cfg cfgpkg.Config) string {
	parts := []string{}
	if n := len(cfg.IgnorePaths); n > 0 {
		parts = append(parts, fmt.Sprintf("%d paths.ignore", n))
	}
	if n := len(cfg.AcceptedAbbreviations); n > 0 {
		parts = append(parts, fmt.Sprintf("%d acceptedAbbreviations", n))
	}
	if n := len(cfg.SensitiveData.PreviewAllowlist); n > 0 {
		parts = append(parts, fmt.Sprintf("%d secretPreviews", n))
	}
	if n := len(cfg.Rules); n > 0 {
		parts = append(parts, fmt.Sprintf("%d per-rule overrides", n))
	}
	if n := len(cfg.MinimumSeverity); n > 0 {
		parts = append(parts, fmt.Sprintf("%d minimumSeverity entries", n))
	}
	if len(parts) == 0 {
		return ""
	}
	return "preserved existing tuning: " + strings.Join(parts, ", ") + " (pass --reset to discard)"
}

// writeFreshStartSetupHint points new adopters at the first-run baseline flow
// without creating a baseline implicitly.
func writeFreshStartSetupHint(stdout io.Writer) error {
	if _, err := fmt.Fprintf(stdout, "fresh start for existing findings: gruff-go analyse --generate-baseline %s .\n", defaultBaselineFileName); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "then scan with: gruff-go analyse --baseline %s .\n", defaultBaselineFileName); err != nil {
		return err
	}
	return nil
}
