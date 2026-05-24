// Package cli implements the gruff-go command-line interface.
// prompt.go owns the bootstrap that asks adopters to generate a .gruff-go.yaml
// when one is missing, plus the stdin TTY probe used to skip the prompt under
// non-interactive shells like CI runners and pipelines.
package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// promptStdin is the reader the bootstrap consults when prompting. Tests swap
// it in place of os.Stdin so they can drive the y/N answer deterministically.
var promptStdin io.Reader = os.Stdin

// stdinTerminalCheck reports whether stdin should be treated as a TTY for the
// prompt-gating decision. Tests override it so they can exercise the
// affirmative path without a real terminal attached.
var stdinTerminalCheck = stdinIsTerminal

// extractNoInteraction removes -n / --no-interaction from args and reports
// whether the flag was set. The flag is global, so it can appear at any
// position alongside -q/--quiet and the ANSI flags.
func extractNoInteraction(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	noInteraction := false
	for _, arg := range args {
		switch arg {
		case "-n", "--no-interaction":
			noInteraction = true
		default:
			out = append(out, arg)
		}
	}
	return out, noInteraction
}

// configuredRegistryInteractive resolves the rule registry and, when no config
// file is on disk and the shell can answer a prompt, offers to generate one
// before falling back to the built-in defaults.
func configuredRegistryInteractive(configPath string, noConfig, interactive bool, stdout io.Writer) (rule.Registry, []string, error) {
	if interactive {
		root, err := os.Getwd()
		if err != nil {
			return rule.Registry{}, nil, err
		}
		if err := maybeBootstrapConfigInRoot(root, configPath, noConfig, stdout); err != nil {
			return rule.Registry{}, nil, err
		}
	}
	return configuredRegistry(configPath, noConfig)
}

// maybeBootstrapConfigInRoot prompts to create .gruff-go.yaml when auto-discovery
// inside root would otherwise return no config. It is a no-op when the caller
// supplied --config, asked for --no-config, the shell isn't a TTY, or an
// existing config file is already on disk under root.
func maybeBootstrapConfigInRoot(root, configPath string, noConfig bool, stdout io.Writer) error {
	if configPath != "" || noConfig {
		return nil
	}
	if !stdinTerminalCheck() {
		return nil
	}
	resolved, ok, err := cfgpkg.ResolvePath(root, "")
	if err != nil {
		return err
	}
	if ok {
		_ = resolved
		return nil
	}
	if !promptForDefaultConfig(stdout) {
		return nil
	}
	target := filepath.Join(root, defaultConfigFileName)
	result, err := writeDefaultConfig(target, false, false)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote default config to %s (%d rules)\n", defaultConfigFileName, result.ruleCount)
	writeFreshStartSetupHint(stdout)
	return nil
}

// promptForDefaultConfig asks the user whether to generate a default config
// file. Anything other than an explicit "y" or "yes" (case-insensitive) keeps
// the existing built-in defaults so accidental newline-only input never lands
// a file on disk the user did not ask for.
func promptForDefaultConfig(stdout io.Writer) bool {
	fmt.Fprintf(stdout, "no %s found in this directory.\n", defaultConfigFileName)
	fmt.Fprint(stdout, "Generate one with default settings? [y/N]: ")
	reader := bufio.NewReader(promptStdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(stdout)
		return false
	}
	answer := strings.TrimSpace(strings.ToLower(line))
	return answer == "y" || answer == "yes"
}

// stdinIsTerminal reports whether os.Stdin is a character device, mirroring
// the heuristic isTerminalWriter uses for the stdout/stderr ANSI decision so
// CI runners, pipes, and redirected stdin all skip the prompt automatically.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
