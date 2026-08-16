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

// extractNoInteraction removes the global non-interactive flag before command dispatch.
// A bare dash or `--` protects later flag-shaped paths from global parsing.
func extractNoInteraction(commandArguments []string) ([]string, bool) {
	remainingArguments := make([]string, 0, len(commandArguments))
	nonInteractiveRequested := false
	// The flag may follow a path until the caller explicitly ends flag parsing.
	for argumentIndex, argument := range commandArguments {
		// Protected operands must reach the command parser unchanged.
		if argument == "--" || argument == "-" {
			remainingArguments = append(remainingArguments, commandArguments[argumentIndex:]...)
			break
		}
		switch argument {
		case "-n", "--no-interaction":
			// Non-interactive mode suppresses first-run prompts even on a terminal.
			nonInteractiveRequested = true
		default:
			// Command-specific tokens pass through unchanged.
			remainingArguments = append(remainingArguments, argument)
		}
	}
	return remainingArguments, nonInteractiveRequested
}

// configuredRegistryInteractive resolves the rule registry and, when no config
// file is on disk and the shell can answer a prompt, offers to generate one
// before falling back to the built-in defaults. Returns the loaded Config so
// callers can consult MinimumSeverity for per-command threshold precedence.
func configuredRegistryInteractive(configPath string, noConfig, interactive bool, promptWriter io.Writer) (rule.Registry, []string, cfgpkg.Config, error) {
	if interactive {
		root, err := os.Getwd()
		if err != nil {
			return rule.Registry{}, nil, cfgpkg.Config{}, err
		}
		if err := maybeBootstrapConfigInRoot(root, configPath, noConfig, promptWriter); err != nil {
			return rule.Registry{}, nil, cfgpkg.Config{}, err
		}
	}
	return configuredRegistry(configPath, noConfig)
}

// maybeBootstrapConfigInRoot prompts to create .gruff-go.yaml when auto-discovery
// inside root would otherwise return no config. It is a no-op when the caller
// supplied --config, asked for --no-config, the shell isn't a TTY, or an
// existing config file is already on disk under root.
func maybeBootstrapConfigInRoot(root, configPath string, noConfig bool, promptWriter io.Writer) error {
	if configPath != "" || noConfig {
		return nil
	}
	if !stdinTerminalCheck() {
		return nil
	}
	_, ok, err := cfgpkg.ResolvePath(root, "")
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	if !promptForDefaultConfig(promptWriter) {
		return nil
	}
	target := filepath.Join(root, defaultConfigFileName)
	result, err := writeDefaultConfig(target, false, false)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(promptWriter, "wrote default config to %s (%d rules)\n", defaultConfigFileName, result.ruleCount); err != nil {
		return err
	}
	if err := writeFreshStartSetupHint(promptWriter); err != nil {
		return err
	}
	return nil
}

// promptForDefaultConfig asks the user whether to generate a default config
// file. Anything other than an explicit "y" or "yes" (case-insensitive) keeps
// the existing built-in defaults so accidental newline-only input never lands
// a file on disk the user did not ask for.
func promptForDefaultConfig(promptWriter io.Writer) bool {
	if _, err := fmt.Fprintf(promptWriter, "no %s found in this directory.\n", defaultConfigFileName); err != nil {
		return false
	}
	if _, err := fmt.Fprint(promptWriter, "Generate one with default settings? [y/N]: "); err != nil {
		return false
	}
	reader := bufio.NewReader(promptStdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		if _, writeErr := fmt.Fprintln(promptWriter); writeErr != nil {
			return false
		}
		return false
	}
	answer := strings.TrimSpace(strings.ToLower(line))
	return answer == "y" || answer == "yes"
}

// stdinIsTerminal enables the first-run prompt only when stdin is an interactive terminal.
// Redirected files, pipes, and /dev/null therefore run without waiting for input.
func stdinIsTerminal() bool {
	return isInteractiveTerminal(os.Stdin)
}
