// Package cli implements the gruff-go command-line interface.
//
// prompt.go owns the bootstrap that asks adopters to generate a .gruff-go.yaml when one is missing.
// The stdin TTY probe skips that prompt under non-interactive shells like CI runners and pipelines.
// extractNoInteraction strips the global -n or --no-interaction flag, which suppresses the prompt even on a terminal.
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

// stdinTerminalCheck reports whether stdin should be treated as a TTY for the prompt-gating decision.
//
// Tests override it so they can exercise the affirmative path without a real terminal attached.
var stdinTerminalCheck = stdinIsTerminal

// extractNoInteraction removes the global non-interactive flag before command dispatch.
// A bare dash or `--` protects later flag-shaped paths from global parsing.
//
// commandArguments is scanned in order: each -n or --no-interaction before the first bare dash or `--` is removed, all other tokens kept.
// Returns the remaining arguments in their original order, with the bare dash or `--` and every token after it passed through unchanged,
// and true when at least one -n or --no-interaction was removed, otherwise false; an input of only those flags yields an empty slice.
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

// configuredRegistryInteractive resolves the rule registry for a scanning command, first offering to write a config when none is on disk.
//
// The offer needs a shell that can answer a prompt; without one, or when the user declines, the built-in defaults apply.
// Callers consult the returned Config's FailOn for per-command exit thresholds and MinimumSeverity for the display floor.
//
// configPath is an explicit config file path, empty for auto-discovery, and noConfig asks for no config; either one skips the prompt.
// interactive enables root discovery and the prompt step, promptWriter receives its text, and targets are the scan paths that locate the root.
//
// Returns the registry, the config's IgnorePaths and the loaded Config from configuredRegistry, which receives configPath, noConfig and targets;
// with no config file in use they are rule.Defaults(), nil and a zero Config.
// Any error comes with zero values: an unreadable launch directory, a failed maybeBootstrapConfigInRoot, or a config or rule-option load failure.
func configuredRegistryInteractive(configPath string, noConfig, interactive bool, promptWriter io.Writer, targets []string) (rule.Registry, []string, cfgpkg.Config, error) {
	if interactive {
		root, err := configDiscoveryRoot(configPath, targets)
		if err != nil {
			return rule.Registry{}, nil, cfgpkg.Config{}, err
		}
		if err := maybeBootstrapConfigInRoot(root, configPath, noConfig, promptWriter); err != nil {
			// Accepting the prompt in a read-only project root fails the write here, and the command stops before scanning.
			return rule.Registry{}, nil, cfgpkg.Config{}, err
		}
	}
	return configuredRegistry(configPath, noConfig, targets)
}

// maybeBootstrapConfigInRoot prompts to create .gruff-go.yaml in root when auto-discovery there would otherwise find no config.
//
// It does nothing when the user passed --config or --no-config, when stdin is not a TTY, or when a config file already exists under root.
//
// configPath carries --config and noConfig carries --no-config; promptWriter receives the question, the success line and the setup hint.
// The error is non-nil when the config lookup under root, the default config write, or writing the success line or hint to promptWriter fails.
// Every skipped case, a declined or unanswerable prompt, and a successful write return nil.
func maybeBootstrapConfigInRoot(root, configPath string, noConfig bool, promptWriter io.Writer) error {
	if configPath != "" || noConfig {
		return nil
	}
	// Non-terminal stdin, such as a pipe, a redirected file or /dev/null, skips the first-run config prompt without reading an answer.
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
	// A blank Enter or any answer other than y or yes lands here, and the run continues on built-in defaults without writing a file.
	if !promptForDefaultConfig(promptWriter) {
		return nil
	}
	target := filepath.Join(root, defaultConfigFileName)
	result, err := writeDefaultConfig(target, false, false)
	if err != nil {
		// A read-only root, or a .gruff-go.yaml another process created after the lookup above, fails the write here and nothing is overwritten.
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

// promptForDefaultConfig asks the user whether to generate a default .gruff-go.yaml, after saying none was found in this directory.
//
// Only y or yes, in any letter case, accepts; any other answer keeps the built-in defaults.
// A bare Enter therefore never lands a file on disk the user did not ask for.
//
// promptWriter receives the missing-file notice and the y/N question, and the answer is read as one line from promptStdin.
// Reports true only for a y or yes answer, and false for any other answer, for input that ends before any text, or on a failed promptWriter write.
func promptForDefaultConfig(promptWriter io.Writer) bool {
	if _, err := fmt.Fprintf(promptWriter, "no %s found in this directory.\n", defaultConfigFileName); err != nil {
		return false
	}
	if _, err := fmt.Fprint(promptWriter, "Generate one with default settings? [y/N]: "); err != nil {
		return false
	}
	reader := bufio.NewReader(promptStdin)
	line, err := reader.ReadString('\n')
	// Ctrl-D at the prompt with nothing typed lands here: a newline tidies the terminal and the built-in defaults apply.
	if err != nil && line == "" {
		if _, writeErr := fmt.Fprintln(promptWriter); writeErr != nil {
			return false
		}
		return false
	}
	// Text returned before end of input still counts as the answer, so y or yes without a trailing newline accepts.
	answer := strings.TrimSpace(strings.ToLower(line))
	return answer == "y" || answer == "yes"
}

// stdinIsTerminal enables the first-run prompt only when stdin is an interactive terminal.
//
// Redirected files, pipes and /dev/null therefore skip the first-run config prompt.
// Reports true when isInteractiveTerminal accepts os.Stdin as an interactive terminal, and false otherwise, which skips the prompt.
func stdinIsTerminal() bool {
	return isInteractiveTerminal(os.Stdin)
}
