// Package cli implements the gruff-go command-line interface.
// This file accepts flags on either side of positional arguments while preserving standard
// end-of-flags behavior. Every command uses this path so a trailing flag cannot become a scan path.
package cli

import (
	"flag"
	"strings"
)

// parseCommandArguments accepts flags before, between, or after positional arguments.
// Use it instead of FlagSet.Parse so trailing flags are validated rather than treated as paths.
func parseCommandArguments(flagSet *flag.FlagSet, commandArguments []string) error {
	flagArguments := make([]string, 0, len(commandArguments))
	positionalArguments := make([]string, 0, len(commandArguments))

	// Preserve the user's positional order while collecting every flag for the standard parser.
scanArguments:
	for argumentIndex := 0; argumentIndex < len(commandArguments); argumentIndex++ {
		argument := commandArguments[argumentIndex]
		switch {
		// `--` lets callers pass paths whose names begin with a dash.
		case argument == "--":
			positionalArguments = append(positionalArguments, commandArguments[argumentIndex+1:]...)
			break scanArguments
		// A bare dash conventionally names stdin and protects every later token from flag parsing.
		case argument == "-":
			positionalArguments = append(positionalArguments, commandArguments[argumentIndex:]...)
			break scanArguments
		// Flag-shaped tokens must reach FlagSet even when they follow a path.
		case hasFlagSyntax(argument):
			flagArguments = append(flagArguments, argument)
			// A registered non-Boolean flag owns its next token, including a leading-dash value.
			if flagHasSeparateValue(flagSet, argument) && argumentIndex+1 < len(commandArguments) {
				argumentIndex++
				flagArguments = append(flagArguments, commandArguments[argumentIndex])
			}
		// Ordinary operands remain in the order the caller supplied them.
		default:
			positionalArguments = append(positionalArguments, argument)
		}
	}

	// FlagSet stops at its first operand, so a synthetic terminator keeps reordered operands positional.
	parseArguments := make([]string, 0, len(flagArguments)+len(positionalArguments)+1)
	parseArguments = append(parseArguments, flagArguments...)
	parseArguments = append(parseArguments, "--")
	parseArguments = append(parseArguments, positionalArguments...)
	return flagSet.Parse(parseArguments)
}

// hasFlagSyntax identifies tokens that FlagSet must validate.
// Callers handle a bare dash first because it ends parsing instead of naming a flag.
func hasFlagSyntax(argument string) bool {
	return len(argument) > 1 && argument[0] == '-'
}

// flagHasSeparateValue reports whether a registered flag takes its value from the next token.
// Unknown flags stay separate so FlagSet can emit its canonical parsing error.
func flagHasSeparateValue(flagSet *flag.FlagSet, argument string) bool {
	flagName, hasInlineValue := parseFlagArgument(argument)
	// An inline assignment is complete, and a token without a flag name cannot own the next argument.
	if flagName == "" || hasInlineValue {
		return false
	}
	registeredFlag := flagSet.Lookup(flagName)
	// An unknown flag must reach FlagSet untouched so the caller sees a flag error rather than a path error.
	if registeredFlag == nil {
		return false
	}
	// Boolean flags are complete without consuming the token that follows them.
	if booleanFlag, ok := registeredFlag.Value.(interface{ IsBoolFlag() bool }); ok && booleanFlag.IsBoolFlag() {
		return false
	}
	return true
}

// parseFlagArgument returns the canonical FlagSet name and whether the token includes `=value`.
// Positional tokens return an empty name so callers cannot consume a following path by mistake.
func parseFlagArgument(argument string) (string, bool) {
	// Positional input has no name in the command's FlagSet.
	if !hasFlagSyntax(argument) {
		return "", false
	}
	flagName := argument[1:]
	// FlagSet accepts both `-name` and `--name`; its lookup key excludes either prefix.
	if strings.HasPrefix(flagName, "-") {
		flagName = flagName[1:]
	}
	// An equals sign keeps the value attached even when that value begins with a dash.
	if separator := strings.IndexByte(flagName, '='); separator >= 0 {
		return flagName[:separator], true
	}
	return flagName, false
}

// helpRequested reports whether a help flag appears before an explicit parsing terminator.
// The value predicate keeps a token such as `--config --help` attached to the preceding flag.
func helpRequested(commandArguments []string, hasSeparateValue func(string) bool) bool {
	// Only tokens before the first terminator can request command help.
	for argumentIndex := 0; argumentIndex < len(commandArguments); argumentIndex++ {
		argument := commandArguments[argumentIndex]
		// A help-shaped token after `-` or `--` is positional input.
		if argument == "--" || argument == "-" {
			return false
		}
		// Either documented spelling displays command help.
		if argument == "-h" || argument == "--help" {
			return true
		}
		// A value owned by another flag cannot independently request help.
		if hasFlagSyntax(argument) && hasSeparateValue(argument) {
			argumentIndex++
		}
	}
	return false
}
