// Package cli implements the gruff-go command-line interface.
//
// This file accepts flags on either side of positional arguments while preserving standard end-of-flags behavior.
// Commands that accept command-specific flags use this path so a trailing flag cannot become a scan path.
package cli

import (
	"flag"
	"strings"
)

// parseCommandArguments accepts flags before, between, or after positional arguments.
//
// Use it instead of FlagSet.Parse so trailing flags are validated rather than treated as paths.
// Tokens after a -- terminator, or from a bare dash onward, stay positional and keep their order.
//
// flagSet receives the parsed flag values and the operands later returned by its Args; commandArguments holds the raw tokens in user order.
// It returns any error flagSet.Parse reports, such as an unknown flag or an invalid flag value.
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
//
// Callers handle a bare dash first because it ends parsing instead of naming a flag.
//
// argument is one command-line token.
// It reports true when argument is longer than one character and begins with a dash, so -- also matches; it reports false otherwise.
func hasFlagSyntax(argument string) bool {
	return len(argument) > 1 && argument[0] == '-'
}

// flagHasSeparateValue reports whether a registered flag takes its value from the next token.
//
// It is false for a token with an inline =value, a positional token, an unknown flag, or a Boolean flag.
// An unknown flag never takes the next token, so a typo such as --fromat json reaches FlagSet alone and gets its canonical parsing error.
//
// flagSet supplies the registered flags looked up by name, and argument is the token being classified.
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

// parseFlagArgument returns the canonical FlagSet name and whether the token carries an inline =value.
//
// Positional tokens return an empty name so callers cannot consume a following path by mistake.
// argument is one command-line token; one or two leading dashes are stripped and the name ends at the first equals sign.
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

// helpRequested reports whether -h or --help appears before an explicit parsing terminator.
//
// commandArguments holds the raw tokens, and hasSeparateValue reports whether a flag-shaped token owns the next token, which is then skipped.
// That predicate keeps --help in --config --help attached to --config as its value, so it does not request help.
//
// It reports false when no -h or --help is found before a - or -- that no flag consumed; a -- taken as a flag value does not end the search.
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
