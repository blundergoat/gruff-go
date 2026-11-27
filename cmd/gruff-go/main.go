package main

import (
	"os"

	"github.com/blundergoat/gruff-go/internal/cli"
)

// main is the process entrypoint for every gruff-go subcommand, such as analyse, hook, baseline and dashboard.
//
// It passes the arguments after the program name to cli.Main and exits with the code it returns, which the shell or CI job then sees.
// Keeping this a one-line delegation lets tests drive cli.Main directly with fake args, stdout and stderr instead of spawning a subprocess.
func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
