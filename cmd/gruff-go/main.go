// Command gruff-go runs the local code quality scanner CLI.
// It delegates to the cli package and forwards the resulting exit code.
package main

import (
	"os"

	"github.com/blundergoat/gruff-go/internal/cli"
)

// main is the process entrypoint that dispatches to the cli package.
func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
