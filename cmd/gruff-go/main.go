// Command gruff-go runs the local code quality scanner CLI.
package main

import (
	"os"

	"github.com/blundergoat/gruff-go/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
