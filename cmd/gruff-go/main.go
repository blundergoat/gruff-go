package main

import (
	"os"

	"github.com/blundergoat/gruff-go/internal/cli"
)

// main keeps the process entrypoint a one-line delegation to cli.Main so the
// CLI can be driven directly from tests (passing fake args/stdout/stderr)
// instead of having to spawn a subprocess; everything interesting lives in the
// cli package.
func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
