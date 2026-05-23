// Command gruff-go scans Go projects for parser-only code-quality signals.
//
// It is intended for local development and CI. The command discovers Go source,
// parses it with the Go standard library, runs the built-in rule registry, and
// scores findings across complexity, dead code, design, documentation, naming,
// security, sensitive data, size, and test quality.
//
// Reports can be written as terminal text, JSON, summary JSON, SARIF, GitHub
// Actions annotations, standalone HTML, or a local browser dashboard.
//
// Install the command with:
//
//	go install github.com/blundergoat/gruff-go/cmd/gruff-go@latest
//
// For implementation details, see internal/cli.
package main
