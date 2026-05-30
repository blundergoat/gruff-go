// Command gruff-go scans Go projects for parser-only code-quality signals.
//
// Its mission is to govern AI-generated code: used as a coding-agent hook, it
// forces output a human who didn't write it can verify, trust, and sign off on -
// legible enough to review, secure where the eye fails, and tested for real
// rather than padded with low-signal ceremony.
//
// It is intended for local development, CI, and coding-agent loops. The command
// discovers Go source, parses it with the Go standard library, runs the built-in
// rule registry, and scores findings across complexity, dead code, design,
// documentation, maintainability, modernisation, naming, security, sensitive
// data, size, and test quality.
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
