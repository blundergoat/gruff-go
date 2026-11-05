// Command gruff-go scans Go projects for parser-only code-quality signals.
//
// Its mission is to govern AI-generated code: as a coding-agent hook, it pushes output toward what a human reviewer can verify and sign off on.
// That means code legible enough to review, secure where the eye fails, and tested for real rather than padded with low-signal ceremony.
//
// It runs in local development, CI and coding-agent loops, discovering Go source and parsing it with the Go standard library.
// Its built-in rules report findings for complexity, dead code, design, documentation, maintainability and modernisation.
// They also cover naming, security, sensitive data, size and test quality; design findings do not change the score.
//
// Reports can be written as terminal text, JSON, summary JSON, SARIF, GitHub Actions annotations, standalone HTML, or a local browser dashboard.
//
// Install the command with:
//
//	go install github.com/blundergoat/gruff-go/cmd/gruff-go@latest
//
// For implementation details, see internal/cli.
package main
