// Package rule defines gruff-go's rule registry and analysers.
//
// This file locks in P1 of the cross-port rubric (ADR-017 item 1): identifier tokenization must keep digit runs, never fold or strip them.
// Names such as sha256 must rejoin unchanged and keep a standalone digit token.
package rule

import (
	"strings"
	"testing"
	"unicode"
)

// TestSplitIdentifierTokensPreservesDigits checks that each listed name rejoins unchanged and yields at least one token made only of digits.
//
// It does not pin the exact split, so boundary heuristics can change; the names are canonical identifiers P1 forbids flagging as placeholders.
// A failure means splitIdentifierTokens dropped characters or left no digit run as a token of its own.
func TestSplitIdentifierTokensPreservesDigits(t *testing.T) {
	for _, name := range []string{"sha256", "parseHTTP2Header", "step0", "v2", "adr020", "base64", "utf8"} {
		tokens := splitIdentifierTokens(name)
		if strings.Join(tokens, "") != name {
			t.Errorf("splitIdentifierTokens(%q) = %#v dropped characters; digits must be preserved", name, tokens)
		}
		if !hasStandaloneDigitToken(tokens) {
			t.Errorf("splitIdentifierTokens(%q) = %#v folded its digit run into a stem; digits must tokenize on their own", name, tokens)
		}
	}
}

// hasStandaloneDigitToken reports whether any token is a non-empty run of only digits, the sign the tokenizer kept a digit run as its own token.
// The tokens slice is tokenizer output; the result is false for nil or empty tokens, or when no non-empty entry consists only of digits.
func hasStandaloneDigitToken(tokens []string) bool {
	for _, token := range tokens {
		if token == "" {
			continue
		}
		allDigits := true
		for _, r := range token {
			if !unicode.IsDigit(r) {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	return false
}
