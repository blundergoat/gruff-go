// Package rule defines gruff-go's rule registry and analysers.
// This file locks in P1 of the cross-port rubric (ADR-017 item 1): identifier
// tokenization must preserve digit runs rather than fold or strip them, so a
// real name like sha256 is never mistaken for a placeholder.
package rule

import (
	"strings"
	"testing"
	"unicode"
)

// TestSplitIdentifierTokensPreservesDigits guards the P1 invariant: every digit
// in an identifier survives tokenization as its own token and is never merged
// into a stem. It asserts two properties rather than an exact split so the test
// tracks the invariant, not the boundary heuristics: the tokens rejoin to the
// original name (nothing dropped), and at least one token is a standalone digit
// run. The inputs are the rubric's canonical domain identifiers - flagging any of
// these as a numbered placeholder is exactly what P1 forbids.
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

// hasStandaloneDigitToken reports whether any token is a non-empty run of only
// digits - the signal that the tokenizer kept a digit run as its own token.
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
