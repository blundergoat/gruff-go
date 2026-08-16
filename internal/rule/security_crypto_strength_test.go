// Package rule tests crypto and random security rules.
package rule

import (
	"fmt"
	"testing"
)

// TestInsecureRandomSecretRule covers math/rand in secret contexts and safe random lookalikes.
func TestInsecureRandomSecretRule(t *testing.T) {
	tests := []struct {
		name string
		file string
		code string
		want int
	}{
		{
			name: "token assignment",
			file: "random.go",
			code: `// Package sample is a test package.
package sample

import "math/rand"

func buildToken() int {
	token := rand.Intn(999999)
	return token
}
`,
			want: 1,
		},
		{
			name: "aliased nonce read",
			file: "random.go",
			code: `// Package sample is a test package.
package sample

import mathrand "math/rand"

func makeNonce() []byte {
	nonce := make([]byte, 16)
	_, _ = mathrand.Read(nonce)
	return nonce
}
`,
			want: 1,
		},
		{
			name: "session key return",
			file: "random.go",
			code: `// Package sample is a test package.
package sample

import "math/rand"

func sessionKey() int {
	return rand.Int()
}
`,
			want: 1,
		},
		{
			name: "sampling",
			file: "random.go",
			code: `// Package sample is a test package.
package sample

import "math/rand"

func pickSample(values []int) int {
	return values[rand.Intn(len(values))]
}
`,
			want: 0,
		},
		{
			name: "crypto rand token",
			file: "random.go",
			code: `// Package sample is a test package.
package sample

import "crypto/rand"

func buildToken() []byte {
	token := make([]byte, 32)
	_, _ = rand.Read(token)
	return token
}
`,
			want: 0,
		},
		{
			name: "ordinary test sampling",
			file: "random_test.go",
			code: `// Package sample is a test package.
package sample

import (
	"math/rand"
	"testing"
)

func TestSampler(t *testing.T) {
	sample := rand.Intn(10)
	_ = sample
}
`,
			want: 0,
		},
		{
			name: "test production token fixture",
			file: "random_test.go",
			code: `// Package sample is a test package.
package sample

import (
	"math/rand"
	"testing"
)

func TestProductionTokenFixture(t *testing.T) {
	productionToken := rand.Int()
	_ = productionToken
}
`,
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, tt.file, tt.code)
			findings := InsecureRandomSecretRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}

// TestInsecureRandomSecretRuleDistinguishesSelectionFromGeneration pins the
// narrow boundary between choosing an existing key and generating key material.
func TestInsecureRandomSecretRuleDistinguishesSelectionFromGeneration(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "corpus-shaped existing key selection",
			code: `package sample

import "math/rand"

func randomKey(keys []string, enabledIdx []int) (string, int) {
	selectedIdx := enabledIdx[rand.Intn(len(enabledIdx))]
	return keys[selectedIdx], selectedIdx
}
`,
			want: 0,
		},
		{
			name: "aliased selector selection with parentheses",
			code: `package sample

import mathrand "math/rand"

type keyPool struct {
	Keys []string
}

func chooseKey(pool keyPool) string {
	return (pool.Keys)[mathrand.Intn(len((pool.Keys)))]
}
`,
			want: 0,
		},
		{
			name: "alphabet selection into token buffer remains generation",
			code: `package sample

import "math/rand"

func generateToken(size int) string {
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789"
	token := make([]byte, size)
	for index := range token {
		token[index] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(token)
}
`,
			want: 1,
		},
		{
			name: "alphabet selection appended into token remains generation",
			code: `package sample

import "math/rand"

func generateToken(size int) string {
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789"
	token := make([]byte, 0, size)
	for range size {
		token = append(token, alphabet[rand.Intn(len(alphabet))])
	}
	return string(token)
}
`,
			want: 1,
		},
		{
			name: "alphabet selection concatenated into token remains generation",
			code: `package sample

import "math/rand"

func generateToken(size int) string {
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789"
	token := ""
	for range size {
		token += string(alphabet[rand.Intn(len(alphabet))])
	}
	return token
}
`,
			want: 1,
		},
		{
			name: "self-referential concatenation into token remains generation",
			code: `package sample

import "math/rand"

func generateToken(size int) string {
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789"
	token := ""
	for range size {
		token = token + string(alphabet[rand.Intn(len(alphabet))])
	}
	return token
}
`,
			want: 1,
		},
		{
			name: "chars selection appended into token remains generation",
			code: `package sample

import "math/rand"

func generateToken(size int) string {
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	token := make([]byte, 0, size)
	for range size {
		token = append(token, chars[rand.Intn(len(chars))])
	}
	return string(token)
}
`,
			want: 1,
		},
		{
			name: "generic pool selection into token buffer remains generation",
			code: `package sample

import "math/rand"

func generateToken(size int) string {
	pool := "abcdefghijklmnopqrstuvwxyz0123456789"
	token := make([]byte, size)
	for index := range token {
		token[index] = pool[rand.Intn(len(pool))]
	}
	return string(token)
}
`,
			want: 1,
		},
		{
			name: "alphabet selection appended into sample stays safe",
			code: `package sample

import "math/rand"

func buildSample(alphabet string) []byte {
	sample := make([]byte, 0, 1)
	sample = append(sample, alphabet[rand.Intn(len(alphabet))])
	return sample
}
`,
			want: 0,
		},
		{
			name: "key assignment remains generation",
			code: `package sample

import "math/rand"

func issueValue() int {
	key := rand.Intn(100)
	return key
}
`,
			want: 1,
		},
		{
			name: "key-named function remains generation",
			code: `package sample

import "math/rand"

func generateKey() int {
	return rand.Intn(100)
}
`,
			want: 1,
		},
		{
			name: "mismatched collection length remains suspicious",
			code: `package sample

import "math/rand"

func chooseKey(values, other []string) string {
	return values[rand.Intn(len(other))]
}
`,
			want: 1,
		},
		{
			name: "arithmetic bound remains suspicious",
			code: `package sample

import "math/rand"

func chooseKey(values []string) string {
	return values[rand.Intn(len(values)-1)]
}
`,
			want: 1,
		},
		{
			name: "stored index remains suspicious",
			code: `package sample

import "math/rand"

func chooseKey(values []string) string {
	keyIndex := rand.Intn(len(values))
	return values[keyIndex]
}
`,
			want: 1,
		},
		{
			name: "non-Intn index remains suspicious",
			code: `package sample

import "math/rand"

func chooseKey(values []string) string {
	return values[int(rand.Int31n(int32(len(values))))]
}
`,
			want: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			unit := parseOne(t, "selection.go", test.code)
			findings := InsecureRandomSecretRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != test.want {
				t.Fatalf("findings = %#v, want %d", findings, test.want)
			}
		})
	}
}

// TestInsecureRandomSecretRuleIgnoresDestinationBufferName pins that a
// generator named for its secret still reports when the buffer it fills is
// named neutrally, and that the indexed and append spellings of the same
// generator never disagree.
func TestInsecureRandomSecretRuleIgnoresDestinationBufferName(t *testing.T) {
	indexedGenerator := `package sample

import "math/rand"

func generateToken(size int) string {
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789"
	%[1]s := make([]byte, size)
	for index := range %[1]s {
		%[1]s[index] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(%[1]s)
}
`
	appendGenerator := `package sample

import "math/rand"

func generateToken(size int) string {
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789"
	%[1]s := make([]byte, 0, size)
	for range size {
		%[1]s = append(%[1]s, alphabet[rand.Intn(len(alphabet))])
	}
	return string(%[1]s)
}
`
	for _, bufferName := range []string{"token", "buf", "out", "result"} {
		t.Run(bufferName, func(t *testing.T) {
			indexed := InsecureRandomSecretRule{}.AnalyzeUnit(
				parseOne(t, "indexed.go", fmt.Sprintf(indexedGenerator, bufferName)), Context{})
			appended := InsecureRandomSecretRule{}.AnalyzeUnit(
				parseOne(t, "append.go", fmt.Sprintf(appendGenerator, bufferName)), Context{})
			if len(indexed) != 1 {
				t.Errorf("indexed %q findings = %#v, want 1", bufferName, indexed)
			}
			if len(appended) != 1 {
				t.Errorf("append %q findings = %#v, want 1", bufferName, appended)
			}
			if len(indexed) != len(appended) {
				t.Errorf("indexed %q reported %d findings but append reported %d; both spell the same generator",
					bufferName, len(indexed), len(appended))
			}
		})
	}
}

// TestWeakCryptoRule covers weak digest contexts, obsolete ciphers, and small RSA keys.
func TestWeakCryptoRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "md5 password hash",
			code: `// Package sample is a test package.
package sample

import "crypto/md5"

func HashPassword(password string) [16]byte {
	return md5.Sum([]byte(password))
}
`,
			want: 1,
		},
		{
			name: "sha1 token signature",
			code: `// Package sample is a test package.
package sample

import "crypto/sha1"

func tokenSignature(token string) [20]byte {
	digest := sha1.Sum([]byte(token))
	return digest
}
`,
			want: 1,
		},
		{
			name: "des cipher",
			code: `// Package sample is a test package.
package sample

import "crypto/des"

func buildCipher(key []byte) {
	_, _ = des.NewCipher(key)
}
`,
			want: 1,
		},
		{
			name: "rc4 cipher",
			code: `// Package sample is a test package.
package sample

import "crypto/rc4"

func buildCipher(key []byte) {
	_, _ = rc4.NewCipher(key)
}
`,
			want: 1,
		},
		{
			name: "small rsa key",
			code: `// Package sample is a test package.
package sample

import (
	"crypto/rand"
	"crypto/rsa"
)

func buildKey() {
	_, _ = rsa.GenerateKey(rand.Reader, 1024)
}
`,
			want: 1,
		},
		{
			name: "md5 checksum",
			code: `// Package sample is a test package.
package sample

import "crypto/md5"

func checksum(data []byte) [16]byte {
	return md5.Sum(data)
}
`,
			want: 0,
		},
		{
			name: "sha1 checksum",
			code: `// Package sample is a test package.
package sample

import "crypto/sha1"

func contentDigest(data []byte) [20]byte {
	sum := sha1.Sum(data)
	return sum
}
`,
			want: 0,
		},
		{
			name: "rsa 2048 key",
			code: `// Package sample is a test package.
package sample

import (
	"crypto/rand"
	"crypto/rsa"
)

func buildKey() {
	_, _ = rsa.GenerateKey(rand.Reader, 2048)
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "crypto.go", tt.code)
			findings := WeakCryptoRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}

// TestWeakCryptoRulePreservesKeyContext keeps key-only weak-digest derivation
// visible while a neutral checksum remains outside the contextual rule.
func TestWeakCryptoRulePreservesKeyContext(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "md5 key derivation",
			code: `package sample

import "crypto/md5"

func deriveKey(input []byte) [16]byte {
	return md5.Sum(input)
}
`,
			want: 1,
		},
		{
			name: "sha1 key digest",
			code: `package sample

import "crypto/sha1"

func keyDigest(input []byte) [20]byte {
	return sha1.Sum(input)
}
`,
			want: 1,
		},
		{
			name: "neutral checksum",
			code: `package sample

import "crypto/md5"

func checksum(input []byte) [16]byte {
	return md5.Sum(input)
}
`,
			want: 0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			unit := parseOne(t, "crypto.go", test.code)
			findings := WeakCryptoRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != test.want {
				t.Fatalf("findings = %#v, want %d", findings, test.want)
			}
		})
	}
}
