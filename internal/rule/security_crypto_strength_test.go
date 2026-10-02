// Package rule tests the security warnings developers receive for random values and weak crypto.
//
// These cases distinguish existing-key selection and storage buckets from generated secrets and key material.
// Run them when changing crypto detection so safe lookalikes stay quiet and security uses remain visible.
package rule

import (
	"fmt"
	"testing"
)

// lowerAlphanumerics is the keyspace the generator fixtures draw from.
// It is joined from two halves so gruff-go's own entropy rule never reads one 36-character literal as a possible secret.
const lowerAlphanumerics = "abcdefghijklmnopqr" + "stuvwxyz0123456789"

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
	// Scan each fixture to check which random uses produce a security warning.
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			unit := parseOne(t, testCase.file, testCase.code)
			findings := InsecureRandomSecretRule{}.AnalyzeUnit(unit, Context{})
			// An unexpected warning count means the developer would see missing or extra security advice.
			if len(findings) != testCase.want {
				t.Fatalf("findings = %#v, want %d", findings, testCase.want)
			}
		})
	}
}

// TestInsecureRandomSecretRuleDistinguishesSelectionFromGeneration pins the narrow boundary between choosing an existing key and generating key
// material.
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
	alphabet := "` + lowerAlphanumerics + `"
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
	alphabet := "` + lowerAlphanumerics + `"
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
	alphabet := "` + lowerAlphanumerics + `"
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
	alphabet := "` + lowerAlphanumerics + `"
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
	chars := "` + lowerAlphanumerics + `"
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
	pool := "` + lowerAlphanumerics + `"
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
	// Check both existing-key selection and generated key material against their expected scan results.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			unit := parseOne(t, "selection.go", test.code)
			findings := InsecureRandomSecretRule{}.AnalyzeUnit(unit, Context{})
			// Keep selection quiet while generated secrets retain the expected warning.
			if len(findings) != test.want {
				t.Fatalf("findings = %#v, want %d", findings, test.want)
			}
		})
	}
}

// TestInsecureRandomSecretRuleIgnoresDestinationBufferName keeps secret generators visible with neutral buffer names.
// Indexed and append forms must give the developer the same warning.
func TestInsecureRandomSecretRuleIgnoresDestinationBufferName(t *testing.T) {
	indexedGenerator := `package sample

import "math/rand"

func generateToken(size int) string {
	alphabet := "` + lowerAlphanumerics + `"
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
	alphabet := "` + lowerAlphanumerics + `"
	%[1]s := make([]byte, 0, size)
	for range size {
		%[1]s = append(%[1]s, alphabet[rand.Intn(len(alphabet))])
	}
	return string(%[1]s)
}
`
	// Try each observed buffer name so a neutral destination cannot hide secret generation.
	for _, bufferName := range []string{"token", "buf", "out", "result"} {
		t.Run(bufferName, func(t *testing.T) {
			indexed := InsecureRandomSecretRule{}.AnalyzeUnit(
				parseOne(t, "indexed.go", fmt.Sprintf(indexedGenerator, bufferName)), Context{})
			appended := InsecureRandomSecretRule{}.AnalyzeUnit(
				parseOne(t, "append.go", fmt.Sprintf(appendGenerator, bufferName)), Context{})
			// The indexed generator must still warn when the developer chooses this buffer name.
			if len(indexed) != 1 {
				t.Errorf("indexed %q findings = %#v, want 1", bufferName, indexed)
			}
			// The append generator must expose the same security risk.
			if len(appended) != 1 {
				t.Errorf("append %q findings = %#v, want 1", bufferName, appended)
			}
			// Equivalent generation forms must show the developer the same warning count.
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
	// Scan each weak primitive and safe checksum fixture against its expected warning count.
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			unit := parseOne(t, "crypto.go", testCase.code)
			findings := WeakCryptoRule{}.AnalyzeUnit(unit, Context{})
			// A count mismatch changes the security advice the developer receives.
			if len(findings) != testCase.want {
				t.Fatalf("findings = %#v, want %d", findings, testCase.want)
			}
		})
	}
}

// TestWeakCryptoRulePreservesKeyContext keeps key-only weak-digest derivation visible while a neutral checksum remains outside the contextual rule.
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
	// Check that key derivation stays visible while a neutral checksum remains quiet.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			unit := parseOne(t, "crypto.go", test.code)
			findings := WeakCryptoRule{}.AnalyzeUnit(unit, Context{})
			// A key-shaped digest must retain the expected security warning.
			if len(findings) != test.want {
				t.Fatalf("findings = %#v, want %d", findings, test.want)
			}
		})
	}
}

// TestWeakCryptoBucketProofRejectsEscapingValues keeps aliases and unknown digest consumers reportable.
func TestWeakCryptoBucketProofRejectsEscapingValues(t *testing.T) {
	tests := []struct {
		name  string
		input string
		index string
	}{
		{"secret through alias", "input := []byte(secretToken)", "digest.Sum(nil)[0]"},
		{"rebound input", "input := []byte(itemID); input = []byte(secretToken)", "digest.Sum(nil)[0]"},
		{"rebound parameter", "itemID = secretToken; input := []byte(itemID)", "digest.Sum(nil)[0]"},
		{"borrowed input", "input := []byte(itemID); change(input)", "digest.Sum(nil)[0]"},
		{"unknown byte consumer", "input := []byte(itemID)", "saveToken(digest.Sum(nil)[0])"},
		{"shadowed byte conversion", "uint8 := saveToken; input := []byte(itemID)", "uint8(digest.Sum(nil)[0])"},
	}
	// Try each alias or escaping value that prevents a complete storage-only proof.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code := fmt.Sprintf(`package sample
import ("crypto/md5"; "strconv")
func BucketKey(itemID, secretToken string) string {
    digest := md5.New()
    %s
    _, _ = digest.Write(input)
    bucketIndex := %s
    return "bucket" + strconv.Itoa(int(bucketIndex))
}
`, test.input, test.index)
			findings := WeakCryptoRule{}.AnalyzeUnit(parseOne(t, "crypto.go", code), Context{})
			// An unproved bucket-shaped flow must still show the developer one weak-crypto warning.
			if len(findings) != 1 {
				t.Fatalf("got %d weak-crypto warnings, want 1", len(findings))
			}
		})
	}
}

// TestWeakCryptoRuleDistinguishesBucketIndexFromKeyMaterial checks what a developer sees when a storage bucket uses one digest byte.
// A full digest key or secret input still needs a security warning.
func TestWeakCryptoRuleDistinguishesBucketIndexFromKeyMaterial(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "storage bucket index",
			code: `package sample
import (
    "crypto/md5"
    "strconv"
)
type StoragePacker struct { viewPrefix string }
// BucketKey returns the storage key of the bucket where the item will be stored.
func (s *StoragePacker) BucketKey(itemID string) string {
    hf := md5.New()
    input := []byte(itemID)
    _, _ = hf.Write(input)
    index := uint8(hf.Sum(nil)[0])
    return s.viewPrefix + strconv.Itoa(int(index))
}
`,
			want: 0,
		},
		{
			name: "aliased sha1 bucket index",
			code: `package sample
import (
    hash "crypto/sha1"
    "strconv"
)
type Store struct { prefix string }
func (s *Store) BucketKey(itemID string) string {
    digest := hash.New()
    _, _ = digest.Write([]byte(itemID))
    bucketIndex := digest.Sum(nil)[0]
    return s.prefix + strconv.Itoa(int(bucketIndex))
}
`,
			want: 0,
		},
		{
			name: "full digest key",
			code: `package sample
import (
    "crypto/md5"
    "encoding/hex"
)
func BucketKey(itemID string) string {
    digest := md5.New()
    _, _ = digest.Write([]byte(itemID))
    return hex.EncodeToString(digest.Sum(nil))
}
`,
			want: 1,
		},
		{
			name: "secret input to bucket index",
			code: `package sample
import (
    "crypto/md5"
    "strconv"
)
func BucketKey(secretToken string) string {
    digest := md5.New()
    _, _ = digest.Write([]byte(secretToken))
    bucketIndex := digest.Sum(nil)[0]
    return "bucket" + strconv.Itoa(int(bucketIndex))
}
`,
			want: 1,
		},
		{
			name: "authentication bucket key",
			code: `package sample
import (
    "crypto/md5"
    "strconv"
)
func AuthBucketKey(itemID string) string {
    digest := md5.New()
    _, _ = digest.Write([]byte(itemID))
    bucketIndex := digest.Sum(nil)[0]
    return "bucket" + strconv.Itoa(int(bucketIndex))
}
`,
			want: 1,
		},
		{
			name: "authentication suffix after bucket key",
			code: `package sample
import (
    "crypto/md5"
    "strconv"
)
func BucketKeyAuth(itemID string) string {
    digest := md5.New()
    _, _ = digest.Write([]byte(itemID))
    bucketIndex := digest.Sum(nil)[0]
    return "bucket" + strconv.Itoa(int(bucketIndex))
}
`,
			want: 1,
		},
		{
			name: "security named hasher in bucket flow",
			code: `package sample
import (
    "crypto/md5"
    "strconv"
)
func BucketKey(itemID string) string {
    keyHasher := md5.New()
    _, _ = keyHasher.Write([]byte(itemID))
    bucketIndex := keyHasher.Sum(nil)[0]
    return "bucket" + strconv.Itoa(int(bucketIndex))
}
`,
			want: 1,
		},
		{
			name: "authentication comment on bucket index",
			code: `package sample
import (
    "crypto/md5"
    "strconv"
)
// BucketKey builds a token for authentication.
func BucketKey(itemID string) string {
    digest := md5.New()
    _, _ = digest.Write([]byte(itemID))
    bucketIndex := digest.Sum(nil)[0]
    return "bucket" + strconv.Itoa(int(bucketIndex))
}
`,
			want: 1,
		},
		{
			name: "bucket index reused as token",
			code: `package sample
import (
    "crypto/md5"
    "strconv"
)
func BucketKey(itemID string) string {
    digest := md5.New()
    _, _ = digest.Write([]byte(itemID))
    bucketIndex := digest.Sum(nil)[0]
    token := strconv.Itoa(int(bucketIndex))
    _ = token
    return "bucket" + strconv.Itoa(int(bucketIndex))
}
`,
			want: 1,
		},
		{
			name: "local conversion shadows strconv",
			code: `package sample
import (
    "crypto/md5"
    "strconv"
)
var _ = strconv.Itoa
type localFormatter struct{}
func (localFormatter) Itoa(value int) string { return "credential" }
func BucketKey(itemID string) string {
    strconv := localFormatter{}
    digest := md5.New()
    _, _ = digest.Write([]byte(itemID))
    bucketIndex := digest.Sum(nil)[0]
    return "bucket" + strconv.Itoa(int(bucketIndex))
}
`,
			want: 1,
		},
	}
	// Compare storage-only bucket flows with nearby uses that return key material.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			unit := parseOne(t, "crypto.go", test.code)
			findings := WeakCryptoRule{}.AnalyzeUnit(unit, Context{})
			// The warning count must match the value's proved role in the scanned function.
			if len(findings) != test.want {
				t.Fatalf("findings = %#v, want %d", findings, test.want)
			}
		})
	}
}

// TestWeakCryptoBucketInputLengthObservations preserves Vault's error check without permitting a shadowed mutator.
func TestWeakCryptoBucketInputLengthObservations(t *testing.T) {
	tests := []struct {
		name        string
		declaration string
		extraUse    string
		want        int
	}{
		{name: "built-in input length", want: 0},
		{name: "global shadowed length", declaration: "func len(value []byte) int { value[0] = 0; return 0 }", want: 1},
		{name: "local shadowed length", extraUse: "len := func(value []byte) int { value[0] = 0; return 0 }", want: 1},
		{name: "input rebound before length", extraUse: "input = []byte(secretToken)", want: 1},
	}
	// Check ordinary length reads alongside shadowed or mutating lookalikes.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code := fmt.Sprintf(`package sample
import ("crypto/md5"; "strconv")
type StoragePacker struct { viewPrefix string }
%s
// BucketKey returns the storage key of the bucket where the given item will be stored.
func (s *StoragePacker) BucketKey(itemID string) string {
 hf := md5.New()
 input := []byte(itemID)
 %s
 n, err := hf.Write(input)
 if err != nil || n != len(input) { return "" }
 index := uint8(hf.Sum(nil)[0])
 return s.viewPrefix + strconv.Itoa(int(index))
}
`, test.declaration, test.extraUse)
			got := WeakCryptoRule{}.AnalyzeUnit(parseOne(t, "crypto.go", code), Context{})
			// Only a proved nonmutating input read may keep the bucket-shaped digest quiet.
			if len(got) != test.want {
				t.Fatalf("got %d weak-crypto warnings, want %d", len(got), test.want)
			}
		})
	}
}
