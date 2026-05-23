// Package rule tests crypto and random security rules.
package rule

import "testing"

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
