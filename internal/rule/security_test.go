// Package rule tests parser-only security rules.
package rule

import "testing"

// TestShellCommandRule covers shell-routed exec calls and direct executable non-findings.
func TestShellCommandRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "command shell",
			code: `// Package sample is a test package.
package sample

import "os/exec"

func sample() {
	exec.Command("bash", "-c", "echo hi")
}
`,
			want: 1,
		},
		{
			name: "command context shell",
			code: `// Package sample is a test package.
package sample

import (
	"context"
	"os/exec"
)

func sample(ctx context.Context) {
	exec.CommandContext(ctx, "/bin/sh", "-c", "echo hi")
}
`,
			want: 1,
		},
		{
			name: "alias import shell",
			code: `// Package sample is a test package.
package sample

import ex "os/exec"

func sample() {
	ex.Command("bash", "-c", "echo hi")
}
`,
			want: 1,
		},
		{
			name: "windows shell path",
			code: `// Package sample is a test package.
package sample

import "os/exec"

func sample() {
	exec.Command("C:\\Windows\\System32\\cmd.exe", "/C", "echo hi")
}
`,
			want: 1,
		},
		{
			name: "powershell command flag",
			code: `// Package sample is a test package.
package sample

import "os/exec"

func sample() {
	exec.Command("powershell.exe", "-Command", "Write-Output hi")
}
`,
			want: 1,
		},
		{
			name: "direct executable",
			code: `// Package sample is a test package.
package sample

import "os/exec"

func sample() {
	exec.Command("git", "status")
}
`,
			want: 0,
		},
		{
			name: "local exec identifier",
			code: `// Package sample is a test package.
package sample

type Runner struct{}

func (Runner) Command(...string) {}

func sample() {
	var exec Runner
	exec.Command("bash", "-c", "echo hi")
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "shell.go", tt.code)
			findings := ShellCommandRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}

// TestTLSInsecureConfigRule covers concrete insecure tls.Config literals and safe lookalikes.
func TestTLSInsecureConfigRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "insecure skip verify",
			code: `// Package sample is a test package.
package sample

import "crypto/tls"

func sample() tls.Config {
	return tls.Config{InsecureSkipVerify: true}
}
`,
			want: 1,
		},
		{
			name: "obsolete minimum version",
			code: `// Package sample is a test package.
package sample

import "crypto/tls"

func sample() tls.Config {
	return tls.Config{MinVersion: tls.VersionTLS10}
}
`,
			want: 1,
		},
		{
			name: "alias obsolete minimum version",
			code: `// Package sample is a test package.
package sample

import securetls "crypto/tls"

func sample() securetls.Config {
	return securetls.Config{MinVersion: securetls.VersionSSL30}
}
`,
			want: 1,
		},
		{
			name: "safe minimum version",
			code: `// Package sample is a test package.
package sample

import "crypto/tls"

func sample() tls.Config {
	return tls.Config{MinVersion: tls.VersionTLS12}
}
`,
			want: 0,
		},
		{
			name: "absent minimum version",
			code: `// Package sample is a test package.
package sample

import "crypto/tls"

func sample() tls.Config {
	return tls.Config{}
}
`,
			want: 0,
		},
		{
			name: "unrelated struct fields",
			code: `// Package sample is a test package.
package sample

type Config struct {
	InsecureSkipVerify bool
	MinVersion int
}

func sample() Config {
	return Config{InsecureSkipVerify: true, MinVersion: 1}
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "tls.go", tt.code)
			findings := TLSInsecureConfigRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}
