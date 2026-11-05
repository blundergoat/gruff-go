// Package rule tests the archive path traversal rule against inline extraction code.
//
// Each case parses one archive.go source and checks how many archive findings the rule reports.
package rule

import "testing"

// TestArchivePathTraversalRule checks that joining an archive entry name onto a destination path is flagged as a zip-slip risk.
//
// A join passed through Clean and a prefix check stays quiet, but that check does not cover a separately named join in the same function.
// Files without an archive import, fixed names and entry.Name() calls stay quiet.
func TestArchivePathTraversalRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "zip entry join",
			code: `// Package sample is a test package.
package sample

import (
	"archive/zip"
	"path/filepath"
)

func extract(reader *zip.ReadCloser, dest string) {
	for _, file := range reader.File {
		target := filepath.Join(dest, file.Name)
		_ = target
	}
}
`,
			want: 1,
		},
		{
			name: "tar entry assigned name",
			code: `// Package sample is a test package.
package sample

import (
	"archive/tar"
	"path/filepath"
)

func extract(reader *tar.Reader, dest string) {
	header, _ := reader.Next()
	name := header.Name
	target := filepath.Join(dest, name)
	_ = target
}
`,
			want: 1,
		},
		{
			name: "path join",
			code: `// Package sample is a test package.
package sample

import (
	"archive/zip"
	"path"
)

func extract(file *zip.File, dest string) {
	target := path.Join(dest, file.Name)
	_ = target
}
`,
			want: 1,
		},
		{
			name: "containment check",
			code: `// Package sample is a test package.
package sample

import (
	"archive/zip"
	"path/filepath"
	"strings"
)

func extract(file *zip.File, dest string) {
	target := filepath.Join(dest, file.Name)
	clean := filepath.Clean(target)
	if !strings.HasPrefix(clean, filepath.Clean(dest)) {
		return
	}
	_ = clean
}
`,
			want: 0,
		},
		{
			name: "containment check does not suppress another archive join",
			code: `// Package sample is a test package.
package sample

import (
	"archive/zip"
	"path/filepath"
	"strings"
)

func extract(safeFile *zip.File, unsafeFile *zip.File, dest string) {
	safeTarget := filepath.Join(dest, safeFile.Name)
	clean := filepath.Clean(safeTarget)
	if !strings.HasPrefix(clean, filepath.Clean(dest)) {
		return
	}
	unsafeTarget := filepath.Join(dest, unsafeFile.Name)
	_ = unsafeTarget
}
`,
			want: 1,
		},
		{
			name: "non archive name",
			code: `// Package sample is a test package.
package sample

import "path/filepath"

func store(user User, dest string) {
	target := filepath.Join(dest, user.Name)
	_ = target
}
`,
			want: 0,
		},
		{
			name: "archive import fixed path",
			code: `// Package sample is a test package.
package sample

import (
	"archive/zip"
	"path/filepath"
)

func extract(file *zip.File, dest string) {
	target := filepath.Join(dest, "fixed.txt")
	_ = target
}
`,
			want: 0,
		},
		{
			name: "directory entry name call",
			code: `// Package sample is a test package.
package sample

import "path/filepath"

func read(entry Entry, dest string) {
	target := filepath.Join(dest, entry.Name())
	_ = target
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "archive.go", tt.code)
			findings := ArchivePathTraversalRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}
