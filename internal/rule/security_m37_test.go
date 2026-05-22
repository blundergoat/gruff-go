// Package rule tests SQL and archive security rules.
package rule

import "testing"

// TestSQLStringQueryRule covers dynamic SQL construction and safe literal/query-builder lookalikes.
func TestSQLStringQueryRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "fmt sprintf query",
			code: `// Package sample is a test package.
package sample

import "fmt"

func sample(db DB, name string) {
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
}
`,
			want: 1,
		},
		{
			name: "concat exec",
			code: `// Package sample is a test package.
package sample

func sample(db DB, id string) {
	db.Exec("DELETE FROM users WHERE id = " + id)
}
`,
			want: 1,
		},
		{
			name: "query context variable",
			code: `// Package sample is a test package.
package sample

func sample(ctx Context, db DB, name string) {
	query := "UPDATE users SET name = '" + name + "'"
	db.QueryContext(ctx, query)
}
`,
			want: 1,
		},
		{
			name: "pgx context offset",
			code: `// Package sample is a test package.
package sample

func sample(ctx Context, pool Pool, schema string) {
	pool.Exec(ctx, "CREATE SCHEMA " + schema)
}
`,
			want: 1,
		},
		{
			name: "parameterized literal",
			code: `// Package sample is a test package.
package sample

func sample(db DB, id string) {
	db.Query("SELECT * FROM users WHERE id = ?", id)
}
`,
			want: 0,
		},
		{
			name: "const query identifier",
			code: `// Package sample is a test package.
package sample

const getUser = "SELECT * FROM users WHERE id = $1"

func sample(ctx Context, db DB, id string) {
	db.Query(ctx, getUser, id)
}
`,
			want: 0,
		},
		{
			name: "non sql exec",
			code: `// Package sample is a test package.
package sample

func sample(runner Runner, name string) {
	runner.Exec("echo " + name)
}
`,
			want: 0,
		},
		{
			name: "non sql sprintf",
			code: `// Package sample is a test package.
package sample

import "fmt"

func sample(runner Runner, name string) {
	runner.Exec(fmt.Sprintf("echo %s", name))
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "sql.go", tt.code)
			findings := SQLStringQueryRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}

// TestArchivePathTraversalRule covers archive entry joins and obvious containment suppressions.
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
