// Package rule tests that a cgo preamble counts as code, not as documentation.
package rule

import (
	"fmt"
	"strings"
	"testing"
)

// TestFileLengthCountsCgoPreamble pins that C source in a cgo preamble reaches the
// substantive line count while ordinary prose stays masked. go/parser reports both
// as comments, so masking indiscriminately let large mixed Go/C files go unreported.
func TestFileLengthCountsCgoPreamble(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "single import preamble counts",
			code: "// Package sample is a test package.\npackage sample\n\n/*\n" +
				repeatLines("int c_decl_%d(void);", 12) +
				"*/\nimport \"C\"\n\nfunc Use() {}\n",
			want: 1,
		},
		{
			name: "grouped import preamble counts",
			code: "// Package sample is a test package.\npackage sample\n\nimport (\n\t/*\n" +
				repeatLines("int c_decl_%d(void);", 12) +
				"\t*/\n\t\"C\"\n)\n\nfunc Use() {}\n",
			want: 1,
		},
		{
			name: "ordinary block comment stays masked",
			code: "// Package sample is a test package.\npackage sample\n\n/*\n" +
				repeatLines("prose line %d", 12) +
				"*/\nfunc Use() {}\n",
			want: 0,
		},
		{
			name: "ordinary line comments stay masked",
			code: "// Package sample is a test package.\npackage sample\n\n" +
				repeatLines("// prose line %d", 12) +
				"\nfunc Use() {}\n",
			want: 0,
		},
		{
			name: "cgo import without a preamble masks other comments",
			code: "// Package sample is a test package.\npackage sample\n\nimport \"C\"\n\n/*\n" +
				repeatLines("prose line %d", 12) +
				"*/\nfunc Use() {}\n",
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "sample.go", tt.code)
			findings := FileLengthRule{MaxLines: 10}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}

// repeatLines builds count numbered lines from a printf-style template.
func repeatLines(template string, count int) string {
	var builder strings.Builder
	for index := 1; index <= count; index++ {
		fmt.Fprintf(&builder, template+"\n", index)
	}
	return builder.String()
}
