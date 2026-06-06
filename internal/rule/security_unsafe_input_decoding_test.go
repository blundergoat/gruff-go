// Package rule tests the parser-only deserialization and XXE security rules.
package rule

import "testing"

// TestUnsafeDeserializationRule covers untrusted gob/yaml decoding and trusted
// or typed decoding that should not fire.
func TestUnsafeDeserializationRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "gob decode request body",
			code: `// Package handler is a test package.
package handler

import (
	"encoding/gob"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	_ = gob.NewDecoder(r.Body).Decode(&payload)
}
`,
			want: 1,
		},
		{
			name: "yaml unmarshal request bytes",
			code: `// Package handler is a test package.
package handler

import (
	"io"
	"net/http"

	"gopkg.in/yaml.v3"
)

func handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var out map[string]any
	_ = yaml.Unmarshal(body, &out)
}
`,
			want: 1,
		},
		{
			name: "yaml decoder from request",
			code: `// Package handler is a test package.
package handler

import (
	"net/http"

	"gopkg.in/yaml.v2"
)

func handle(w http.ResponseWriter, r *http.Request) {
	var out map[string]any
	_ = yaml.NewDecoder(r.Body).Decode(&out)
}
`,
			want: 1,
		},
		{
			name: "gob decode trusted local file",
			code: `// Package handler is a test package.
package handler

import (
	"encoding/gob"
	"net/http"
	"os"
)

func handle(w http.ResponseWriter, r *http.Request) {
	_ = r
	f, _ := os.Open("/var/cache/state.gob")
	var payload map[string]any
	_ = gob.NewDecoder(f).Decode(&payload)
}
`,
			want: 0,
		},
		{
			name: "json decode request body is allowed",
			code: `// Package handler is a test package.
package handler

import (
	"encoding/json"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	var out map[string]any
	_ = json.NewDecoder(r.Body).Decode(&out)
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "handler.go", tt.code)
			findings := UnsafeDeserializationRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}

// TestXXECandidateRule covers entity-resolving XML decoders and the safe stdlib
// default that must not fire.
func TestXXECandidateRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "entity map assignment",
			code: `// Package svc is a test package.
package svc

import (
	"io"
	"encoding/xml"
)

func decode(r io.Reader, entities map[string]string) {
	dec := xml.NewDecoder(r)
	dec.Entity = entities
	_ = dec.Decode(nil)
}
`,
			want: 1,
		},
		{
			name: "decoder literal with entity",
			code: `// Package svc is a test package.
package svc

import "encoding/xml"

func build(entities map[string]string) *xml.Decoder {
	return &xml.Decoder{Entity: entities}
}
`,
			want: 1,
		},
		{
			name: "plain stdlib decoder is safe",
			code: `// Package svc is a test package.
package svc

import (
	"io"
	"encoding/xml"
)

func decode(r io.Reader) {
	dec := xml.NewDecoder(r)
	_ = dec.Decode(nil)
}
`,
			want: 0,
		},
		{
			name: "no xml import",
			code: `// Package svc is a test package.
package svc

type Decoder struct {
	Entity map[string]string
}

func build(entities map[string]string) Decoder {
	d := Decoder{}
	d.Entity = entities
	return d
}
`,
			want: 0,
		},
		{
			name: "same-name var in another function is not the decoder",
			code: `// Package svc is a test package.
package svc

import (
	"io"
	"encoding/xml"
)

type custom struct {
	Entity map[string]string
}

func decode(r io.Reader) {
	dec := xml.NewDecoder(r)
	_ = dec.Decode(nil)
}

func other(entities map[string]string) {
	dec := custom{}
	dec.Entity = entities
	_ = dec
}
`,
			want: 0,
		},
		{
			name: "closure decoder does not taint same-named outer non-decoder",
			code: `// Package svc is a test package.
package svc

import "encoding/xml"

type custom struct {
	Entity map[string]string
}

func decode(entities map[string]string) {
	_ = func() {
		dec := xml.NewDecoder(nil)
		_ = dec
	}
	dec := custom{}
	dec.Entity = entities
	_ = dec
}
`,
			want: 0,
		},
		{
			name: "closure configuring an enclosing decoder still flags",
			code: `// Package svc is a test package.
package svc

import "encoding/xml"

func decode(entities map[string]string) {
	dec := xml.NewDecoder(nil)
	func() {
		dec.Entity = entities
	}()
	_ = dec
}
`,
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "svc.go", tt.code)
			findings := XXECandidateRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != tt.want {
				t.Fatalf("findings = %#v, want %d", findings, tt.want)
			}
		})
	}
}
