// Package report renders gruff-go analysis results into output formats.
//
// This file holds the indented JSON writer shared by the JSON-shaped reporters.
// The writer adds no HTML escaping of its own, but escapes that a value's own MarshalJSON method already wrote stay in the output.
package report

import (
	"encoding/json"
	"io"
)

// WriteJSON encodes value as indented JSON, adding no HTML escaping of its own; escapes a custom marshaler already wrote stay as they are.
//
// It writes the encoding to writer with two-space indentation, no line prefix, and a trailing newline.
// It returns an error when value cannot be marshalled to JSON or when the write to writer fails, and nil otherwise.
func WriteJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
