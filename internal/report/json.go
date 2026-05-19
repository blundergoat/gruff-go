// Package report renders gruff-go analysis results into output formats.
// This file holds the indented JSON writer shared by the JSON-shaped reporters.
package report

import (
	"encoding/json"
	"io"
)

// WriteJSON encodes value as indented JSON without HTML escaping.
func WriteJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
