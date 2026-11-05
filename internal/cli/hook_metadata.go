package cli

// hookBelowThresholdRuleIDs lists rules whose numeric threshold is a floor, so a finding fires because the measured value sits below it.
//
// An example is a package summary shorter than the required minimum; every other rule ID reports the hook direction "above".
//
// Keep this in sync with the rule registry; TestHookScopeAndDirectionRuleIDsExist in hook_test.go fails if an ID goes stale.
var hookBelowThresholdRuleIDs = map[string]struct{}{
	"docs.comment-rubric": {},
}

// hookThresholdDirection reports the B5 direction for a rule's threshold: "below" when it is a floor the measured value fell under, else "above".
//
// A wrong direction inverts the remediation signal for any metadata consumer, so it is derived per rule rather than hardcoded to "above".
//
// ruleID is the finding's rule identifier, looked up in hookBelowThresholdRuleIDs; any rule not listed there reports "above".
func hookThresholdDirection(ruleID string) string {
	if _, ok := hookBelowThresholdRuleIDs[ruleID]; ok {
		return "below"
	}
	return "above"
}

// hookMetadata converts known metric metadata into B5's normative shape.
//
// ruleID selects the threshold direction, and metadata is the finding's rule metadata, which may be nil.
//
// It returns measured, threshold, unit and direction when hookMeasured finds a value and threshold is numeric, copying a string limitBand.
// Failing that, numeric findings and minFindings values give the same four keys with unit "findings".
// Otherwise the result is a shallow copy of metadata, or an empty non-nil map when metadata is nil.
func hookMetadata(ruleID string, metadata map[string]any) map[string]any {
	if measured, unit, ok := hookMeasured(metadata); ok {
		if threshold, ok := hookNumber(metadata["threshold"]); ok {
			out := map[string]any{
				"measured":  measured,
				"threshold": threshold,
				"unit":      unit,
				"direction": hookThresholdDirection(ruleID),
			}
			// A banded size or complexity finding keeps its band beside the measurement
			// (FAMILY-CONTRACT.md section 12, search `The band key`).
			if band, ok := metadata["limitBand"].(string); ok {
				out["limitBand"] = band
			}
			return out
		}
	}
	if measured, ok := hookNumber(metadata["findings"]); ok {
		if threshold, ok := hookNumber(metadata["minFindings"]); ok {
			return map[string]any{
				"measured":  measured,
				"threshold": threshold,
				"unit":      "findings",
				"direction": hookThresholdDirection(ruleID),
			}
		}
	}
	// A finding with no metadata gets an empty map rather than nil, so a JSON encoder writes {} instead of null.
	if metadata == nil {
		return map[string]any{}
	}
	out := map[string]any{}
	for key, value := range metadata {
		out[key] = value
	}
	return out
}

// hookMeasured finds the measured value and unit in metadata, a finding's legacy rule metadata map.
//
// It checks the keys lines, complexity, depth, parameters and measured in that order and returns the first numeric value with its unit and true.
// The unit is the key name, except "value" for the measured key; nil metadata or no numeric key gives nil, an empty unit and false.
func hookMeasured(metadata map[string]any) (any, string, bool) {
	for _, candidate := range []struct {
		key  string
		unit string
	}{
		{key: "lines", unit: "lines"},
		{key: "complexity", unit: "complexity"},
		{key: "depth", unit: "depth"},
		{key: "parameters", unit: "parameters"},
		{key: "measured", unit: "value"},
	} {
		if value, ok := metadata[candidate.key]; ok {
			if measured, ok := hookNumber(value); ok {
				return measured, candidate.unit, true
			}
		}
	}
	return nil, "", false
}

// hookNumber accepts numeric types emitted by in-process rules and JSON fixtures.
//
// value is a raw metadata entry; it returns value unchanged with true for an int, int64 or float64, and a float32 widened to float64 with true.
// Any other type, including nil, gives nil and false, so that entry is not read as a measurement.
func hookNumber(value any) (any, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return typed, true
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	default:
		return nil, false
	}
}
