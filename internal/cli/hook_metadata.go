package cli

// hookBelowThresholdRuleIDs lists rules whose numeric threshold is a floor, so a
// finding fires because the measured value sits *below* it (e.g. a package
// summary shorter than the required minimum). Every other metric rule treats its
// threshold as a ceiling. Keep this in sync with the rule registry; the guard in
// hook_test.go (TestHookScopeAndDirectionRuleIDsExist) fails if an ID goes stale.
var hookBelowThresholdRuleIDs = map[string]struct{}{
	"docs.comment-rubric": {},
}

// hookThresholdDirection reports the B5 `direction` for a rule's threshold:
// "below" when the threshold is a floor the measured value fell under, else
// "above". A wrong direction inverts the remediation signal for any metadata
// consumer, so it is derived per rule rather than hardcoded to "above".
func hookThresholdDirection(ruleID string) string {
	if _, ok := hookBelowThresholdRuleIDs[ruleID]; ok {
		return "below"
	}
	return "above"
}

// hookMetadata converts known metric metadata into B5's normative shape.
func hookMetadata(ruleID string, metadata map[string]any) map[string]any {
	if measured, unit, ok := hookMeasured(metadata); ok {
		if threshold, ok := hookNumber(metadata["threshold"]); ok {
			return map[string]any{
				"measured":  measured,
				"threshold": threshold,
				"unit":      unit,
				"direction": hookThresholdDirection(ruleID),
			}
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
	if metadata == nil {
		return map[string]any{}
	}
	out := map[string]any{}
	for key, value := range metadata {
		out[key] = value
	}
	return out
}

// hookMeasured finds the measured value and unit in legacy rule metadata.
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
