package rule

// reviewedFalsePositiveShapes records the precision boundary sealed during the
// family rule review. Detector definitions keep owning behavior and policy;
// this catalogue layer adds only user-facing recognition and mitigation text.
var reviewedFalsePositiveShapes = map[string]FalsePositiveShape{
	"dead-code.empty-block": {
		Shape: "A control-flow block used only for header work, or an intentionally empty select or comment-only body, " +
			"can look unfinished to the syntax-only check.",
		Mitigation: "Move the work into the body, add an executable statement, or disable the rule for the reviewed path.",
	},
	"dead-code.unused-private-const": {
		Shape: "A package-private constant referenced through reflection, build-tagged files, or indirect registration " +
			"can appear unreferenced to the parser-only package index.",
		Mitigation: "Keep a parser-visible reference, remove the declaration, or leave this opt-in rule disabled for that package.",
	},
	"dead-code.unused-private-function": {
		Shape: "A package-private function reached through reflection, build-tagged files, or indirect registration " +
			"can appear unreferenced to the parser-only package index.",
		Mitigation: "Keep a parser-visible reference, remove the function, or disable the rule for the reviewed package.",
	},
	"dead-code.unused-private-type": {
		Shape: "A package-private type referenced through reflection, build-tagged files, or indirect registration " +
			"can appear unreferenced to the parser-only package index.",
		Mitigation: "Keep a parser-visible reference, remove the type, or leave this opt-in rule disabled for that package.",
	},
	"dead-code.unused-private-var": {
		Shape: "A package-private variable referenced through reflection, build-tagged files, or indirect registration " +
			"can appear unreferenced to the parser-only package index.",
		Mitigation: "Keep a parser-visible reference, remove the variable, or leave this opt-in rule disabled for that package.",
	},
	"design.hotspot-file": {
		Shape:      "Several valid findings can be intentionally clustered in one file even though their composite hotspot is not a separate defect.",
		Mitigation: "Triage the underlying findings; do not make a separate code edit solely to clear the score-neutral composite.",
	},
	"docs.comment-rubric": {
		Shape:      "A concise but substantive comment can miss the configured line or token threshold.",
		Mitigation: "Tune minLines or minTokens for the selected paths, or remove the path from this rule's scope.",
	},
	"docs.config-field-comment": {
		Shape:      "An obvious configuration field, or one documented by its containing schema, can lack a field-local comment in an included path.",
		Mitigation: "Add a field comment, narrow includePaths to the schema that requires them, or disable the rule for the reviewed path.",
	},
	"docs.exported-symbol-comment": {
		Shape: "A generated or externally constrained exported declaration outside the built-in generated, internal, and test exclusions " +
			"can lack a local doc comment.",
		Mitigation: "Add the Go doc comment, mark generated source canonically, or disable the rule for the reviewed path.",
	},
	"docs.suppression-without-rationale": {
		Shape: "A suppression with its explanation in a non-adjacent comment, or without a reason:, rationale:, or because: prefix, " +
			"is not recognised as justified.",
		Mitigation: "Put an adjacent comment with one recognised rationale prefix immediately before the suppression.",
	},
	"maintainability.ignored-error": {
		Shape:      "A deliberately discarded value whose name or constructor marks it as an error is indistinguishable from an accidental discard.",
		Mitigation: "Handle or log the error, or disable the rule at the reviewed scope when discarding it is intentional.",
	},
	"maintainability.loop-variable-address": {
		Shape:      "The nearest go.mod syntax version can differ from the effective build semantics selected by an external toolchain override.",
		Mitigation: "Index the collection or copy the loop value explicitly, or review the finding against the effective Go version.",
	},
	"maintainability.production-panic": {
		Shape:      "A documented panic paired with recovery at a wider boundary can look like an unhandled production panic.",
		Mitigation: "Return an error where practical, or disable the rule only after reviewing the matching recovery boundary.",
	},
	"naming.contextual-generic": {
		Shape:      "A domain-meaningful name such as item or result can match the generic-name heuristic in a long function.",
		Mitigation: "Add the project term to genericNames, adjust minFunctionLines, or rename the identifier with its domain role.",
	},
	"naming.get-prefix": {
		Shape:      "A zero-argument receiver method named Get... can be required by a protocol, framework, or compatibility API.",
		Mitigation: "Add the exact method name to allowNames, rename it when compatible, or keep this opt-in rule disabled.",
	},
	"naming.identifier-quality": {
		Shape:      "A project-specific term can match a configured placeholder name even when it carries clear domain meaning.",
		Mitigation: "Remove that term from placeholderNames or rename the identifier to make its role explicit.",
	},
	"naming.misspelling": {
		Shape:      "A proper noun, vendor term, or domain word can collide with a built-in misspelling entry.",
		Mitigation: "Add the exact token to ignore or extra, or correct the identifier when the match is a typo.",
	},
	"naming.negated-boolean": {
		Shape:      "An established public API can intentionally use a negative boolean name to preserve compatibility or express policy.",
		Mitigation: "Add the exact name to allowList, adjust prefixes, or rename only when the API contract permits it.",
	},
	"naming.package-stutter": {
		Shape:      "An exported compatibility name or accepted domain noun can intentionally repeat its package name.",
		Mitigation: "Add the exact symbol to allowStutter, rename it when compatible, or keep this opt-in rule disabled.",
	},
	"naming.receiver-consistency": {
		Shape:      "A type can deliberately mix pointer and value receivers for method-set or API design, and equally common names can be ambiguous.",
		Mitigation: "Add the type to allowMixed, inspect the reported group, or keep this opt-in rule disabled.",
	},
	"security.archive-path-traversal": {
		Shape:      "A containment check implemented in a helper outside the extraction function is not visible to the bounded same-function proof.",
		Mitigation: "Keep the destination containment check visible beside extraction, or review and disable the rule for the vetted helper.",
	},
	"security.github-actions-pull-request-target": {
		Shape:      "The text scanner can see checkout or command execution but cannot prove that a condition selects only a trusted ref or event path.",
		Mitigation: "Use a safer trigger, isolate trusted work in another job, or disable the rule only after reviewing every privileged path.",
	},
	"security.github-actions-secrets-in-pr": {
		Shape:      "A secret reference in a pull-request workflow can sit behind a trusted-actor condition the text scanner does not evaluate.",
		Mitigation: "Gate the secret-bearing job explicitly or move it to a separate trusted workflow.",
	},
	"security.insecure-random-secret": {
		Shape:      "A math/rand call in sampling or simulation code can inherit a token-, key-, or nonce-like surrounding name.",
		Mitigation: "Use crypto/rand for security values, or rename and review non-security sampling code before disabling the rule.",
	},
	"security.open-redirect-candidate": {
		Shape:      "A redirect validation helper outside the current function, or with an unrecognised name, is not visible to the local proof.",
		Mitigation: "Keep the allowlist or validation check visible beside the redirect sink, or review the helper before disabling the rule.",
	},
	"security.path-traversal-file-access": {
		Shape:      "A filesystem containment helper outside the current function, or with an unrecognised name, is not visible to the local proof.",
		Mitigation: "Keep the clean-and-containment check visible beside the filesystem sink, or review the helper before disabling the rule.",
	},
	"security.request-body-without-limit": {
		Shape:      "A request-body limit applied by a wrapper or helper outside the current function is not visible to the same-function check.",
		Mitigation: "Keep http.MaxBytesReader or io.LimitReader visible before the full read, or review the wrapper before disabling the rule.",
	},
	"security.request-controlled-url": {
		Shape:      "A request-derived URL validated by a helper outside the analyzed function can still appear unconstrained.",
		Mitigation: "Keep the trusted-host or fixed-base check visible in the same function so the bounded detector can see it.",
	},
	"security.sensitive-data-logging": {
		Shape:      "A secret-like identifier can carry already-redacted or non-secret domain data through a wrapper the syntax check does not recognise.",
		Mitigation: "Use a recognised redaction call beside the log sink, avoid logging the value, or review the wrapper before disabling the rule.",
	},
	"security.sql-string-query": {
		Shape:      "A query assembled from trusted static fragments or a vetted builder can look like interpolated SQL to the syntax check.",
		Mitigation: "Parameterise untrusted values and keep a prepared or static query shape visible at the execution call.",
	},
	"security.template-injection-xss": {
		Shape:      "A custom sanitizer or safe rendering abstraction outside the current function is not visible to the local taint proof.",
		Mitigation: "Use html/template or html.EscapeString visibly before the response sink, or review the abstraction before disabling the rule.",
	},
	"security.unsafe-deserialization": {
		Shape:      "Request-derived bytes authenticated or validated outside the current function can still look untrusted at a gob or YAML decoder.",
		Mitigation: "Use a typed vetted format or keep the trust-boundary validation visible beside decoding.",
	},
	"security.weak-crypto": {
		Shape:      "MD5 or SHA-1 used only for a non-security checksum can appear security-sensitive when nearby names imply credentials or integrity.",
		Mitigation: "Use a modern digest for security work, or make the non-security checksum context explicit before disabling the rule.",
	},
	"security.xxe-candidate": {
		Shape:      "A custom XML entity map containing only fixed local entities still matches the decoder configuration heuristic.",
		Mitigation: "Leave Decoder.Entity unset where possible, or validate the fixed map before disabling the rule.",
	},
	"sensitive-data.connection-string": {
		Shape:      "A non-secret fixture password embedded in a connection URL for a non-local host is indistinguishable from a credential.",
		Mitigation: "Use runtime substitution or a local placeholder connection string instead of an embedded password.",
	},
	"sensitive-data.high-entropy-string": {
		Shape:      "A legitimate random-looking constant outside the built-in hex, UUID, SRI, and path exclusions can exceed the entropy threshold.",
		Mitigation: "Raise minLength or entropy for the project, or replace the fixture with a recognisable placeholder.",
	},
	"sensitive-data.jwt-token": {
		Shape:      "A syntactically valid sample, expired, or test JWT is indistinguishable from a live token literal.",
		Mitigation: "Use a non-token placeholder or load the fixture from an approved secure test source.",
	},
	"sensitive-data.phi-pattern": {
		Shape:      "A structurally valid synthetic SSN, Medicare MBI, or labelled MRN outside the placeholder set can look like real health data.",
		Mitigation: "Use a recognised placeholder or keep this opt-in rule disabled for the reviewed fixture path.",
	},
	"sensitive-data.pii-pattern": {
		Shape:      "A realistic synthetic email, phone number, or Luhn-valid payment-card fixture can look like real personal data.",
		Mitigation: "Use a reserved email domain, an invalid test number, or keep this opt-in rule disabled for the reviewed fixture path.",
	},
	"sensitive-data.secret-pattern": {
		Shape:      "A raw-string fixture or configuration example with a secret-shaped assignment can look like a committed credential.",
		Mitigation: "Use a recognised placeholder prefix or move the value to runtime configuration; do not suppress by matching secret text.",
	},
	"test-quality.helper-missing-t-helper": {
		Shape:      "A failing helper can intentionally report its own location, or use a custom testing wrapper the syntax check does not recognise.",
		Mitigation: "Call Helper on the testing object, or review and disable the rule for the intentional reporting helper.",
	},
	"test-quality.no-failure-path": {
		Shape:      "An assertion helper in a sibling file, method, dot import, or custom harness can be invisible to the file-local helper index.",
		Mitigation: "Keep a recognised failure call visible in the test, or disable the rule while the external assertion path is reviewed.",
	},
	"test-quality.parallel-range-capture": {
		Shape:      "The nearest go.mod syntax version can differ from the effective build semantics selected by an external toolchain override.",
		Mitigation: "Update the go directive or copy the range value before t.Parallel, then review against the effective Go version.",
	},
}

// withReviewedFalsePositiveShapes enriches the canonical catalogue without
// overriding guidance already owned by an individual rule definition.
func withReviewedFalsePositiveShapes(definition Definition) Definition {
	if len(definition.FalsePositiveShapes) > 0 {
		return definition
	}

	knownShape, ok := reviewedFalsePositiveShapes[definition.ID]
	if !ok {
		return definition
	}

	definition.FalsePositiveShapes = []FalsePositiveShape{knownShape}
	return definition
}
