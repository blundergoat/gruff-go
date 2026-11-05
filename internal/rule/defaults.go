// Package rule defines gruff-go's rule registry and analysers.
//
// This file wires the default rule pack and the strict-config option helpers.
// For a missing or wrongly typed option they fall back to the rule's built-in setting instead of raising an error.
// Config file validation rejects a zero or negative threshold before these helpers run.
package rule

// Defaults returns the built-in registry without project configuration.
// It panics if NewRegistryWithComposite rejects the built-in rule lists, a gruff-go defect that no user config can cause.
func Defaults() Registry {
	registry, err := DefaultsConfigured(Config{})
	if err != nil {
		panic(err)
	}
	return registry
}

// DefaultsConfigured returns the built-in registry after applying rule config.
//
// config overrides built-in rule options, thresholds, enablement, and severities.
// When NewRegistryWithComposite fails, it returns a zero Registry and that error.
func DefaultsConfigured(config Config) (Registry, error) {
	registry, err := NewRegistryWithComposite(defaultUnitRules(config), defaultProjectRules(config), defaultCompositeRules(config))
	if err != nil {
		return Registry{}, err
	}
	registry.applyEnablement(config.Enabled)
	registry.applySeverities(config.Severities)
	registry.refreshActiveRules()
	return registry, nil
}

// defaultUnitRules builds the per-unit rule slice from strict config so DefaultsConfigured stays small.
// It returns the metric, maintainability, security, dependency, documentation, sensitive-data, naming, and test-quality rules in that order.
func defaultUnitRules(config Config) []UnitRule {
	rules := []UnitRule{}
	rules = append(rules, defaultMetricUnitRules(config)...)
	rules = append(rules, defaultMaintainabilityUnitRules()...)
	rules = append(rules, defaultSecurityUnitRules()...)
	rules = append(rules, defaultDependencyUnitRules()...)
	rules = append(rules, defaultDocumentationUnitRules(config)...)
	rules = append(rules, defaultSensitiveDataUnitRules(config)...)
	rules = append(rules, defaultNamingUnitRules(config)...)
	rules = append(rules, defaultTestQualityUnitRules()...)
	return rules
}

// defaultMetricUnitRules returns size, complexity, and dead-code unit rules.
// Thresholds come from config, falling back to the package defaults when a threshold is absent or not positive.
func defaultMetricUnitRules(config Config) []UnitRule {
	return []UnitRule{
		FileLengthRule{MaxLines: intThreshold(config, "size.file-length", "maxLines", fileLengthThreshold)},
		FunctionLengthRule{MaxLines: intThreshold(config, "size.function-length", "maxLines", functionLengthThreshold)},
		CognitiveComplexityRule{MaxComplexity: intThreshold(config, "complexity.cognitive", "maxComplexity", cognitiveComplexityThreshold)},
		CyclomaticComplexityRule{MaxComplexity: intThreshold(config, "complexity.cyclomatic", "maxComplexity", cyclomaticThreshold)},
		EmptyBlockRule{},
		UnreachableCodeRule{},
		ParameterCountRule{MaxParameters: intThreshold(config, "size.parameter-count", "maxParameters", parameterCountThreshold)},
		NestingDepthRule{MaxDepth: intThreshold(config, "complexity.nesting-depth", "maxDepth", nestingDepthThreshold)},
	}
}

// defaultMaintainabilityUnitRules returns lifecycle and production maintainability checks.
func defaultMaintainabilityUnitRules() []UnitRule {
	return []UnitRule{
		IgnoredErrorRule{},
		ContextTODOProductionRule{},
		DeferInLoopRule{},
		LogFatalLibraryRule{},
		LoopVariableAddressRule{},
		IoutilDeprecatedRule{},
	}
}

// defaultSecurityUnitRules returns parser-only security checks.
func defaultSecurityUnitRules() []UnitRule {
	return []UnitRule{
		ShellCommandRule{},
		TLSInsecureConfigRule{},
		HTTPClientNoTimeoutRule{},
		HTTPServerNoTimeoutRule{},
		PermissiveFileModeRule{},
		RequestBodyWithoutLimitRule{},
		ArchivePathTraversalRule{},
		InsecureRandomSecretRule{},
		WeakCryptoRule{},
		RequestControlledURLRule{},
		PathTraversalFileAccessRule{},
		OpenRedirectRule{},
		UnsafeDeserializationRule{},
		XXECandidateRule{},
		TemplateInjectionXSSRule{},
		GitHubActionsUnpinnedActionRule{},
		GitHubActionsRemoteShellRule{},
		GitHubActionsBroadPermissionsRule{},
		GitHubActionsPullRequestTargetRule{},
		GitHubActionsSecretsInPRRule{},
	}
}

// defaultDependencyUnitRules returns parser-only Go-module dependency-posture checks.
//
// They emit the security pillar but carry dependency.* IDs to mirror the cross-port dependency rule family.
func defaultDependencyUnitRules() []UnitRule {
	return []UnitRule{
		GoModLocalReplaceRule{},
		GoModRemoteReplaceRule{},
	}
}

// defaultDocumentationUnitRules returns documentation checks that run per source unit.
// config supplies the exported-comment ignoreInternalPackages flag, default true, and the config-field-comment include and exclude paths.
func defaultDocumentationUnitRules(config Config) []UnitRule {
	return []UnitRule{
		SuppressionWithoutRationaleRule{},
		ExportedSymbolCommentRule{IgnoreInternalPackages: boolOption(config, "docs.exported-symbol-comment", "ignoreInternalPackages", true)},
		MissingParamDocRule{},
		MissingReturnDocRule{},
		ConfigFieldCommentRule{
			IncludePaths: stringSliceOption(config, "docs.config-field-comment", "includePaths"),
			ExcludePaths: stringSliceOption(config, "docs.config-field-comment", "excludePaths"),
		},
	}
}

// defaultSensitiveDataUnitRules returns vendor and generic sensitive-data checks.
//
// The PII and PHI detectors ship with DefaultEnabled false because they are heuristic and noisier than the exact-prefix vendor rules.
// Per ADR-007 and ADR-009 they stay out of default scans until a project opts in, rather than riding at an inflated severity to dodge the gate.
//
// config is not read; every rule shares one preview policy from newSensitivePreviewPolicy.
func defaultSensitiveDataUnitRules(config Config) []UnitRule {
	previews := newSensitivePreviewPolicy()
	return []UnitRule{
		SensitiveDataRule{previews: previews},
		PrivateKeyRule{previews: previews},
		AWSAccessKeyRule{previews: previews},
		JWTTokenRule{previews: previews},
		ConnectionStringRule{previews: previews},
		GitHubTokenRule{previews: previews},
		SlackTokenRule{previews: previews},
		StripeLiveKeyRule{previews: previews},
		GoogleAPIKeyRule{previews: previews},
		AnthropicAPIKeyRule{previews: previews},
		GCPServiceAccountRule{previews: previews},
		NPMTokenRule{previews: previews},
		GitLabTokenRule{previews: previews},
		PIIPatternRule{previews: previews},
		PHIPatternRule{previews: previews},
	}
}

// defaultNamingUnitRules returns identifier and package-local naming checks.
// config supplies each rule's options and the contextual-generic thresholds, plus the accepted abbreviations for acronym-case.
func defaultNamingUnitRules(config Config) []UnitRule {
	return []UnitRule{
		AcronymCaseRule{
			Acronyms:              stringSliceOption(config, "naming.acronym-case", "acronyms"),
			Allow:                 stringSliceOption(config, "naming.acronym-case", "allow"),
			AcceptedAbbreviations: config.AcceptedAbbreviations,
		},
		GetPrefixRule{
			ExcludePaths: stringSliceOption(config, "naming.get-prefix", "excludePaths"),
			ExcludeNames: stringSliceOption(config, "naming.get-prefix", "excludeNames"),
		},
		IdentifierQualityRule{PlaceholderNames: stringSliceOption(config, "naming.identifier-quality", "placeholderNames")},
		MisspellingRule{
			Extra:  stringMapOption(config, "naming.misspelling", "extra"),
			Ignore: stringSliceOption(config, "naming.misspelling", "ignore"),
		},
		ContextualGenericRule{
			GenericNames:     stringSliceOption(config, "naming.contextual-generic", "genericNames"),
			MinBodyLines:     intThreshold(config, "naming.contextual-generic", "minBodyLines", contextualGenericBodyLinesThreshold),
			AccumulatorNames: stringSliceOption(config, "naming.contextual-generic", "accumulatorNames"),
			MinFunctionLines: intThreshold(config, "naming.contextual-generic", "minFunctionLines", contextualGenericFunctionLinesThreshold),
			RequireMultiple:  boolPointer(boolOption(config, "naming.contextual-generic", "requireMultiple", true)),
		},
	}
}

// defaultTestQualityUnitRules returns unit-level test-quality checks.
func defaultTestQualityUnitRules() []UnitRule {
	return []UnitRule{
		DuplicateTestBodyRule{},
		EmptyTestRule{},
		HelperMissingTHelperRule{},
		ParallelRangeCaptureRule{},
		FatalInGoroutineRule{},
		TempDirMisuseRule{},
		SleepInTestRule{},
	}
}

// defaultProjectRules builds the project-level rule slice from strict config.
//
// It returns the fixed project rule list, which is never empty.
// config feeds only the package-stutter, receiver-consistency, and comment-rubric settings.
func defaultProjectRules(config Config) []ProjectRule {
	return []ProjectRule{
		// Package-scoped since 2026-09-07: a package that recovers its own panics declares
		// that boundary in whichever file owns the entry point, not the one that panics.
		ProductionPanicRule{},
		PackageCommentRule{},
		PackageNameUnderscoreRule{},
		PackageStutterRule{AllowStutter: stringSliceOption(config, "naming.package-stutter", "allowStutter")},
		ReceiverConsistencyRule{
			AllowMixed:   stringSliceOption(config, "naming.receiver-consistency", "allowMixed"),
			InspectGroup: stringOption(config, "naming.receiver-consistency", "inspectGroup", "both"),
		},
		UnusedPrivateConstRule{},
		UnusedPrivateFunctionRule{},
		UnusedPrivateTypeRule{},
		UnusedPrivateVarRule{},
		StaticAnalysisRedundantTestRule{},
		CommentRubricRule{
			MinPackageCommentLines:   intThreshold(config, "docs.comment-rubric", "minPackageCommentLines", commentRubricMinPackageCommentLines),
			MinWordsBeyondSymbol:     intOption(config, "docs.comment-rubric", "minWordsBeyondSymbol", 0),
			IncludePaths:             stringSliceOption(config, "docs.comment-rubric", "includePaths"),
			ExcludePaths:             stringSliceOption(config, "docs.comment-rubric", "excludePaths"),
			RequirePackageSummary:    boolOption(config, "docs.comment-rubric", "requirePackageSummary", false),
			RequireFunctionComments:  boolOption(config, "docs.comment-rubric", "requireFunctionComments", false),
			RequireNamedTypeComments: boolOption(config, "docs.comment-rubric", "requireNamedTypeComments", false),
			RequireStructComments:    boolOption(config, "docs.comment-rubric", "requireStructComments", false),
			RequireInterfaceComments: boolOption(config, "docs.comment-rubric", "requireInterfaceComments", false),
			RequireConstComments:     boolOption(config, "docs.comment-rubric", "requireConstComments", false),
			RequireVarComments:       boolOption(config, "docs.comment-rubric", "requireVarComments", false),
			IgnoreTests:              boolOption(config, "docs.comment-rubric", "ignoreTests", false),
		},
	}
}

// defaultCompositeRules builds the composite rule slice from strict config.
// It returns only the design.hotspot-file rule, its minFindings and minPillars thresholds read from config with package defaults as fallback.
func defaultCompositeRules(config Config) []CompositeRule {
	return []CompositeRule{
		DesignHotspotFileRule{
			MinFindings: intThreshold(config, "design.hotspot-file", "minFindings", hotspotFileMinFindings),
			MinPillars:  intThreshold(config, "design.hotspot-file", "minPillars", hotspotFileMinPillars),
		},
	}
}

// stringSliceOption reads a string-slice rule option from strict config.
//
// It looks up key under ruleID in config.Options and returns its non-empty string items in order, skipping other item types.
// The result is nil when the rule or key is absent or the value is not a list, and empty when no item qualifies.
func stringSliceOption(config Config, ruleID, key string) []string {
	options, ok := config.Options[ruleID]
	if !ok {
		return nil
	}
	value, ok := options[key]
	if !ok {
		return nil
	}
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if str, ok := item.(string); ok && str != "" {
			out = append(out, str)
		}
	}
	return out
}

// boolOption reads a boolean rule option from strict config.
// It returns the bool stored at key under ruleID in config.Options, or fallback when the rule or key is missing or the value is not a bool.
func boolOption(config Config, ruleID, key string, fallback bool) bool {
	options, ok := config.Options[ruleID]
	if !ok {
		return fallback
	}
	value, ok := options[key]
	if !ok {
		return fallback
	}
	boolValue, ok := value.(bool)
	if !ok {
		return fallback
	}
	return boolValue
}

// boolPointer returns the address of the supplied bool, used for tri-state rule options.
// Each call yields a pointer to its own copy of value, never nil.
func boolPointer(value bool) *bool {
	return &value
}

// stringOption reads a string rule option from strict config.
//
// It returns the string stored at key under ruleID in config.Options.
// fallback is returned instead when the rule or key is missing or the value is empty or not a string.
func stringOption(config Config, ruleID, key string, fallback string) string {
	options, ok := config.Options[ruleID]
	if !ok {
		return fallback
	}
	value, ok := options[key]
	if !ok {
		return fallback
	}
	stringValue, ok := value.(string)
	if !ok || stringValue == "" {
		return fallback
	}
	return stringValue
}

// stringMapOption reads a string-to-string map rule option from strict config.
//
// It returns the entries at key under ruleID in config.Options whose values are non-empty strings, dropping the rest.
// The result is nil when the rule or key is absent or the value is not a map, and empty when no entry qualifies.
func stringMapOption(config Config, ruleID, key string) map[string]string {
	options, ok := config.Options[ruleID]
	if !ok {
		return nil
	}
	value, ok := options[key]
	if !ok {
		return nil
	}
	raw, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		str, ok := v.(string)
		if !ok || str == "" {
			continue
		}
		out[k] = str
	}
	return out
}

// intThreshold reads a named positive integer threshold from strict config.
//
// It returns the value stored as name under ruleID in config.Thresholds, converted to int.
// fallback is returned when the rule or name is missing or the value is zero or negative.
func intThreshold(config Config, ruleID string, name string, fallback int) int {
	values, ok := config.Thresholds[ruleID]
	if !ok {
		return fallback
	}
	value, ok := values[name]
	// Config file validation already rejects zero and negative thresholds, so this value check only guards a rule.Config built in code.
	if !ok || value <= 0 {
		return fallback
	}
	return int(value)
}

// intOption reads an integer rule option from strict config, accepting int, int64, and float64 values.
//
// Negative values fall through to fallback; zero is kept so a project can disable a feature explicitly, unlike intThreshold.
// The config file loader delivers numbers as float64; int and int64 arrive only from a rule.Config built in code.
//
// It returns the number stored at key under ruleID in config.Options, with a float64 truncated toward zero by the int conversion.
// fallback is also returned when the rule or key is missing or the value has another type.
func intOption(config Config, ruleID, key string, fallback int) int {
	options, ok := config.Options[ruleID]
	if !ok {
		return fallback
	}
	value, ok := options[key]
	if !ok {
		return fallback
	}
	switch v := value.(type) {
	case int:
		if v < 0 {
			return fallback
		}
		return v
	case int64:
		if v < 0 {
			return fallback
		}
		return int(v)
	case float64:
		if v < 0 {
			return fallback
		}
		return int(v)
	default:
		return fallback
	}
}
