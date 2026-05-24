// Package rule defines gruff-go's rule registry and analysers.
// This file wires the default rule pack and the strict-config option helpers.
package rule

// Defaults returns the built-in registry without project configuration.
func Defaults() Registry {
	registry, err := DefaultsConfigured(Config{})
	if err != nil {
		panic(err)
	}
	return registry
}

// DefaultsConfigured returns the built-in registry after applying rule config.
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
func defaultUnitRules(config Config) []UnitRule {
	rules := []UnitRule{}
	rules = append(rules, defaultMetricUnitRules(config)...)
	rules = append(rules, defaultMaintainabilityUnitRules()...)
	rules = append(rules, defaultSecurityUnitRules()...)
	rules = append(rules, defaultDocumentationUnitRules(config)...)
	rules = append(rules, defaultSensitiveDataUnitRules(config)...)
	rules = append(rules, defaultNamingUnitRules(config)...)
	rules = append(rules, defaultTestQualityUnitRules()...)
	return rules
}

// defaultMetricUnitRules returns size, complexity, and dead-code unit rules.
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
		ProductionPanicRule{},
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
		SQLStringQueryRule{},
		ArchivePathTraversalRule{},
		InsecureRandomSecretRule{},
		WeakCryptoRule{},
	}
}

// defaultDocumentationUnitRules returns documentation checks that run per source unit.
func defaultDocumentationUnitRules(config Config) []UnitRule {
	return []UnitRule{
		SuppressionWithoutRationaleRule{},
		ExportedSymbolCommentRule{IgnoreInternalPackages: boolOption(config, "docs.exported-symbol-comment", "ignoreInternalPackages", true)},
		ConfigFieldCommentRule{
			IncludePaths: stringSliceOption(config, "docs.config-field-comment", "includePaths"),
			ExcludePaths: stringSliceOption(config, "docs.config-field-comment", "excludePaths"),
		},
	}
}

// defaultSensitiveDataUnitRules returns vendor and generic sensitive-data checks.
func defaultSensitiveDataUnitRules(config Config) []UnitRule {
	return []UnitRule{
		SensitiveDataRule{PreviewAllowlist: config.SensitiveDataPreviewAllowlist},
		PrivateKeyRule{},
		AWSAccessKeyRule{},
		JWTTokenRule{},
		ConnectionStringRule{},
		GitHubTokenRule{},
		SlackTokenRule{},
		StripeLiveKeyRule{},
		GoogleAPIKeyRule{},
		AnthropicAPIKeyRule{},
		GCPServiceAccountRule{},
		NPMTokenRule{},
		GitLabTokenRule{},
	}
}

// defaultNamingUnitRules returns identifier and package-local naming checks.
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
		NegatedBooleanRule{
			Prefixes:  stringSliceOption(config, "naming.negated-boolean", "prefixes"),
			AllowList: stringSliceOption(config, "naming.negated-boolean", "allowList"),
			Scope:     stringOption(config, "naming.negated-boolean", "scope", "exported"),
		},
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
		SkippedTestRule{},
		EmptyTestRule{},
		HelperMissingTHelperRule{},
		NoFailurePathTestRule{},
		ParallelRangeCaptureRule{},
		FatalInGoroutineRule{},
		TempDirMisuseRule{},
	}
}

// defaultProjectRules builds the project-level rule slice from strict config.
func defaultProjectRules(config Config) []ProjectRule {
	return []ProjectRule{
		PackageCommentRule{},
		PackageNameUnderscoreRule{},
		PackageStutterRule{AllowStutter: stringSliceOption(config, "naming.package-stutter", "allowStutter")},
		ReceiverConsistencyRule{
			AllowMixed:   stringSliceOption(config, "naming.receiver-consistency", "allowMixed"),
			InspectGroup: stringOption(config, "naming.receiver-consistency", "inspectGroup", "both"),
		},
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
func defaultCompositeRules(config Config) []CompositeRule {
	return []CompositeRule{
		DesignGodFunctionRule{},
		DesignHotspotFileRule{
			MinFindings: intThreshold(config, "design.hotspot-file", "minFindings", hotspotFileMinFindings),
			MinPillars:  intThreshold(config, "design.hotspot-file", "minPillars", hotspotFileMinPillars),
		},
	}
}

// stringSliceOption reads a string-slice rule option from strict config.
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
func boolPointer(value bool) *bool {
	return &value
}

// stringOption reads a string rule option from strict config.
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
func intThreshold(config Config, ruleID string, name string, fallback int) int {
	values, ok := config.Thresholds[ruleID]
	if !ok {
		return fallback
	}
	value, ok := values[name]
	if !ok || value <= 0 {
		return fallback
	}
	return int(value)
}

// intOption reads an integer rule option from strict config, accepting numeric forms (int, int64, float64).
// Negative values fall through to the supplied fallback; zero is preserved so callers can disable a feature
// explicitly. The strict config decoder hands integers in as int or float64 depending on the source format.
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
