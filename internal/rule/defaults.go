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
	registry, err := NewRegistryWithComposite([]UnitRule{
		FileLengthRule{MaxLines: intThreshold(config, "size.file-length", "maxLines", fileLengthThreshold)},
		FunctionLengthRule{MaxLines: intThreshold(config, "size.function-length", "maxLines", functionLengthThreshold)},
		CyclomaticComplexityRule{MaxComplexity: intThreshold(config, "complexity.cyclomatic", "maxComplexity", cyclomaticThreshold)},
		SensitiveDataRule{PreviewAllowlist: config.SensitiveDataPreviewAllowlist},
		EmptyBlockRule{},
		ShellCommandRule{},
		SkippedTestRule{},
		ParameterCountRule{MaxParameters: intThreshold(config, "size.parameter-count", "maxParameters", parameterCountThreshold)},
		NestingDepthRule{MaxDepth: intThreshold(config, "complexity.nesting-depth", "maxDepth", nestingDepthThreshold)},
		CommentRubricRule{
			MinPackageCommentLines:   intThreshold(config, "docs.comment-rubric", "minPackageCommentLines", commentRubricMinPackageCommentLines),
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
		ExportedSymbolCommentRule{IgnoreInternalPackages: boolOption(config, "docs.exported-symbol-comment", "ignoreInternalPackages", true)},
		PrivateKeyRule{},
		AWSAccessKeyRule{},
		JWTTokenRule{},
		ConnectionStringRule{},
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
		EmptyTestRule{},
		NoFailurePathTestRule{},
	}, []ProjectRule{
		PackageCommentRule{},
		PackageNameUnderscoreRule{},
		ReceiverConsistencyRule{
			AllowMixed:   stringSliceOption(config, "naming.receiver-consistency", "allowMixed"),
			InspectGroup: stringOption(config, "naming.receiver-consistency", "inspectGroup", "both"),
		},
	}, []CompositeRule{
		DesignGodFunctionRule{},
		DesignHotspotFileRule{
			MinFindings: intThreshold(config, "design.hotspot-file", "minFindings", hotspotFileMinFindings),
			MinPillars:  intThreshold(config, "design.hotspot-file", "minPillars", hotspotFileMinPillars),
		},
	})
	if err != nil {
		return Registry{}, err
	}
	registry.applyEnablement(config.Enabled)
	registry.applySeverities(config.Severities)
	registry.refreshActiveRules()
	return registry, nil
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
