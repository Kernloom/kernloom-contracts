// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package contracts defines the wire-level schemas shared by Forge and KLIQ.
//
// This module deliberately contains data contracts only: no Forge persistence,
// no KLIQ runtime state, and no adapter-specific implementation types.
package contracts

import "time"

const (
	RuntimeAPIVersion = "kernloom.io/runtime/v1alpha1"
	PolicyAPIVersion  = "kernloom.io/v1"

	KindPolicyIntent           = "PolicyIntent"
	KindAccessPolicy           = "AccessPolicy"
	KindRequirementPolicy      = "RequirementPolicy"
	KindCapabilityRequirement  = "CapabilityRequirement"
	KindGuardrailPolicy        = "GuardrailPolicy"
	KindDetectionPolicy        = "DetectionPolicy"
	KindResponsePolicy         = "ResponsePolicy"
	KindAlertRoute             = "AlertRoute"
	KindRuntimeBundle          = "RuntimeBundle"
	KindRuntimePolicyPack      = "RuntimePolicyPack"
	KindRuntimeDecision        = "RuntimeDecision"
	KindLocalRiskAssessment    = "LocalRiskAssessment"
	KindObservation            = "Observation"
	KindVendorAssessment       = "VendorAssessment"
	KindContextSnapshot        = "ContextSnapshot"
	KindPIPHealth              = "PIPHealth"
	KindRiskIndicator          = "RiskIndicator"
	KindRiskAssessment         = "RiskAssessment"
	KindRiskModel              = "RiskModel"
	KindRiskCombinationProfile = "RiskCombinationProfile"
	KindEnforcementReceipt     = "EnforcementReceipt"
	KindRuntimeFinding         = "RuntimeFinding"
	KindRuntimeBundleAck       = "RuntimeBundleAck"
	KindComponentInventory     = "ComponentInventory"
	KindKLIQConfigAssetReport  = "KliqConfigAssetReport"
	KindHealthReport           = "HealthReport"
	KindRuntimeDecisionSummary = "RuntimeDecisionSummary"
	KindAdapterStatus          = "AdapterStatus"
	KindFailoverStatus         = "FailoverStatus"
	KindRuntimeStatus          = "RuntimeStatus"
	KindBaselineProposal       = "BaselineProposal"
	KindGraphProposal          = "GraphProposal"
	SignatureAlgorithmEd25519  = "ed25519"
)

type TypeMeta struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind" yaml:"kind"`
}

type ObjectMeta struct {
	ID         string            `json:"id,omitempty" yaml:"id,omitempty"`
	Name       string            `json:"name,omitempty" yaml:"name,omitempty"`
	NodeID     string            `json:"node_id,omitempty" yaml:"node_id,omitempty"`
	Generation int               `json:"generation,omitempty" yaml:"generation,omitempty"`
	IssuedAt   time.Time         `json:"issued_at,omitempty" yaml:"issued_at,omitempty"`
	ExpiresAt  time.Time         `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	Labels     map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

type TruthValue string

const (
	TruthTrue    TruthValue = "true"
	TruthFalse   TruthValue = "false"
	TruthUnknown TruthValue = "unknown"
)

type MissingContextBehavior string

const (
	MissingContextDeny             MissingContextBehavior = "deny"
	MissingContextNotMatch         MissingContextBehavior = "not_match"
	MissingContextDegradeToAlert   MissingContextBehavior = "degrade_to_alert"
	MissingContextRequireReview    MissingContextBehavior = "require_review"
	MissingContextFailValidation   MissingContextBehavior = "fail_validation"
	MissingContextRejectHardAction MissingContextBehavior = "reject_hard_action"
)

type DetectionEvaluatorType string

const (
	DetectionEvaluatorStateless        DetectionEvaluatorType = "stateless"
	DetectionEvaluatorWindowed         DetectionEvaluatorType = "windowed"
	DetectionEvaluatorStatefulSequence DetectionEvaluatorType = "stateful_sequence"
	DetectionEvaluatorExternalSignal   DetectionEvaluatorType = "external_signal"
)

type DetectionEvaluatorContract struct {
	Type              DetectionEvaluatorType `json:"type" yaml:"type"`
	StateRequired     bool                   `json:"state_required,omitempty" yaml:"stateRequired,omitempty"`
	PreferredRuntimes []string               `json:"preferred_runtimes,omitempty" yaml:"preferredRuntimes,omitempty"`
	AllowedRuntimes   []string               `json:"allowed_runtimes,omitempty" yaml:"allowedRuntimes,omitempty"`
}

type RequirementFreshnessContract struct {
	MaxAge  Duration `json:"max_age,omitempty" yaml:"maxAge,omitempty"`
	Require bool     `json:"require,omitempty" yaml:"require,omitempty"`
}

type RequirementConditionContract struct {
	ID                     string                       `json:"id" yaml:"id"`
	Type                   string                       `json:"type,omitempty" yaml:"type,omitempty"`
	Signal                 string                       `json:"signal,omitempty" yaml:"signal,omitempty"`
	Operator               string                       `json:"operator,omitempty" yaml:"operator,omitempty"`
	Value                  any                          `json:"value,omitempty" yaml:"value,omitempty"`
	CEL                    string                       `json:"cel,omitempty" yaml:"cel,omitempty"`
	Freshness              RequirementFreshnessContract `json:"freshness,omitempty" yaml:"freshness,omitempty"`
	MinConfidence          float64                      `json:"min_confidence,omitempty" yaml:"minConfidence,omitempty"`
	MissingContext         MissingContextBehavior       `json:"missing_context,omitempty" yaml:"missingContext,omitempty"`
	InsufficientConfidence MissingContextBehavior       `json:"insufficient_confidence,omitempty" yaml:"insufficientConfidence,omitempty"`
}

type RuntimeActionState struct {
	ActionID        string    `json:"action_id" yaml:"action_id"`
	Level           string    `json:"level,omitempty" yaml:"level,omitempty"`
	SourceID        string    `json:"source_id,omitempty" yaml:"source_id,omitempty"`
	ResourceRef     string    `json:"resource_ref,omitempty" yaml:"resource_ref,omitempty"`
	ResponseRuleID  string    `json:"response_rule_id,omitempty" yaml:"response_rule_id,omitempty"`
	DetectionRuleID string    `json:"detection_rule_id,omitempty" yaml:"detection_rule_id,omitempty"`
	Active          bool      `json:"active" yaml:"active"`
	AppliedAt       time.Time `json:"applied_at,omitempty" yaml:"applied_at,omitempty"`
	ExpiresAt       time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	Evidence        []string  `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

type Signature struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	KeyID     string `json:"key_id,omitempty" yaml:"key_id,omitempty"`
	Value     string `json:"value" yaml:"value"`
}

// RuntimeBundle is the signed Forge-to-KLIQ runtime artifact.
type RuntimeBundle struct {
	TypeMeta  `yaml:",inline"`
	Metadata  ObjectMeta        `json:"metadata" yaml:"metadata"`
	Spec      RuntimeBundleSpec `json:"spec" yaml:"spec"`
	Signature Signature         `json:"signature" yaml:"signature"`
}

type RuntimeBundleSpec struct {
	RuntimePolicyPack      RuntimePolicyPack `json:"runtime_policy_pack" yaml:"runtime_policy_pack"`
	RuntimePDPProfile      RuntimePDPProfile `json:"runtime_pdp_profile,omitempty" yaml:"runtime_pdp_profile,omitempty"`
	Registry               RegistryRef       `json:"registry,omitempty" yaml:"registry,omitempty"`
	RegistrySnapshot       RegistrySnapshot  `json:"registry_snapshot,omitempty" yaml:"registry_snapshot,omitempty"`
	ContextRegistryVersion string            `json:"context_registry_version,omitempty" yaml:"context_registry_version,omitempty"`
	AdapterSelector        AdapterSelector   `json:"adapter_selector,omitempty" yaml:"adapter_selector,omitempty"`
	BaselineLifecycle      BaselineLifecycle `json:"baseline_lifecycle,omitempty" yaml:"baseline_lifecycle,omitempty"`
	GraphLifecycle         GraphLifecycle    `json:"graph_lifecycle,omitempty" yaml:"graph_lifecycle,omitempty"`
	EnforcementBounds      EnforcementBounds `json:"enforcement_bounds,omitempty" yaml:"enforcement_bounds,omitempty"`
	Failover               FailoverConfig    `json:"failover,omitempty" yaml:"failover,omitempty"`
	Extensions             map[string]any    `json:"extensions,omitempty" yaml:"extensions,omitempty"`
}

type RegistryRef struct {
	Name     string `json:"name,omitempty" yaml:"name,omitempty"`
	Version  string `json:"version,omitempty" yaml:"version,omitempty"`
	Revision string `json:"revision,omitempty" yaml:"revision,omitempty"`
	Digest   string `json:"digest,omitempty" yaml:"digest,omitempty"`
}

type RegistrySnapshot struct {
	Ref                     RegistryRef                  `json:"ref,omitempty" yaml:"ref,omitempty"`
	ContextVersion          string                       `json:"context_version,omitempty" yaml:"context_version,omitempty"`
	ContextKeys             []ContextKeyEntry            `json:"context_keys,omitempty" yaml:"context_keys,omitempty"`
	RiskLevels              []RiskLevelEntry             `json:"risk_levels,omitempty" yaml:"risk_levels,omitempty"`
	RiskTaxonomy            RiskTaxonomySnapshot         `json:"risk_taxonomy,omitempty" yaml:"risk_taxonomy,omitempty"`
	Capabilities            []CapabilityEntry            `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	ActionLevels            []ActionLevelEntry           `json:"action_levels,omitempty" yaml:"action_levels,omitempty"`
	ActionContracts         []RuntimeActionContractEntry `json:"action_contracts,omitempty" yaml:"action_contracts,omitempty"`
	Signals                 []SignalEntry                `json:"signals,omitempty" yaml:"signals,omitempty"`
	Metrics                 []MetricEntry                `json:"metrics,omitempty" yaml:"metrics,omitempty"`
	LabelPolicies           []LabelPolicyEntry           `json:"label_policies,omitempty" yaml:"label_policies,omitempty"`
	RetentionClasses        []RetentionClassEntry        `json:"retention_classes,omitempty" yaml:"retention_classes,omitempty"`
	Granularities           []GranularityEntry           `json:"granularities,omitempty" yaml:"granularities,omitempty"`
	Scopes                  ScopeRegistryView            `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	AccessPolicySchemas     []AccessPolicySchemaEntry    `json:"access_policy_schemas,omitempty" yaml:"access_policy_schemas,omitempty"`
	DetectionEvaluators     []DetectionEvaluatorEntry    `json:"detection_evaluators,omitempty" yaml:"detection_evaluators,omitempty"`
	MissingContextBehaviors []PolicyVocabularyEntry      `json:"missing_context_behaviors,omitempty" yaml:"missing_context_behaviors,omitempty"`
	GuardrailTypes          []PolicyVocabularyEntry      `json:"guardrail_types,omitempty" yaml:"guardrail_types,omitempty"`
	GapHandlingBehaviors    []PolicyVocabularyEntry      `json:"gap_handling_behaviors,omitempty" yaml:"gap_handling_behaviors,omitempty"`
	GapTypes                []GapTypeEntry               `json:"gap_types,omitempty" yaml:"gap_types,omitempty"`
	NotificationBindings    NotificationBindingsSnapshot `json:"notification_bindings,omitempty" yaml:"notification_bindings,omitempty"`
}

type ContextKeyEntry struct {
	ID                string   `json:"id" yaml:"id"`
	Type              string   `json:"type,omitempty" yaml:"type,omitempty"`
	Values            []string `json:"values,omitempty" yaml:"values,omitempty"`
	Scope             string   `json:"scope,omitempty" yaml:"scope,omitempty"`
	Sensitivity       string   `json:"sensitivity,omitempty" yaml:"sensitivity,omitempty"`
	DefaultTTL        string   `json:"default_ttl,omitempty" yaml:"defaultTTL,omitempty"`
	PermittedSources  []string `json:"permitted_sources,omitempty" yaml:"permittedSources,omitempty"`
	Description       string   `json:"description,omitempty" yaml:"description,omitempty"`
	Deprecated        bool     `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
	DeprecationReason string   `json:"deprecation_reason,omitempty" yaml:"deprecationReason,omitempty"`
	ReplacedBy        string   `json:"replaced_by,omitempty" yaml:"replacedBy,omitempty"`
}

type RiskLevelEntry struct {
	ID                 string `json:"id" yaml:"id"`
	ScoreRange         []int  `json:"score_range,omitempty" yaml:"scoreRange,omitempty"`
	EnforcementMeaning string `json:"enforcement_meaning,omitempty" yaml:"enforcementMeaning,omitempty"`
}

type RiskTaxonomySnapshot struct {
	Scopes                      []string                        `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	Quality                     map[string]any                  `json:"quality,omitempty" yaml:"quality,omitempty"`
	MinimumQualityByActionLevel map[string]RiskQualityThreshold `json:"minimum_quality_by_action_level,omitempty" yaml:"minimumQualityByActionLevel,omitempty"`
	SourceTypes                 []RiskSourceTypeEntry           `json:"source_types,omitempty" yaml:"sourceTypes,omitempty"`
}

type RiskQualityThreshold struct {
	Confidence   float64 `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	Completeness float64 `json:"completeness,omitempty" yaml:"completeness,omitempty"`
}

type RiskSourceTypeEntry struct {
	ID string `json:"id" yaml:"id"`
}

type CapabilityEntry struct {
	ID                  string              `json:"id" yaml:"id"`
	Category            string              `json:"category,omitempty" yaml:"category,omitempty"`
	Domain              string              `json:"domain,omitempty" yaml:"domain,omitempty"`
	Effect              string              `json:"effect,omitempty" yaml:"effect,omitempty"`
	RuntimeAction       bool                `json:"runtime_action,omitempty" yaml:"runtimeAction,omitempty"`
	Severity            int                 `json:"severity,omitempty" yaml:"severity,omitempty"`
	ActionContract      string              `json:"action_contract,omitempty" yaml:"actionContract,omitempty"`
	AllowedPaths        []string            `json:"allowed_paths,omitempty" yaml:"allowedPaths,omitempty"`
	RequiredGranularity map[string][]string `json:"required_granularity,omitempty" yaml:"requiredGranularity,omitempty"`
	RequiresApproval    bool                `json:"requires_approval,omitempty" yaml:"requiresApproval,omitempty"`
	Reversible          bool                `json:"reversible,omitempty" yaml:"reversible,omitempty"`
	SafeLocalDefault    bool                `json:"safe_local_default,omitempty" yaml:"safeLocalDefault,omitempty"`
}

type ActionLevelEntry struct {
	ID          string `json:"id" yaml:"id"`
	MaxSeverity int    `json:"max_severity" yaml:"maxSeverity"`
}

type RuntimeActionContractEntry struct {
	ID                     string   `json:"id" yaml:"id"`
	Level                  string   `json:"level,omitempty" yaml:"level,omitempty"`
	Effect                 string   `json:"effect,omitempty" yaml:"effect,omitempty"`
	Monotonicity           string   `json:"monotonicity,omitempty" yaml:"monotonicity,omitempty"`
	RuntimeAllowed         bool     `json:"runtime_allowed,omitempty" yaml:"runtimeAllowed,omitempty"`
	ConfigPathOnly         bool     `json:"config_path_only,omitempty" yaml:"configPathOnly,omitempty"`
	RequiresApproval       bool     `json:"requires_approval,omitempty" yaml:"requiresApproval,omitempty"`
	RequiresTTL            bool     `json:"requires_ttl,omitempty" yaml:"requiresTTL,omitempty"`
	DefaultTTL             string   `json:"default_ttl,omitempty" yaml:"defaultTTL,omitempty"`
	MaxTTL                 string   `json:"max_ttl,omitempty" yaml:"maxTTL,omitempty"`
	RequiresLease          bool     `json:"requires_lease,omitempty" yaml:"requiresLease,omitempty"`
	RequiresAudit          bool     `json:"requires_audit,omitempty" yaml:"requiresAudit,omitempty"`
	AutoRevert             string   `json:"auto_revert,omitempty" yaml:"autoRevert,omitempty"`
	Reversible             bool     `json:"reversible,omitempty" yaml:"reversible,omitempty"`
	AllowedDecisionSources []string `json:"allowed_decision_sources,omitempty" yaml:"allowedDecisionSources,omitempty"`
	RequiredConfidence     string   `json:"required_confidence,omitempty" yaml:"requiredConfidence,omitempty"`
	CanGrantAccess         bool     `json:"can_grant_access,omitempty" yaml:"canGrantAccess,omitempty"`
}

type DetectionEvaluatorEntry struct {
	ID              string   `json:"id" yaml:"id"`
	StateRequired   bool     `json:"state_required,omitempty" yaml:"stateRequired,omitempty"`
	AllowedRuntimes []string `json:"allowed_runtimes,omitempty" yaml:"allowedRuntimes,omitempty"`
	Description     string   `json:"description,omitempty" yaml:"description,omitempty"`
}

type AccessPolicySchemaEntry struct {
	ID                          string              `json:"id" yaml:"id"`
	APIVersion                  string              `json:"api_version,omitempty" yaml:"apiVersion,omitempty"`
	WireKind                    string              `json:"wire_kind,omitempty" yaml:"wireKind,omitempty"`
	Status                      string              `json:"status,omitempty" yaml:"status,omitempty"`
	Description                 string              `json:"description,omitempty" yaml:"description,omitempty"`
	Actions                     []PolicyActionEntry `json:"actions,omitempty" yaml:"actions,omitempty"`
	Effects                     []PolicyEffectEntry `json:"effects,omitempty" yaml:"effects,omitempty"`
	SubjectSelectorTypes        []SelectorTypeEntry `json:"subject_selector_types,omitempty" yaml:"subjectSelectorTypes,omitempty"`
	ResourceSelectorTypes       []SelectorTypeEntry `json:"resource_selector_types,omitempty" yaml:"resourceSelectorTypes,omitempty"`
	ConditionTypes              []string            `json:"condition_types,omitempty" yaml:"conditionTypes,omitempty"`
	Operators                   []string            `json:"operators,omitempty" yaml:"operators,omitempty"`
	EnforcementConstraintFields []string            `json:"enforcement_constraint_fields,omitempty" yaml:"enforcementConstraintFields,omitempty"`
	Invariants                  []string            `json:"invariants,omitempty" yaml:"invariants,omitempty"`
	JSONSchema                  string              `json:"json_schema,omitempty" yaml:"jsonSchema,omitempty"`
}

type PolicyActionEntry struct {
	ID          string `json:"id" yaml:"id"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

type PolicyEffectEntry struct {
	ID          string `json:"id" yaml:"id"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

type SelectorTypeEntry struct {
	ID                    string `json:"id" yaml:"id"`
	SelectorClass         string `json:"selector_class,omitempty" yaml:"selectorClass,omitempty"`
	ContextKey            string `json:"context_key,omitempty" yaml:"contextKey,omitempty"`
	CanonicalSubjectType  string `json:"canonical_subject_type,omitempty" yaml:"canonicalSubjectType,omitempty"`
	CanonicalResourceType string `json:"canonical_resource_type,omitempty" yaml:"canonicalResourceType,omitempty"`
	RequiresRef           bool   `json:"requires_ref,omitempty" yaml:"requiresRef,omitempty"`
	Description           string `json:"description,omitempty" yaml:"description,omitempty"`
}

type PolicyVocabularyEntry struct {
	ID          string   `json:"id" yaml:"id"`
	AppliesTo   []string `json:"applies_to,omitempty" yaml:"appliesTo,omitempty"`
	Meaning     string   `json:"meaning,omitempty" yaml:"meaning,omitempty"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
}

type GapTypeEntry struct {
	ID              string `json:"id" yaml:"id"`
	SeverityDefault string `json:"severity_default,omitempty" yaml:"severityDefault,omitempty"`
}

type NotificationBindingsSnapshot struct {
	Channels    []NotificationChannelBindingEntry `json:"channels,omitempty" yaml:"channels,omitempty"`
	CaseSystems []NotificationCaseSystemEntry     `json:"case_systems,omitempty" yaml:"caseSystems,omitempty"`
}

type NotificationChannelBindingEntry struct {
	ID          string   `json:"id" yaml:"id"`
	RefPrefixes []string `json:"ref_prefixes,omitempty" yaml:"refPrefixes,omitempty"`
}

type NotificationCaseSystemEntry struct {
	ID string `json:"id" yaml:"id"`
}

type SignalEntry struct {
	ID                  string                 `json:"id" yaml:"id"`
	Domain              string                 `json:"domain,omitempty" yaml:"domain,omitempty"`
	EntityScopes        []string               `json:"entity_scopes,omitempty" yaml:"entityScopes,omitempty"`
	VisibilityScopes    []string               `json:"visibility_scopes,omitempty" yaml:"visibilityScopes,omitempty"`
	DefaultTTL          string                 `json:"default_ttl,omitempty" yaml:"defaultTTL,omitempty"`
	DerivedFromMetrics  []string               `json:"derived_from_metrics,omitempty" yaml:"derivedFromMetrics,omitempty"`
	Evidence            SignalEvidence         `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Confidence          SignalConfidencePolicy `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	EnforcementEligible any                    `json:"enforcement_eligible,omitempty" yaml:"enforcementEligible,omitempty"`
	RequiredContext     []string               `json:"required_context,omitempty" yaml:"requiredContext,omitempty"`
	SuggestedResponses  []string               `json:"suggested_responses,omitempty" yaml:"suggestedResponses,omitempty"`
	Deprecated          bool                   `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
	DeprecationReason   string                 `json:"deprecation_reason,omitempty" yaml:"deprecationReason,omitempty"`
	ReplacedBy          string                 `json:"replaced_by,omitempty" yaml:"replacedBy,omitempty"`
}

type SignalEvidence struct {
	Required []string `json:"required,omitempty" yaml:"required,omitempty"`
	Optional []string `json:"optional,omitempty" yaml:"optional,omitempty"`
}

type SignalConfidencePolicy struct {
	MinimumForAlert     string `json:"minimum_for_alert,omitempty" yaml:"minimumForAlert,omitempty"`
	MinimumForRateLimit string `json:"minimum_for_rate_limit,omitempty" yaml:"minimumForRateLimit,omitempty"`
	MinimumForBlock     string `json:"minimum_for_block,omitempty" yaml:"minimumForBlock,omitempty"`
}

type MetricEntry struct {
	ID                    string   `json:"id" yaml:"id"`
	Domain                string   `json:"domain,omitempty" yaml:"domain,omitempty"`
	ValueType             string   `json:"value_type,omitempty" yaml:"valueType,omitempty"`
	Unit                  string   `json:"unit,omitempty" yaml:"unit,omitempty"`
	EntityScopes          []string `json:"entity_scopes,omitempty" yaml:"entityScopes,omitempty"`
	VisibilityScopes      []string `json:"visibility_scopes,omitempty" yaml:"visibilityScopes,omitempty"`
	BaselineAllowed       bool     `json:"baseline_allowed,omitempty" yaml:"baselineAllowed,omitempty"`
	HighCardinalityRisk   string   `json:"high_cardinality_risk,omitempty" yaml:"highCardinalityRisk,omitempty"`
	AllowedLabels         []string `json:"allowed_labels,omitempty" yaml:"allowedLabels,omitempty"`
	ForbiddenLabels       []string `json:"forbidden_labels,omitempty" yaml:"forbiddenLabels,omitempty"`
	Aggregations          []string `json:"aggregations,omitempty" yaml:"aggregations,omitempty"`
	DefaultWindow         string   `json:"default_window,omitempty" yaml:"defaultWindow,omitempty"`
	RetentionClass        string   `json:"retention_class,omitempty" yaml:"retentionClass,omitempty"`
	RequiresNormalization bool     `json:"requires_normalization,omitempty" yaml:"requiresNormalization,omitempty"`
}

type LabelPolicyEntry struct {
	ID                    string `json:"id" yaml:"id"`
	Allowed               bool   `json:"allowed" yaml:"allowed"`
	Cardinality           string `json:"cardinality,omitempty" yaml:"cardinality,omitempty"`
	PIIRisk               string `json:"pii_risk,omitempty" yaml:"piiRisk,omitempty"`
	RequiresNormalization bool   `json:"requires_normalization,omitempty" yaml:"requiresNormalization,omitempty"`
	Reason                string `json:"reason,omitempty" yaml:"reason,omitempty"`
}

type RetentionClassEntry struct {
	ID               string `json:"id" yaml:"id"`
	DefaultRetention string `json:"default_retention,omitempty" yaml:"defaultRetention,omitempty"`
}

type GranularityEntry struct {
	ID            string `json:"id" yaml:"id"`
	SemanticLevel string `json:"semantic_level,omitempty" yaml:"semanticLevel,omitempty"`
	EntityScope   string `json:"entity_scope,omitempty" yaml:"entityScope,omitempty"`
	Description   string `json:"description,omitempty" yaml:"description,omitempty"`
}

type ScopeRegistryView struct {
	EntityScopes     []ScopeEntry `json:"entity_scopes,omitempty" yaml:"entityScopes,omitempty"`
	VisibilityScopes []ScopeEntry `json:"visibility_scopes,omitempty" yaml:"visibilityScopes,omitempty"`
}

type ScopeEntry struct {
	ID          string `json:"id" yaml:"id"`
	EntityType  string `json:"entity_type,omitempty" yaml:"entityType,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

type AdapterSelector struct {
	RequiredCapabilities []string `json:"required_capabilities,omitempty" yaml:"required_capabilities,omitempty"`
	PreferredAdapters    []string `json:"preferred_adapters,omitempty" yaml:"preferred_adapters,omitempty"`
	DisabledAdapters     []string `json:"disabled_adapters,omitempty" yaml:"disabled_adapters,omitempty"`
}

type RuntimePDPProfile struct {
	Name      string         `json:"name,omitempty" yaml:"name,omitempty"`
	Mode      string         `json:"mode,omitempty" yaml:"mode,omitempty"`
	Variables []RuntimeInput `json:"variables,omitempty" yaml:"variables,omitempty"`
}

type RuntimeInput struct {
	Name     string `json:"name" yaml:"name"`
	Required bool   `json:"required,omitempty" yaml:"required,omitempty"`
	Source   string `json:"source,omitempty" yaml:"source,omitempty"`
}

type BaselineLifecycle struct {
	Mode             string   `json:"mode,omitempty" yaml:"mode,omitempty"`
	LearningWindow   Duration `json:"learning_window,omitempty" yaml:"learning_window,omitempty"`
	MinCleanRuntime  Duration `json:"min_clean_runtime,omitempty" yaml:"min_clean_runtime,omitempty"`
	MinConfidence    float64  `json:"min_confidence,omitempty" yaml:"min_confidence,omitempty"`
	ProposalUpload   bool     `json:"proposal_upload,omitempty" yaml:"proposal_upload,omitempty"`
	AllowLocalFreeze bool     `json:"allow_local_freeze,omitempty" yaml:"allow_local_freeze,omitempty"`
}

type GraphLifecycle struct {
	Mode                 string   `json:"mode,omitempty" yaml:"mode,omitempty"`
	MinCleanLearning     Duration `json:"min_clean_learning,omitempty" yaml:"min_clean_learning,omitempty"`
	MinLearnedEdges      int      `json:"min_learned_edges,omitempty" yaml:"min_learned_edges,omitempty"`
	MinBaselineCoverage  float64  `json:"min_baseline_coverage,omitempty" yaml:"min_baseline_coverage,omitempty"`
	RequireNoBlockFor    Duration `json:"require_no_block_for,omitempty" yaml:"require_no_block_for,omitempty"`
	FreezeApproval       string   `json:"freeze_approval,omitempty" yaml:"freeze_approval,omitempty"`
	ObserveAfterFreeze   Duration `json:"observe_after_freeze,omitempty" yaml:"observe_after_freeze,omitempty"`
	FinalPhase           string   `json:"final_phase,omitempty" yaml:"final_phase,omitempty"`
	IncludeEdgeBaselines bool     `json:"include_edge_baselines,omitempty" yaml:"include_edge_baselines,omitempty"`
}

type EnforcementBounds struct {
	MaxActionDuringBootstrap     string `json:"max_action_during_bootstrap,omitempty" yaml:"max_action_during_bootstrap,omitempty"`
	MaxActionDuringFrozenObserve string `json:"max_action_during_frozen_observe,omitempty" yaml:"max_action_during_frozen_observe,omitempty"`
	MaxActionDuringFrozenEnforce string `json:"max_action_during_frozen_enforce,omitempty" yaml:"max_action_during_frozen_enforce,omitempty"`
	AllowBlock                   bool   `json:"allow_block,omitempty" yaml:"allow_block,omitempty"`
}

type FailoverConfig struct {
	Behavior                          string `json:"behavior,omitempty" yaml:"behavior,omitempty"`
	AllowLearningWhileOffline         bool   `json:"allow_learning_while_offline,omitempty" yaml:"allow_learning_while_offline,omitempty"`
	AllowLocalFreezeWhileOffline      bool   `json:"allow_local_freeze_while_offline,omitempty" yaml:"allow_local_freeze_while_offline,omitempty"`
	AllowEnforcePromotionWhileOffline bool   `json:"allow_enforce_promotion_while_offline,omitempty" yaml:"allow_enforce_promotion_while_offline,omitempty"`
}

// RuntimePolicyPack contains Forge-compiled CEL rules and action authorization.
type RuntimePolicyPack struct {
	TypeMeta `yaml:",inline"`
	Metadata ObjectMeta            `json:"metadata" yaml:"metadata"`
	Spec     RuntimePolicyPackSpec `json:"spec" yaml:"spec"`
}

type RuntimePolicyPackSpec struct {
	CapabilitiesRequired []string                      `json:"capabilities_required,omitempty" yaml:"capabilities_required,omitempty"`
	DefaultEffect        string                        `json:"default_effect,omitempty" yaml:"default_effect,omitempty"`
	AutonomyLifecycle    *RuntimeAutonomyLifecycleSpec `json:"autonomy_lifecycle,omitempty" yaml:"autonomy_lifecycle,omitempty"`
	AccessPolicies       []RuntimeAccessPolicy         `json:"access_policies,omitempty" yaml:"access_policies,omitempty"`
	Rules                []RuntimePolicyRule           `json:"rules,omitempty" yaml:"rules,omitempty"`
	Guardrails           []RuntimeGuardrail            `json:"guardrails,omitempty" yaml:"guardrails,omitempty"`
	DetectionRules       []RuntimeDetectionRule        `json:"detection_rules,omitempty" yaml:"detection_rules,omitempty"`
	ResponseRules        []RuntimeResponseRule         `json:"response_rules,omitempty" yaml:"response_rules,omitempty"`
	AlertRoutes          []RuntimeAlertRoute           `json:"alert_routes,omitempty" yaml:"alert_routes,omitempty"`
	GapMetadata          []RuntimeGapMetadata          `json:"gap_metadata,omitempty" yaml:"gap_metadata,omitempty"`
	Exports              []RuntimeExportTarget         `json:"exports,omitempty" yaml:"exports,omitempty"`
}

// RuntimeAccessPolicy is the adapter-neutral desired access state that KLIQ
// can hand to AccessPolicyPEPs. It carries authored AccessPolicy intent without
// pretending every runtime adapter can natively enforce app/identity policy.
type RuntimeAccessPolicy struct {
	ID            string                   `json:"id" yaml:"id"`
	Description   string                   `json:"description,omitempty" yaml:"description,omitempty"`
	Subject       RuntimeAccessSubject     `json:"subject" yaml:"subject"`
	Action        string                   `json:"action" yaml:"action"`
	Resource      RuntimeAccessResource    `json:"resource" yaml:"resource"`
	Requirements  []string                 `json:"requirements,omitempty" yaml:"requirements,omitempty"`
	Conditions    []RuntimeAccessCondition `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	Effect        string                   `json:"effect" yaml:"effect"`
	DefaultEffect string                   `json:"default_effect,omitempty" yaml:"default_effect,omitempty"`
	Source        string                   `json:"source,omitempty" yaml:"source,omitempty"`
	ReasonCodes   []string                 `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
}

type RuntimeAccessSubject struct {
	Type string `json:"type" yaml:"type"`
	Ref  string `json:"ref,omitempty" yaml:"ref,omitempty"`
}

type RuntimeAccessResource struct {
	Type string `json:"type" yaml:"type"`
	Ref  string `json:"ref,omitempty" yaml:"ref,omitempty"`
}

type RuntimeAccessCondition struct {
	ID       string `json:"id" yaml:"id"`
	Type     string `json:"type,omitempty" yaml:"type,omitempty"`
	Signal   string `json:"signal,omitempty" yaml:"signal,omitempty"`
	Operator string `json:"operator,omitempty" yaml:"operator,omitempty"`
	Value    any    `json:"value,omitempty" yaml:"value,omitempty"`
	CEL      string `json:"cel,omitempty" yaml:"cel,omitempty"`
}

// RuntimeAutonomyLifecycleSpec contains bounded autonomy behavior that KLIQ can
// interpret without operators authoring internal FSM/CEL implementation details.
type RuntimeAutonomyLifecycleSpec struct {
	Hold                    []RuntimeAutonomyHoldRule            `json:"hold,omitempty" yaml:"hold,omitempty"`
	StepDown                RuntimeAutonomyStepDown              `json:"step_down,omitempty" yaml:"step_down,omitempty"`
	Allow                   []RuntimeAutonomyAllowance           `json:"allow,omitempty" yaml:"allow,omitempty"`
	ApprovalRequired        []RuntimeAutonomyApprovalRequirement `json:"approval_required,omitempty" yaml:"approval_required,omitempty"`
	MaxActionDuration       []RuntimeAutonomyActionDurationLimit `json:"max_action_duration,omitempty" yaml:"max_action_duration,omitempty"`
	BlastRadius             []RuntimeAutonomyBlastRadiusLimit    `json:"blast_radius,omitempty" yaml:"blast_radius,omitempty"`
	MaxRenewals             int                                  `json:"max_renewals,omitempty" yaml:"max_renewals,omitempty"`
	RestorePreviousOnResume bool                                 `json:"restore_previous_on_resume,omitempty" yaml:"restore_previous_on_resume,omitempty"`
	ReasonCodes             []string                             `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
	RequiresAudit           bool                                 `json:"requires_audit,omitempty" yaml:"requires_audit,omitempty"`
}

type RuntimeAutonomyHoldRule struct {
	ID          string                       `json:"id,omitempty" yaml:"id,omitempty"`
	While       RuntimeAutonomyHoldCondition `json:"while" yaml:"while"`
	Action      RuntimeActionSpec            `json:"action" yaml:"action"`
	ReasonCodes []string                     `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
}

type RuntimeAutonomyHoldCondition struct {
	EnforcementFeedbackActive bool     `json:"enforcement_feedback_active,omitempty" yaml:"enforcement_feedback_active,omitempty"`
	Levels                    []string `json:"levels,omitempty" yaml:"levels,omitempty"`
}

type RuntimeAutonomyStepDown struct {
	CleanAfter   Duration `json:"clean_after,omitempty" yaml:"clean_after,omitempty"`
	ObserveAfter Duration `json:"observe_after,omitempty" yaml:"observe_after,omitempty"`
}

type RuntimeAutonomyAllowance struct {
	Action                 string                 `json:"action" yaml:"action"`
	Subject                RuntimeAutonomySubject `json:"subject,omitempty" yaml:"subject,omitempty"`
	RequiresPreviousAction string                 `json:"requires_previous_action,omitempty" yaml:"requires_previous_action,omitempty"`
	ReasonCodes            []string               `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
}

type RuntimeAutonomySubject struct {
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	Ref  string `json:"ref,omitempty" yaml:"ref,omitempty"`
}

type RuntimeAutonomyApprovalRequirement struct {
	Action      string   `json:"action" yaml:"action"`
	ReasonCodes []string `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
}

type RuntimeAutonomyActionDurationLimit struct {
	Action   string   `json:"action" yaml:"action"`
	Duration Duration `json:"duration" yaml:"duration"`
}

type RuntimeAutonomyBlastRadiusLimit struct {
	Action     string   `json:"action" yaml:"action"`
	MaxTargets int      `json:"max_targets" yaml:"max_targets"`
	Scope      string   `json:"scope,omitempty" yaml:"scope,omitempty"`
	Window     Duration `json:"window,omitempty" yaml:"window,omitempty"`
}

type RuntimeGapMetadata struct {
	ID          string            `json:"id" yaml:"id"`
	Type        string            `json:"type,omitempty" yaml:"type,omitempty"`
	Behavior    string            `json:"behavior,omitempty" yaml:"behavior,omitempty"`
	Target      string            `json:"target,omitempty" yaml:"target,omitempty"`
	Requirement string            `json:"requirement,omitempty" yaml:"requirement,omitempty"`
	Severity    string            `json:"severity,omitempty" yaml:"severity,omitempty"`
	Deployable  bool              `json:"deployable,omitempty" yaml:"deployable,omitempty"`
	Reason      string            `json:"reason,omitempty" yaml:"reason,omitempty"`
	Meta        map[string]string `json:"meta,omitempty" yaml:"meta,omitempty"`
}

// RuntimeGuardrail is a compiled safety invariant that KLIQ must evaluate
// before executing a runtime action. Guardrails are deliberately small and
// runtime-focused; richer authored GuardrailPolicy objects are compiled by
// Forge into this executable shape.
type RuntimeGuardrail struct {
	ID               string                      `json:"id" yaml:"id"`
	Type             string                      `json:"type" yaml:"type"`
	Subject          RuntimeGuardrailSubject     `json:"subject,omitempty" yaml:"subject,omitempty"`
	ForbiddenActions []string                    `json:"forbidden_actions,omitempty" yaml:"forbidden_actions,omitempty"`
	AppliesTo        RuntimeGuardrailAppliesTo   `json:"applies_to,omitempty" yaml:"applies_to,omitempty"`
	Enforcement      RuntimeGuardrailEnforcement `json:"enforcement,omitempty" yaml:"enforcement,omitempty"`
	ReasonCodes      []string                    `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
}

type RuntimeGuardrailSubject struct {
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	Ref  string `json:"ref,omitempty" yaml:"ref,omitempty"`
}

type RuntimeGuardrailAppliesTo struct {
	Resources []string `json:"resources,omitempty" yaml:"resources,omitempty"`
}

type RuntimeGuardrailEnforcement struct {
	ViolationBehavior string `json:"violation_behavior,omitempty" yaml:"violation_behavior,omitempty"`
	UnknownBehavior   string `json:"unknown_behavior,omitempty" yaml:"unknown_behavior,omitempty"`
}

// RuntimeDetectionRule is a compiled stateful observation intent. It records
// what KLIQ should detect; response rules can reference detections by ID.
type RuntimeDetectionRule struct {
	ID          string                  `json:"id" yaml:"id"`
	Description string                  `json:"description,omitempty" yaml:"description,omitempty"`
	Type        string                  `json:"type" yaml:"type"`
	Subject     RuntimeDetectionSubject `json:"subject,omitempty" yaml:"subject,omitempty"`
	ResourceRef string                  `json:"resource_ref,omitempty" yaml:"resource_ref,omitempty"`
	Threshold   int                     `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	Window      Duration                `json:"window,omitempty" yaml:"window,omitempty"`
	Scope       string                  `json:"scope,omitempty" yaml:"scope,omitempty"`
	Params      map[string]any          `json:"params,omitempty" yaml:"params,omitempty"`
	ReasonCodes []string                `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
}

type RuntimeDetectionSubject struct {
	Type     string `json:"type,omitempty" yaml:"type,omitempty"`
	Ref      string `json:"ref,omitempty" yaml:"ref,omitempty"`
	Selector string `json:"selector,omitempty" yaml:"selector,omitempty"`
}

// RuntimeResponseRule is a compiled response intent. It is separate from access
// authorization rules: the trigger describes an observed condition and the
// actions describe bounded runtime reactions such as alerts, rate limits or
// case creation.
type RuntimeResponseRule struct {
	ID          string                  `json:"id" yaml:"id"`
	Description string                  `json:"description,omitempty" yaml:"description,omitempty"`
	When        RuntimeResponseTrigger  `json:"when" yaml:"when"`
	Then        []RuntimeResponseAction `json:"then" yaml:"then"`
	ReasonCodes []string                `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
}

type RuntimeResponseTrigger struct {
	Type        string         `json:"type,omitempty" yaml:"type,omitempty"`
	Detection   string         `json:"detection,omitempty" yaml:"detection,omitempty"`
	ResourceRef string         `json:"resource_ref,omitempty" yaml:"resource_ref,omitempty"`
	Threshold   int            `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	Window      Duration       `json:"window,omitempty" yaml:"window,omitempty"`
	Scope       string         `json:"scope,omitempty" yaml:"scope,omitempty"`
	Params      map[string]any `json:"params,omitempty" yaml:"params,omitempty"`
}

type RuntimeResponseAction struct {
	ID       string                `json:"id" yaml:"id"`
	Route    string                `json:"route,omitempty" yaml:"route,omitempty"`
	Severity string                `json:"severity,omitempty" yaml:"severity,omitempty"`
	Dedupe   Duration              `json:"dedupe,omitempty" yaml:"dedupe,omitempty"`
	TTL      Duration              `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	Target   RuntimeResponseTarget `json:"target,omitempty" yaml:"target,omitempty"`
	Params   map[string]any        `json:"params,omitempty" yaml:"params,omitempty"`
}

type RuntimeResponseTarget struct {
	Scope string `json:"scope,omitempty" yaml:"scope,omitempty"`
	Ref   string `json:"ref,omitempty" yaml:"ref,omitempty"`
}

// RuntimeAlertRoute defines where alert actions go and how noisy repeated
// events are deduplicated, acknowledged and escalated.
type RuntimeAlertRoute struct {
	ID              string                      `json:"id" yaml:"id"`
	Audience        RuntimeAlertAudience        `json:"audience,omitempty" yaml:"audience,omitempty"`
	Channels        []RuntimeAlertChannel       `json:"channels,omitempty" yaml:"channels,omitempty"`
	DefaultSeverity string                      `json:"default_severity,omitempty" yaml:"default_severity,omitempty"`
	Deduplication   RuntimeAlertDeduplication   `json:"deduplication,omitempty" yaml:"deduplication,omitempty"`
	CaseManagement  RuntimeAlertCaseManagement  `json:"case_management,omitempty" yaml:"case_management,omitempty"`
	Acknowledgement RuntimeAlertAcknowledgement `json:"acknowledgement,omitempty" yaml:"acknowledgement,omitempty"`
	Meta            map[string]string           `json:"meta,omitempty" yaml:"meta,omitempty"`
}

type RuntimeAlertAudience struct {
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	Ref  string `json:"ref,omitempty" yaml:"ref,omitempty"`
}

type RuntimeAlertChannel struct {
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	Ref  string `json:"ref,omitempty" yaml:"ref,omitempty"`
}

type RuntimeAlertDeduplication struct {
	Enabled bool     `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Window  Duration `json:"window,omitempty" yaml:"window,omitempty"`
	Keys    []string `json:"keys,omitempty" yaml:"keys,omitempty"`
}

type RuntimeAlertCaseManagement struct {
	CreateCase bool   `json:"create_case,omitempty" yaml:"create_case,omitempty"`
	System     string `json:"system,omitempty" yaml:"system,omitempty"`
}

type RuntimeAlertAcknowledgement struct {
	Required     bool                     `json:"required,omitempty" yaml:"required,omitempty"`
	Timeout      Duration                 `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	NoEscalation bool                     `json:"no_escalation,omitempty" yaml:"no_escalation,omitempty"`
	Escalation   []RuntimeAlertEscalation `json:"escalation,omitempty" yaml:"escalation,omitempty"`
}

type RuntimeAlertEscalation struct {
	To  RuntimeAlertAudience `json:"to,omitempty" yaml:"to,omitempty"`
	Via []string             `json:"via,omitempty" yaml:"via,omitempty"`
}

type RuntimePolicyRule struct {
	ID          string            `json:"id,omitempty" yaml:"id,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	When        string            `json:"when" yaml:"when"`
	Then        RuntimeActionSpec `json:"then" yaml:"then"`
	ReasonCodes []string          `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
}

type RuntimeActionSpec struct {
	Capability string         `json:"capability" yaml:"capability"`
	Level      string         `json:"level,omitempty" yaml:"level,omitempty"`
	TTL        Duration       `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	Params     map[string]any `json:"params,omitempty" yaml:"params,omitempty"`
}

type RuntimeExportTarget struct {
	Kind string            `json:"kind" yaml:"kind"`
	Name string            `json:"name,omitempty" yaml:"name,omitempty"`
	Meta map[string]string `json:"meta,omitempty" yaml:"meta,omitempty"`
}

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type LocalRiskAssessment struct {
	TypeMeta      `yaml:",inline"`
	Metadata      ObjectMeta         `json:"metadata" yaml:"metadata"`
	Subject       EntityRef          `json:"subject" yaml:"subject"`
	Level         RiskLevel          `json:"level" yaml:"level"`
	Score         int                `json:"score" yaml:"score"`
	Confidence    float64            `json:"confidence" yaml:"confidence"`
	Completeness  float64            `json:"completeness" yaml:"completeness"`
	Domains       []string           `json:"domains,omitempty" yaml:"domains,omitempty"`
	Contributions []RiskContribution `json:"contributions,omitempty" yaml:"contributions,omitempty"`
	MissingInputs []string           `json:"missing_inputs,omitempty" yaml:"missing_inputs,omitempty"`
	ValidUntil    time.Time          `json:"valid_until" yaml:"valid_until"`
	Model         string             `json:"model" yaml:"model"`
}

type RiskContribution struct {
	SignalID        string  `json:"signal_id,omitempty" yaml:"signal_id,omitempty"`
	SignalType      string  `json:"signal_type,omitempty" yaml:"signal_type,omitempty"`
	Domain          string  `json:"domain,omitempty" yaml:"domain,omitempty"`
	Score           int     `json:"score" yaml:"score"`
	Confidence      float64 `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	Weight          float64 `json:"weight,omitempty" yaml:"weight,omitempty"`
	Model           string  `json:"model,omitempty" yaml:"model,omitempty"`
	ModelVersion    string  `json:"model_version,omitempty" yaml:"model_version,omitempty"`
	RuleID          string  `json:"rule_id,omitempty" yaml:"rule_id,omitempty"`
	ContextKey      string  `json:"context_key,omitempty" yaml:"context_key,omitempty"`
	IndicatorRef    string  `json:"indicator_ref,omitempty" yaml:"indicator_ref,omitempty"`
	BaseValue       int     `json:"base_value,omitempty" yaml:"base_value,omitempty"`
	Direction       string  `json:"direction,omitempty" yaml:"direction,omitempty"`
	FreshnessFactor float64 `json:"freshness_factor,omitempty" yaml:"freshness_factor,omitempty"`
	EffectiveValue  float64 `json:"effective_value,omitempty" yaml:"effective_value,omitempty"`
}

type EntityRef struct {
	Kind      string            `json:"kind" yaml:"kind"`
	ID        string            `json:"id" yaml:"id"`
	Namespace string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

type ContextProvenance struct {
	SourceAdapter    string    `json:"source_adapter" yaml:"source_adapter"`
	SourceType       string    `json:"source_type" yaml:"source_type"`
	PIPInstanceID    string    `json:"pip_instance_id,omitempty" yaml:"pip_instance_id,omitempty"`
	CollectedAt      time.Time `json:"collected_at" yaml:"collected_at"`
	MappingVersion   string    `json:"mapping_version,omitempty" yaml:"mapping_version,omitempty"`
	TraceID          string    `json:"trace_id,omitempty" yaml:"trace_id,omitempty"`
	Origin           string    `json:"origin,omitempty" yaml:"origin,omitempty"`
	ActionGenerated  bool      `json:"action_generated,omitempty" yaml:"action_generated,omitempty"`
	ParentDecisionID string    `json:"parent_decision_id,omitempty" yaml:"parent_decision_id,omitempty"`
}

type DataQuality struct {
	Confidence float64  `json:"confidence" yaml:"confidence"`
	MaxAge     Duration `json:"max_age,omitempty" yaml:"max_age,omitempty"`
}

type Observation struct {
	TypeMeta     `yaml:",inline"`
	Metadata     ObjectMeta        `json:"metadata" yaml:"metadata"`
	Entity       EntityRef         `json:"entity" yaml:"entity"`
	Key          string            `json:"key" yaml:"key"`
	Value        any               `json:"value,omitempty" yaml:"value,omitempty"`
	ObservedAt   time.Time         `json:"observed_at" yaml:"observed_at"`
	Provenance   ContextProvenance `json:"provenance" yaml:"provenance"`
	EvidenceRefs []string          `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
	Extensions   map[string]any    `json:"extensions,omitempty" yaml:"extensions,omitempty"`
}

type VendorAssessment struct {
	TypeMeta     `yaml:",inline"`
	Metadata     ObjectMeta        `json:"metadata" yaml:"metadata"`
	Vendor       string            `json:"vendor" yaml:"vendor"`
	Key          string            `json:"key" yaml:"key"`
	Value        any               `json:"value,omitempty" yaml:"value,omitempty"`
	Entity       EntityRef         `json:"entity" yaml:"entity"`
	MappedTo     string            `json:"mapped_to,omitempty" yaml:"mapped_to,omitempty"`
	FidelityNote string            `json:"fidelity_note,omitempty" yaml:"fidelity_note,omitempty"`
	ObservedAt   time.Time         `json:"observed_at" yaml:"observed_at"`
	Provenance   ContextProvenance `json:"provenance" yaml:"provenance"`
}

type ContextFact struct {
	Key          string            `json:"key" yaml:"key"`
	Value        any               `json:"value,omitempty" yaml:"value,omitempty"`
	Entity       EntityRef         `json:"entity" yaml:"entity"`
	Status       string            `json:"status" yaml:"status"`
	Quality      DataQuality       `json:"quality" yaml:"quality"`
	ObservedAt   time.Time         `json:"observed_at" yaml:"observed_at"`
	ValidUntil   time.Time         `json:"valid_until,omitempty" yaml:"valid_until,omitempty"`
	Provenance   ContextProvenance `json:"provenance" yaml:"provenance"`
	EvidenceRefs []string          `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
}

type EntityLink struct {
	Subject      EntityRef   `json:"subject" yaml:"subject"`
	Aliases      []EntityRef `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	Confidence   float64     `json:"confidence" yaml:"confidence"`
	Approved     bool        `json:"approved,omitempty" yaml:"approved,omitempty"`
	Source       string      `json:"source,omitempty" yaml:"source,omitempty"`
	ObservedAt   time.Time   `json:"observed_at,omitempty" yaml:"observed_at,omitempty"`
	EvidenceRefs []string    `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
}

type PIPHealth struct {
	TypeMeta        `yaml:",inline"`
	Metadata        ObjectMeta `json:"metadata" yaml:"metadata"`
	SourceAdapter   string     `json:"source_adapter" yaml:"source_adapter"`
	Status          string     `json:"status" yaml:"status"`
	Healthy         bool       `json:"healthy" yaml:"healthy"`
	EventLagSeconds float64    `json:"event_lag_seconds,omitempty" yaml:"event_lag_seconds,omitempty"`
	LastSeenAt      time.Time  `json:"last_seen_at" yaml:"last_seen_at"`
	Details         string     `json:"details,omitempty" yaml:"details,omitempty"`
}

type RequiredSignal struct {
	PolicyID      string   `json:"policy_id" yaml:"policy_id"`
	RequirementID string   `json:"requirement_id" yaml:"requirement_id"`
	ContextKey    string   `json:"context_key" yaml:"context_key"`
	Providers     []string `json:"providers,omitempty" yaml:"providers,omitempty"`
	Mandatory     bool     `json:"mandatory" yaml:"mandatory"`
	OnMissing     string   `json:"on_missing" yaml:"on_missing"`
}

type ContextSnapshot struct {
	TypeMeta               `yaml:",inline"`
	Metadata               ObjectMeta         `json:"metadata" yaml:"metadata"`
	SnapshotAt             time.Time          `json:"snapshot_at" yaml:"snapshot_at"`
	ValidUntil             time.Time          `json:"valid_until" yaml:"valid_until"`
	ContextRegistryVersion string             `json:"context_registry_version" yaml:"context_registry_version"`
	ContextRegistryDigest  string             `json:"context_registry_digest,omitempty" yaml:"context_registry_digest,omitempty"`
	Facts                  []ContextFact      `json:"facts,omitempty" yaml:"facts,omitempty"`
	VendorAssessments      []VendorAssessment `json:"vendor_assessments,omitempty" yaml:"vendor_assessments,omitempty"`
	EntityLinks            []EntityLink       `json:"entity_links,omitempty" yaml:"entity_links,omitempty"`
	PIPHealth              []PIPHealth        `json:"pip_health,omitempty" yaml:"pip_health,omitempty"`
}

type RiskIndicator struct {
	TypeMeta     `yaml:",inline"`
	Metadata     ObjectMeta `json:"metadata" yaml:"metadata"`
	Key          string     `json:"key" yaml:"key"`
	Scope        EntityRef  `json:"scope" yaml:"scope"`
	State        string     `json:"state" yaml:"state"`
	Severity     string     `json:"severity" yaml:"severity"`
	Confidence   float64    `json:"confidence" yaml:"confidence"`
	ObservedAt   time.Time  `json:"observed_at" yaml:"observed_at"`
	ValidUntil   time.Time  `json:"valid_until" yaml:"valid_until"`
	EvidenceRefs []string   `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
}

type RiskAssessment struct {
	TypeMeta      `yaml:",inline"`
	Metadata      ObjectMeta         `json:"metadata" yaml:"metadata"`
	Scope         EntityRef          `json:"scope" yaml:"scope"`
	Score         int                `json:"score" yaml:"score"`
	Level         RiskLevel          `json:"level" yaml:"level"`
	Confidence    float64            `json:"confidence" yaml:"confidence"`
	Completeness  float64            `json:"completeness" yaml:"completeness"`
	Model         string             `json:"model" yaml:"model"`
	ModelVersion  string             `json:"model_version" yaml:"model_version"`
	CalculatedAt  time.Time          `json:"calculated_at" yaml:"calculated_at"`
	ValidUntil    time.Time          `json:"valid_until" yaml:"valid_until"`
	Contributions []RiskContribution `json:"contributions,omitempty" yaml:"contributions,omitempty"`
	MissingInputs []string           `json:"missing_inputs,omitempty" yaml:"missing_inputs,omitempty"`
	ReasonCodes   []string           `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
	EvidenceRefs  []string           `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
}

type RiskModel struct {
	TypeMeta               `yaml:",inline"`
	Metadata               ObjectMeta       `json:"metadata" yaml:"metadata"`
	ScopeTypes             []string         `json:"scope_types" yaml:"scope_types"`
	Inputs                 []RiskModelInput `json:"inputs" yaml:"inputs"`
	Levels                 map[string][]int `json:"levels,omitempty" yaml:"levels,omitempty"`
	TTL                    Duration         `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	MinConfidence          float64          `json:"min_confidence,omitempty" yaml:"min_confidence,omitempty"`
	MinCompleteness        float64          `json:"min_completeness,omitempty" yaml:"min_completeness,omitempty"`
	ContextRegistryVersion string           `json:"context_registry_version,omitempty" yaml:"context_registry_version,omitempty"`
	Digest                 string           `json:"digest,omitempty" yaml:"digest,omitempty"`
}

type RiskModelInput struct {
	ID               string   `json:"id" yaml:"id"`
	Source           string   `json:"source" yaml:"source"`
	Key              string   `json:"key" yaml:"key"`
	Match            any      `json:"match,omitempty" yaml:"match,omitempty"`
	Domain           string   `json:"domain,omitempty" yaml:"domain,omitempty"`
	BaseContribution int      `json:"base_contribution" yaml:"base_contribution"`
	ConfidenceMode   string   `json:"confidence_mode,omitempty" yaml:"confidence_mode,omitempty"`
	HalfLife         Duration `json:"half_life,omitempty" yaml:"half_life,omitempty"`
}

type RiskCombinationProfile struct {
	TypeMeta       `yaml:",inline"`
	Metadata       ObjectMeta `json:"metadata" yaml:"metadata"`
	LocalMode      string     `json:"local_mode" yaml:"local_mode"`
	Strategy       string     `json:"strategy" yaml:"strategy"`
	GlobalWeight   float64    `json:"global_weight,omitempty" yaml:"global_weight,omitempty"`
	GlobalTTL      Duration   `json:"global_ttl,omitempty" yaml:"global_ttl,omitempty"`
	OnGlobalExpiry string     `json:"on_global_expiry,omitempty" yaml:"on_global_expiry,omitempty"`
}

type RuntimeDecision struct {
	TypeMeta     `yaml:",inline"`
	Metadata     ObjectMeta           `json:"metadata" yaml:"metadata"`
	Subject      EntityRef            `json:"subject" yaml:"subject"`
	Action       RuntimeActionSpec    `json:"action" yaml:"action"`
	Effect       string               `json:"effect" yaml:"effect"`
	Decider      string               `json:"decider" yaml:"decider"`
	Risk         *LocalRiskAssessment `json:"risk,omitempty" yaml:"risk,omitempty"`
	ReasonCodes  []string             `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
	EvidenceRefs []string             `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
	ValidUntil   time.Time            `json:"valid_until,omitempty" yaml:"valid_until,omitempty"`
}

type EnforcementReceipt struct {
	TypeMeta     `yaml:",inline"`
	Metadata     ObjectMeta `json:"metadata" yaml:"metadata"`
	DecisionID   string     `json:"decision_id" yaml:"decision_id"`
	LeaseID      string     `json:"lease_id,omitempty" yaml:"lease_id,omitempty"`
	NodeID       string     `json:"node_id" yaml:"node_id"`
	AdapterID    string     `json:"adapter_id" yaml:"adapter_id"`
	Status       string     `json:"status" yaml:"status"`
	RevertStatus string     `json:"revert_status,omitempty" yaml:"revert_status,omitempty"`
	Message      string     `json:"message,omitempty" yaml:"message,omitempty"`
	Action       string     `json:"action,omitempty" yaml:"action,omitempty"`
	Target       string     `json:"target,omitempty" yaml:"target,omitempty"`
	FencingToken string     `json:"fencing_token,omitempty" yaml:"fencing_token,omitempty"`
	AppliedAt    time.Time  `json:"applied_at" yaml:"applied_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	RevertedAt   *time.Time `json:"reverted_at,omitempty" yaml:"reverted_at,omitempty"`
}

type RuntimeBundleAck struct {
	TypeMeta         `yaml:",inline"`
	Metadata         ObjectMeta `json:"metadata" yaml:"metadata"`
	NodeID           string     `json:"node_id" yaml:"node_id"`
	BundleGeneration int        `json:"bundle_generation" yaml:"bundle_generation"`
	BundleHash       string     `json:"bundle_hash,omitempty" yaml:"bundle_hash,omitempty"`
	Applied          bool       `json:"applied" yaml:"applied"`
	ErrorDetail      string     `json:"error_detail,omitempty" yaml:"error_detail,omitempty"`
	ReportedAt       time.Time  `json:"reported_at" yaml:"reported_at"`
}

type RuntimeFinding struct {
	TypeMeta     `yaml:",inline"`
	Metadata     ObjectMeta        `json:"metadata" yaml:"metadata"`
	NodeID       string            `json:"node_id" yaml:"node_id"`
	Subject      EntityRef         `json:"subject" yaml:"subject"`
	Severity     string            `json:"severity" yaml:"severity"`
	Title        string            `json:"title" yaml:"title"`
	Detail       string            `json:"detail,omitempty" yaml:"detail,omitempty"`
	EvidenceRefs []string          `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty" yaml:"attributes,omitempty"`
	ObservedAt   time.Time         `json:"observed_at" yaml:"observed_at"`
}

type ComponentCapabilityStatus struct {
	ID          string   `json:"id" yaml:"id"`
	Status      string   `json:"status" yaml:"status"`
	Granularity []string `json:"granularity,omitempty" yaml:"granularity,omitempty"`
	Reason      string   `json:"reason,omitempty" yaml:"reason,omitempty"`
}

type ComponentInventory struct {
	APIVersion   string                     `json:"apiVersion" yaml:"apiVersion"`
	Kind         string                     `json:"kind" yaml:"kind"`
	Metadata     ComponentInventoryMetadata `json:"metadata" yaml:"metadata"`
	ControlledBy ComponentInventoryControl  `json:"controlled_by" yaml:"controlled_by"`
	Component    ComponentInventoryProduct  `json:"component" yaml:"component"`
	Roles        []string                   `json:"roles" yaml:"roles"`
	Profiles     []string                   `json:"profiles" yaml:"profiles"`

	EffectiveCapabilities   []ComponentCapabilityStatus `json:"effective_capabilities" yaml:"effective_capabilities"`
	UnavailableCapabilities []ComponentCapabilityStatus `json:"unavailable_capabilities,omitempty" yaml:"unavailable_capabilities,omitempty"`

	OS         string            `json:"os,omitempty" yaml:"os,omitempty"`
	Arch       string            `json:"arch,omitempty" yaml:"arch,omitempty"`
	Labels     map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	ReportedAt time.Time         `json:"reported_at,omitempty" yaml:"reported_at,omitempty"`
}

type ComponentInventoryMetadata struct {
	ID        string    `json:"id" yaml:"id"`
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
}

type ComponentInventoryControl struct {
	NodeID        string `json:"node_id" yaml:"node_id"`
	PluginAdapter string `json:"plugin_adapter,omitempty" yaml:"plugin_adapter,omitempty"`
}

type ComponentInventoryProduct struct {
	Product string `json:"product" yaml:"product"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
}

type KLIQConfigAssetReport struct {
	APIVersion string                   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                   `json:"kind" yaml:"kind"`
	Metadata   KLIQConfigReportMetadata `json:"metadata" yaml:"metadata"`
	Mode       string                   `json:"mode" yaml:"mode"`

	HasPolicyPack         bool   `json:"has_policy_pack" yaml:"has_policy_pack"`
	PolicyMaxAction       string `json:"policy_max_action" yaml:"policy_max_action"`
	AllowLocalBlock       bool   `json:"allow_local_block" yaml:"allow_local_block"`
	DryRun                bool   `json:"dry_run" yaml:"dry_run"`
	AutonomousEnforcement bool   `json:"autonomous_enforcement" yaml:"autonomous_enforcement"`
	PolicyAuthority       string `json:"policy_authority" yaml:"policy_authority"`

	AllowedCapabilities []string `json:"allowed_capabilities,omitempty" yaml:"allowed_capabilities,omitempty"`
	EnforcementMode     string   `json:"enforcement_mode" yaml:"enforcement_mode"`

	SoftDirectiveRatePPS uint64 `json:"soft_directive_rate_pps,omitempty" yaml:"soft_directive_rate_pps,omitempty"`
	HardDirectiveRatePPS uint64 `json:"hard_directive_rate_pps,omitempty" yaml:"hard_directive_rate_pps,omitempty"`

	SoftRateFactor       float64 `json:"soft_rate_factor,omitempty" yaml:"soft_rate_factor,omitempty"`
	HardRateFactor       float64 `json:"hard_rate_factor,omitempty" yaml:"hard_rate_factor,omitempty"`
	InitialTrigPPS       float64 `json:"initial_trig_pps,omitempty" yaml:"initial_trig_pps,omitempty"`
	EffectiveSoftRatePPS uint64  `json:"effective_soft_rate_pps,omitempty" yaml:"effective_soft_rate_pps,omitempty"`
	EffectiveHardRatePPS uint64  `json:"effective_hard_rate_pps,omitempty" yaml:"effective_hard_rate_pps,omitempty"`

	Adapters  []AdapterSummary `json:"adapters" yaml:"adapters"`
	Analyzers []string         `json:"analyzers" yaml:"analyzers"`
	Safety    SafetyConfig     `json:"safety" yaml:"safety"`
}

type KLIQConfigReportMetadata struct {
	NodeID    string    `json:"node_id" yaml:"node_id"`
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
}

type AdapterSummary struct {
	ID      string `json:"id" yaml:"id"`
	Plugin  string `json:"plugin" yaml:"plugin"`
	Enabled bool   `json:"enabled" yaml:"enabled"`
}

type SafetyConfig struct {
	DefaultIfNoPolicyPack string `json:"default_if_no_policy_pack" yaml:"default_if_no_policy_pack"`
	MaxActionWithoutForge string `json:"max_action_without_forge" yaml:"max_action_without_forge"`
}

type HealthReport struct {
	TypeMeta             `yaml:",inline"`
	Metadata             ObjectMeta      `json:"metadata" yaml:"metadata"`
	NodeID               string          `json:"node_id" yaml:"node_id"`
	Status               string          `json:"status" yaml:"status"`
	Healthy              bool            `json:"healthy" yaml:"healthy"`
	AdapterHealth        []AdapterStatus `json:"adapter_health,omitempty" yaml:"adapter_health,omitempty"`
	PIPHealth            []PIPHealth     `json:"pip_health,omitempty" yaml:"pip_health,omitempty"`
	LastBundleGeneration int             `json:"last_bundle_generation,omitempty" yaml:"last_bundle_generation,omitempty"`
	LastBundleHash       string          `json:"last_bundle_hash,omitempty" yaml:"last_bundle_hash,omitempty"`
	UptimeSeconds        uint64          `json:"uptime_seconds,omitempty" yaml:"uptime_seconds,omitempty"`
	ErrorCount           int             `json:"error_count,omitempty" yaml:"error_count,omitempty"`
	LastError            string          `json:"last_error,omitempty" yaml:"last_error,omitempty"`
	ReportedAt           time.Time       `json:"reported_at" yaml:"reported_at"`
}

type RuntimeDecisionSummary struct {
	TypeMeta         `yaml:",inline"`
	Metadata         ObjectMeta            `json:"metadata" yaml:"metadata"`
	NodeID           string                `json:"node_id" yaml:"node_id"`
	WindowStart      time.Time             `json:"window_start" yaml:"window_start"`
	WindowEnd        time.Time             `json:"window_end" yaml:"window_end"`
	DecisionCount    int                   `json:"decision_count" yaml:"decision_count"`
	ByLevel          map[string]int        `json:"by_level,omitempty" yaml:"by_level,omitempty"`
	TopSubjects      []RuntimeSummaryCount `json:"top_subjects,omitempty" yaml:"top_subjects,omitempty"`
	TopRules         []RuntimeSummaryCount `json:"top_rules,omitempty" yaml:"top_rules,omitempty"`
	ActiveLeaseCount int                   `json:"active_lease_count,omitempty" yaml:"active_lease_count,omitempty"`
	ReportedAt       time.Time             `json:"reported_at" yaml:"reported_at"`
}

type RuntimeSummaryCount struct {
	ID    string `json:"id" yaml:"id"`
	Count int    `json:"count" yaml:"count"`
}

type AdapterStatus struct {
	TypeMeta           `yaml:",inline"`
	Metadata           ObjectMeta `json:"metadata" yaml:"metadata"`
	NodeID             string     `json:"node_id" yaml:"node_id"`
	AdapterID          string     `json:"adapter_id" yaml:"adapter_id"`
	Kind               string     `json:"kind" yaml:"kind"`
	Healthy            bool       `json:"healthy" yaml:"healthy"`
	Status             string     `json:"status,omitempty" yaml:"status,omitempty"`
	ActiveCapabilities []string   `json:"active_capabilities,omitempty" yaml:"active_capabilities,omitempty"`
	LastTelemetryAt    time.Time  `json:"last_telemetry_at,omitempty" yaml:"last_telemetry_at,omitempty"`
	ErrorDetail        string     `json:"error_detail,omitempty" yaml:"error_detail,omitempty"`
	ReportedAt         time.Time  `json:"reported_at" yaml:"reported_at"`
}

type FailoverStatus struct {
	TypeMeta                  `yaml:",inline"`
	Metadata                  ObjectMeta `json:"metadata" yaml:"metadata"`
	NodeID                    string     `json:"node_id" yaml:"node_id"`
	ForgeReachable            bool       `json:"forge_reachable" yaml:"forge_reachable"`
	LastSuccessfulHeartbeatAt time.Time  `json:"last_successful_heartbeat_at,omitempty" yaml:"last_successful_heartbeat_at,omitempty"`
	BundleAgeSeconds          uint64     `json:"bundle_age_seconds,omitempty" yaml:"bundle_age_seconds,omitempty"`
	ContextTTLStatus          string     `json:"context_ttl_status,omitempty" yaml:"context_ttl_status,omitempty"`
	ActiveMode                string     `json:"active_mode" yaml:"active_mode"`
	Reason                    string     `json:"reason,omitempty" yaml:"reason,omitempty"`
	ReportedAt                time.Time  `json:"reported_at" yaml:"reported_at"`
}

type RuntimeStatus struct {
	NodeID                 string                  `json:"node_id"`
	BundleGeneration       int                     `json:"bundle_generation"`
	BundleHash             string                  `json:"bundle_hash,omitempty"`
	Applied                bool                    `json:"applied"`
	DriftDetected          bool                    `json:"drift_detected"`
	ErrorDetail            string                  `json:"error_detail,omitempty"`
	ReportedAt             time.Time               `json:"reported_at"`
	FeatureProfile         string                  `json:"feature_profile,omitempty"`
	TupleEnforcementActive bool                    `json:"tuple_enforcement_active"`
	ActiveComponents       map[string]bool         `json:"active_components,omitempty"`
	BootstrapAutotune      BootstrapAutotuneStatus `json:"bootstrap_autotune_status,omitempty"`
	GraphLifecycle         GraphLifecycleStatus    `json:"graph_lifecycle_status,omitempty"`
	SourceBaseline         SourceBaselineStatus    `json:"source_baseline_status,omitempty"`
	ExemptionStatus        ExemptionStatus         `json:"exemption_status,omitempty"`
	Health                 *HealthReport           `json:"health,omitempty"`
	DecisionSummary        *RuntimeDecisionSummary `json:"decision_summary,omitempty"`
	AdapterStatuses        []AdapterStatus         `json:"adapter_statuses,omitempty"`
	Failover               *FailoverStatus         `json:"failover_status,omitempty"`
}

type TriggerSet struct {
	PPS  float64 `json:"pps" yaml:"pps"`
	SYN  float64 `json:"syn" yaml:"syn"`
	Scan float64 `json:"scan" yaml:"scan"`
	BPS  float64 `json:"bps" yaml:"bps"`
}

type BootstrapAutotuneStatus struct {
	Enabled          bool       `json:"enabled" yaml:"enabled"`
	Phase            string     `json:"phase" yaml:"phase"`
	ObservedSeconds  uint64     `json:"observed_seconds" yaml:"observed_seconds"`
	RequiredSeconds  uint64     `json:"required_seconds" yaml:"required_seconds"`
	CleanRatio       float64    `json:"clean_ratio" yaml:"clean_ratio"`
	CompletedWindows int        `json:"completed_windows" yaml:"completed_windows"`
	ActiveTriggers   TriggerSet `json:"active_triggers" yaml:"active_triggers"`
	LastUpdateAt     time.Time  `json:"last_update_at,omitempty" yaml:"last_update_at,omitempty"`
	ReadyForSteady   bool       `json:"ready_for_steady" yaml:"ready_for_steady"`
}

type GraphLifecycleStatus struct {
	Phase                string    `json:"phase" yaml:"phase"`
	StartedAt            time.Time `json:"started_at,omitempty" yaml:"started_at,omitempty"`
	CleanLearningSeconds uint64    `json:"clean_learning_seconds" yaml:"clean_learning_seconds"`
	LearnedEdges         int       `json:"learned_edges" yaml:"learned_edges"`
	CandidateEdges       int       `json:"candidate_edges" yaml:"candidate_edges"`
	BaselineCoverage     float64   `json:"baseline_coverage" yaml:"baseline_coverage"`
	ReadyToFreeze        bool      `json:"ready_to_freeze" yaml:"ready_to_freeze"`
	FreezeBlockedBy      []string  `json:"freeze_blocked_by,omitempty" yaml:"freeze_blocked_by,omitempty"`
}

type SourceBaselineStatus struct {
	TrackedSources        int `json:"tracked_sources" yaml:"tracked_sources"`
	MaxSources            int `json:"max_sources" yaml:"max_sources"`
	HighConfidenceSources int `json:"high_confidence_sources" yaml:"high_confidence_sources"`
}

type ExemptionStatus struct {
	LocalWhitelistHash    string `json:"local_whitelist_hash,omitempty" yaml:"local_whitelist_hash,omitempty"`
	ManagedWhitelistHash  string `json:"managed_whitelist_hash,omitempty" yaml:"managed_whitelist_hash,omitempty"`
	FeedbackEntriesActive int    `json:"feedback_entries_active" yaml:"feedback_entries_active"`
}

type BaselineProposal struct {
	APIVersion string               `json:"apiVersion" yaml:"apiVersion"`
	Kind       string               `json:"kind" yaml:"kind"`
	Metadata   ProposalMetadata     `json:"metadata" yaml:"metadata"`
	Spec       BaselineProposalSpec `json:"spec" yaml:"spec"`
}

type ProposalMetadata struct {
	NodeID      string    `json:"node_id" yaml:"node_id"`
	GeneratedAt time.Time `json:"generated_at" yaml:"generated_at"`
}

type BaselineProposalSpec struct {
	BootstrapAutotune     BootstrapProposalSummary `json:"bootstrap_autotune,omitempty" yaml:"bootstrap_autotune,omitempty"`
	SourceBaselineSummary SourceProposalSummary    `json:"source_baseline_summary,omitempty" yaml:"source_baseline_summary,omitempty"`
	GraphSummary          GraphProposalSummary     `json:"graph_summary,omitempty" yaml:"graph_summary,omitempty"`
	EdgeBaselineSummary   EdgeProposalSummary      `json:"edge_baseline_summary,omitempty" yaml:"edge_baseline_summary,omitempty"`
	GraphEdges            []GraphEdgeEntry         `json:"graph_edges,omitempty" yaml:"graph_edges,omitempty"`
}

type GraphProposal struct {
	APIVersion string            `json:"apiVersion" yaml:"apiVersion"`
	Kind       string            `json:"kind" yaml:"kind"`
	Metadata   ProposalMetadata  `json:"metadata" yaml:"metadata"`
	Spec       GraphProposalSpec `json:"spec" yaml:"spec"`
}

type GraphProposalSpec struct {
	Summary       GraphProposalSummary `json:"summary,omitempty" yaml:"summary,omitempty"`
	Edges         []GraphEdgeEntry     `json:"edges,omitempty" yaml:"edges,omitempty"`
	Lifecycle     GraphLifecycleStatus `json:"lifecycle,omitempty" yaml:"lifecycle,omitempty"`
	TriggerReason string               `json:"trigger_reason,omitempty" yaml:"trigger_reason,omitempty"`
}

type BootstrapProposalSummary struct {
	Phase           string     `json:"phase" yaml:"phase"`
	ObservedSeconds uint64     `json:"observed_seconds" yaml:"observed_seconds"`
	CleanRatio      float64    `json:"clean_ratio" yaml:"clean_ratio"`
	Triggers        TriggerSet `json:"triggers" yaml:"triggers"`
}

type SourceProposalSummary struct {
	TrackedSources        int     `json:"tracked_sources" yaml:"tracked_sources"`
	HighConfidenceSources int     `json:"high_confidence_sources" yaml:"high_confidence_sources"`
	AverageConfidence     float64 `json:"average_confidence" yaml:"average_confidence"`
}

type GraphProposalSummary struct {
	CandidateEdges int `json:"candidate_edges" yaml:"candidate_edges"`
	LearnedEdges   int `json:"learned_edges" yaml:"learned_edges"`
	ApprovedEdges  int `json:"approved_edges" yaml:"approved_edges"`
	DeniedEdges    int `json:"denied_edges" yaml:"denied_edges"`
	FrozenEdges    int `json:"frozen_edges" yaml:"frozen_edges"`
}

type EdgeProposalSummary struct {
	EdgesWithBaseline int     `json:"edges_with_baseline" yaml:"edges_with_baseline"`
	BaselineCoverage  float64 `json:"baseline_coverage" yaml:"baseline_coverage"`
}

type GraphEdgeEntry struct {
	Source      EdgeEntity             `json:"source" yaml:"source"`
	Destination EdgeEntity             `json:"destination" yaml:"destination"`
	Predicate   string                 `json:"predicate,omitempty" yaml:"predicate,omitempty"`
	Dimensions  map[string]string      `json:"dimensions,omitempty" yaml:"dimensions,omitempty"`
	State       string                 `json:"state,omitempty" yaml:"state,omitempty"`
	Baselines   []MetricBaselineValues `json:"baselines,omitempty" yaml:"baselines,omitempty"`
}

type EdgeEntity struct {
	Kind string `json:"kind" yaml:"kind"`
	ID   string `json:"id" yaml:"id"`
}

type MetricBaselineValues struct {
	MetricID     string  `json:"metric_id" yaml:"metric_id"`
	EWMA         float64 `json:"ewma" yaml:"ewma"`
	Peak         float64 `json:"peak,omitempty" yaml:"peak,omitempty"`
	Observations int     `json:"observations" yaml:"observations"`
}
