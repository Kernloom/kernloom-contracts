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

	KindRuntimeBundle         = "RuntimeBundle"
	KindRuntimePolicyPack     = "RuntimePolicyPack"
	KindRuntimeDecision       = "RuntimeDecision"
	KindLocalRiskAssessment   = "LocalRiskAssessment"
	KindEnforcementReceipt    = "EnforcementReceipt"
	KindRuntimeFinding        = "RuntimeFinding"
	KindRuntimeBundleAck      = "RuntimeBundleAck"
	SignatureAlgorithmEd25519 = "ed25519"
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
	Ref              RegistryRef                 `json:"ref,omitempty" yaml:"ref,omitempty"`
	ContextVersion   string                      `json:"context_version,omitempty" yaml:"context_version,omitempty"`
	ContextKeys      []ContextKeyEntry           `json:"context_keys,omitempty" yaml:"context_keys,omitempty"`
	RiskLevels       []RiskLevelEntry            `json:"risk_levels,omitempty" yaml:"risk_levels,omitempty"`
	RiskTaxonomy     RiskTaxonomySnapshot        `json:"risk_taxonomy,omitempty" yaml:"risk_taxonomy,omitempty"`
	Capabilities     []CapabilityEntry           `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	ActionLevels     []ActionLevelEntry          `json:"action_levels,omitempty" yaml:"action_levels,omitempty"`
	ActionContracts []RuntimeActionContractEntry `json:"action_contracts,omitempty" yaml:"action_contracts,omitempty"`
	Signals          []SignalEntry               `json:"signals,omitempty" yaml:"signals,omitempty"`
	Metrics          []MetricEntry               `json:"metrics,omitempty" yaml:"metrics,omitempty"`
	LabelPolicies    []LabelPolicyEntry          `json:"label_policies,omitempty" yaml:"label_policies,omitempty"`
	RetentionClasses []RetentionClassEntry       `json:"retention_classes,omitempty" yaml:"retention_classes,omitempty"`
	Granularities    []GranularityEntry          `json:"granularities,omitempty" yaml:"granularities,omitempty"`
	Scopes           ScopeRegistryView           `json:"scopes,omitempty" yaml:"scopes,omitempty"`
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
	Scopes                      []string                         `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	Quality                     map[string]any                   `json:"quality,omitempty" yaml:"quality,omitempty"`
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
	CapabilitiesRequired []string              `json:"capabilities_required,omitempty" yaml:"capabilities_required,omitempty"`
	DefaultEffect        string                `json:"default_effect,omitempty" yaml:"default_effect,omitempty"`
	Rules                []RuntimePolicyRule   `json:"rules,omitempty" yaml:"rules,omitempty"`
	Exports              []RuntimeExportTarget `json:"exports,omitempty" yaml:"exports,omitempty"`
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
	SignalID   string  `json:"signal_id,omitempty" yaml:"signal_id,omitempty"`
	SignalType string  `json:"signal_type,omitempty" yaml:"signal_type,omitempty"`
	Domain     string  `json:"domain,omitempty" yaml:"domain,omitempty"`
	Score      int     `json:"score" yaml:"score"`
	Confidence float64 `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	Weight     float64 `json:"weight,omitempty" yaml:"weight,omitempty"`
}

type EntityRef struct {
	Kind      string            `json:"kind" yaml:"kind"`
	ID        string            `json:"id" yaml:"id"`
	Namespace string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
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
