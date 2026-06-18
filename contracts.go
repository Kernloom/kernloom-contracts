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
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

type ObjectMeta struct {
	ID         string            `json:"id,omitempty"`
	Name       string            `json:"name,omitempty"`
	NodeID     string            `json:"node_id,omitempty"`
	Generation int               `json:"generation,omitempty"`
	IssuedAt   time.Time         `json:"issued_at,omitempty"`
	ExpiresAt  time.Time         `json:"expires_at,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id,omitempty"`
	Value     string `json:"value"`
}

// RuntimeBundle is the signed Forge-to-KLIQ runtime artifact.
type RuntimeBundle struct {
	TypeMeta
	Metadata  ObjectMeta        `json:"metadata"`
	Spec      RuntimeBundleSpec `json:"spec"`
	Signature Signature         `json:"signature"`
}

type RuntimeBundleSpec struct {
	RuntimePolicyPack      RuntimePolicyPack `json:"runtime_policy_pack"`
	RuntimePDPProfile      RuntimePDPProfile `json:"runtime_pdp_profile,omitempty"`
	ContextRegistryVersion string            `json:"context_registry_version,omitempty"`
	AdapterSelector        AdapterSelector   `json:"adapter_selector,omitempty"`
	BaselineLifecycle      BaselineLifecycle `json:"baseline_lifecycle,omitempty"`
	GraphLifecycle         GraphLifecycle    `json:"graph_lifecycle,omitempty"`
	EnforcementBounds      EnforcementBounds `json:"enforcement_bounds,omitempty"`
	Failover               FailoverConfig    `json:"failover,omitempty"`
	Extensions             map[string]any    `json:"extensions,omitempty"`
}

type AdapterSelector struct {
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
	PreferredAdapters    []string `json:"preferred_adapters,omitempty"`
	DisabledAdapters     []string `json:"disabled_adapters,omitempty"`
}

type RuntimePDPProfile struct {
	Name      string         `json:"name,omitempty"`
	Mode      string         `json:"mode,omitempty"`
	Variables []RuntimeInput `json:"variables,omitempty"`
}

type RuntimeInput struct {
	Name     string `json:"name"`
	Required bool   `json:"required,omitempty"`
	Source   string `json:"source,omitempty"`
}

type BaselineLifecycle struct {
	Mode             string   `json:"mode,omitempty"`
	LearningWindow   Duration `json:"learning_window,omitempty"`
	MinCleanRuntime  Duration `json:"min_clean_runtime,omitempty"`
	MinConfidence    float64  `json:"min_confidence,omitempty"`
	ProposalUpload   bool     `json:"proposal_upload,omitempty"`
	AllowLocalFreeze bool     `json:"allow_local_freeze,omitempty"`
}

type GraphLifecycle struct {
	Mode                 string   `json:"mode,omitempty"`
	MinCleanLearning     Duration `json:"min_clean_learning,omitempty"`
	MinLearnedEdges      int      `json:"min_learned_edges,omitempty"`
	MinBaselineCoverage  float64  `json:"min_baseline_coverage,omitempty"`
	RequireNoBlockFor    Duration `json:"require_no_block_for,omitempty"`
	FreezeApproval       string   `json:"freeze_approval,omitempty"`
	ObserveAfterFreeze   Duration `json:"observe_after_freeze,omitempty"`
	FinalPhase           string   `json:"final_phase,omitempty"`
	IncludeEdgeBaselines bool     `json:"include_edge_baselines,omitempty"`
}

type EnforcementBounds struct {
	MaxActionDuringBootstrap     string `json:"max_action_during_bootstrap,omitempty"`
	MaxActionDuringFrozenObserve string `json:"max_action_during_frozen_observe,omitempty"`
	MaxActionDuringFrozenEnforce string `json:"max_action_during_frozen_enforce,omitempty"`
	AllowBlock                   bool   `json:"allow_block,omitempty"`
}

type FailoverConfig struct {
	Behavior                          string `json:"behavior,omitempty"`
	AllowLearningWhileOffline         bool   `json:"allow_learning_while_offline,omitempty"`
	AllowLocalFreezeWhileOffline      bool   `json:"allow_local_freeze_while_offline,omitempty"`
	AllowEnforcePromotionWhileOffline bool   `json:"allow_enforce_promotion_while_offline,omitempty"`
}

// RuntimePolicyPack contains Forge-compiled CEL rules and action authorization.
type RuntimePolicyPack struct {
	TypeMeta
	Metadata ObjectMeta            `json:"metadata"`
	Spec     RuntimePolicyPackSpec `json:"spec"`
}

type RuntimePolicyPackSpec struct {
	CapabilitiesRequired []string              `json:"capabilities_required,omitempty"`
	DefaultEffect        string                `json:"default_effect,omitempty"`
	Rules                []RuntimePolicyRule   `json:"rules,omitempty"`
	Exports              []RuntimeExportTarget `json:"exports,omitempty"`
}

type RuntimePolicyRule struct {
	ID          string            `json:"id,omitempty"`
	Description string            `json:"description,omitempty"`
	When        string            `json:"when"`
	Then        RuntimeActionSpec `json:"then"`
	ReasonCodes []string          `json:"reason_codes,omitempty"`
}

type RuntimeActionSpec struct {
	Capability string         `json:"capability"`
	Level      string         `json:"level,omitempty"`
	TTL        Duration       `json:"ttl,omitempty"`
	Params     map[string]any `json:"params,omitempty"`
}

type RuntimeExportTarget struct {
	Kind string            `json:"kind"`
	Name string            `json:"name,omitempty"`
	Meta map[string]string `json:"meta,omitempty"`
}

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type LocalRiskAssessment struct {
	TypeMeta
	Metadata      ObjectMeta         `json:"metadata"`
	Subject       EntityRef          `json:"subject"`
	Level         RiskLevel          `json:"level"`
	Score         int                `json:"score"`
	Confidence    float64            `json:"confidence"`
	Completeness  float64            `json:"completeness"`
	Domains       []string           `json:"domains,omitempty"`
	Contributions []RiskContribution `json:"contributions,omitempty"`
	MissingInputs []string           `json:"missing_inputs,omitempty"`
	ValidUntil    time.Time          `json:"valid_until"`
	Model         string             `json:"model"`
}

type RiskContribution struct {
	SignalID   string  `json:"signal_id,omitempty"`
	SignalType string  `json:"signal_type,omitempty"`
	Domain     string  `json:"domain,omitempty"`
	Score      int     `json:"score"`
	Confidence float64 `json:"confidence,omitempty"`
	Weight     float64 `json:"weight,omitempty"`
}

type EntityRef struct {
	Kind      string            `json:"kind"`
	ID        string            `json:"id"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type RuntimeDecision struct {
	TypeMeta
	Metadata     ObjectMeta           `json:"metadata"`
	Subject      EntityRef            `json:"subject"`
	Action       RuntimeActionSpec    `json:"action"`
	Effect       string               `json:"effect"`
	Decider      string               `json:"decider"`
	Risk         *LocalRiskAssessment `json:"risk,omitempty"`
	ReasonCodes  []string             `json:"reason_codes,omitempty"`
	EvidenceRefs []string             `json:"evidence_refs,omitempty"`
	ValidUntil   time.Time            `json:"valid_until,omitempty"`
}

type EnforcementReceipt struct {
	TypeMeta
	Metadata     ObjectMeta `json:"metadata"`
	DecisionID   string     `json:"decision_id"`
	LeaseID      string     `json:"lease_id,omitempty"`
	NodeID       string     `json:"node_id"`
	AdapterID    string     `json:"adapter_id"`
	Status       string     `json:"status"`
	RevertStatus string     `json:"revert_status,omitempty"`
	Message      string     `json:"message,omitempty"`
	Action       string     `json:"action,omitempty"`
	Target       string     `json:"target,omitempty"`
	FencingToken string     `json:"fencing_token,omitempty"`
	AppliedAt    time.Time  `json:"applied_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	RevertedAt   *time.Time `json:"reverted_at,omitempty"`
}

type RuntimeBundleAck struct {
	TypeMeta
	Metadata         ObjectMeta `json:"metadata"`
	NodeID           string     `json:"node_id"`
	BundleGeneration int        `json:"bundle_generation"`
	BundleHash       string     `json:"bundle_hash,omitempty"`
	Applied          bool       `json:"applied"`
	ErrorDetail      string     `json:"error_detail,omitempty"`
	ReportedAt       time.Time  `json:"reported_at"`
}

type RuntimeFinding struct {
	TypeMeta
	Metadata     ObjectMeta        `json:"metadata"`
	NodeID       string            `json:"node_id"`
	Subject      EntityRef         `json:"subject"`
	Severity     string            `json:"severity"`
	Title        string            `json:"title"`
	Detail       string            `json:"detail,omitempty"`
	EvidenceRefs []string          `json:"evidence_refs,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	ObservedAt   time.Time         `json:"observed_at"`
}
