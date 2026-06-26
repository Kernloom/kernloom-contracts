// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package contracts_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
)

func TestRuntimeBundleSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	bundle := sampleRuntimeBundle(now)

	signed, err := contracts.SignRuntimeBundle(bundle, "forge-test-key", priv)
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	if err := contracts.VerifyRuntimeBundle(signed, pub, now); err != nil {
		t.Fatalf("verify signed bundle: %v", err)
	}

	signed.Metadata.Generation = 2
	if err := contracts.VerifyRuntimeBundle(signed, pub, now); err == nil {
		t.Fatal("tampered bundle should fail verification")
	}
}

func TestRuntimeBundleFixtureRoundTrip(t *testing.T) {
	raw, err := os.ReadFile("testdata/runtime_bundle_unsigned.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var bundle contracts.RuntimeBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if err := contracts.ValidateRuntimeBundle(bundle, time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("validate fixture: %v", err)
	}
	if bundle.Spec.RuntimePolicyPack.Spec.Rules[0].Then.TTL.Duration != 10*time.Minute {
		t.Fatalf("ttl decode: got %s", bundle.Spec.RuntimePolicyPack.Spec.Rules[0].Then.TTL.Duration)
	}
}

func TestLocalRiskAssessmentFixtureRoundTrip(t *testing.T) {
	raw, err := os.ReadFile("testdata/local_risk_assessment.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var assessment contracts.LocalRiskAssessment
	if err := json.Unmarshal(raw, &assessment); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if assessment.Level != contracts.RiskHigh {
		t.Fatalf("level: got %s", assessment.Level)
	}
	if len(assessment.Contributions) != 1 || assessment.Contributions[0].Domain != "source" {
		t.Fatalf("contributions: %#v", assessment.Contributions)
	}
}

func TestRuntimePolicyPackResponseIRRoundTrip(t *testing.T) {
	pack := contracts.RuntimePolicyPack{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimePolicyPack,
		},
		Metadata: contracts.ObjectMeta{Name: "response-pack"},
		Spec: contracts.RuntimePolicyPackSpec{
			AccessPolicies: []contracts.RuntimeAccessPolicy{{
				ID: "ziti-controller-admin-access",
				Subject: contracts.RuntimeAccessSubject{
					Type: "group",
					Ref:  "kernloom-admins",
				},
				Action: "access",
				Resource: contracts.RuntimeAccessResource{
					Type: "application",
					Ref:  "ziti-controller",
				},
				Conditions: []contracts.RuntimeAccessCondition{{
					ID:       "require-mfa",
					Type:     "authentication_strength",
					Signal:   "session.authentication.strength",
					Operator: "in",
					Value:    []any{"mfa", "phishing_resistant_mfa"},
				}},
				Effect:        "allow",
				DefaultEffect: "deny",
				Source:        "protect-ziti-controller-admin-access",
			}},
			DetectionRules: []contracts.RuntimeDetectionRule{{
				ID:          "admin-deny",
				Type:        "access.denied_threshold",
				ResourceRef: "ziti-controller",
				Subject: contracts.RuntimeDetectionSubject{
					Type: "group",
					Ref:  "kernloom-admins",
				},
				Threshold: 5,
				Window:    contracts.NewDuration(15 * time.Minute),
				Scope:     "source",
			}},
			ResponseRules: []contracts.RuntimeResponseRule{{
				ID: "denied-access-alert",
				When: contracts.RuntimeResponseTrigger{
					Detection: "admin-deny",
				},
				Then: []contracts.RuntimeResponseAction{{
					ID:       "notify.alert.emit",
					Route:    "alert-route.security-ops",
					Severity: "medium",
					Dedupe:   contracts.NewDuration(15 * time.Minute),
				}},
			}},
			AlertRoutes: []contracts.RuntimeAlertRoute{{
				ID: "alert-route.security-ops",
				Audience: contracts.RuntimeAlertAudience{
					Type: "group",
					Ref:  "group.kernloom-security-ops",
				},
				Channels: []contracts.RuntimeAlertChannel{{
					Type: "slack",
					Ref:  "channel.security-ops",
				}},
				DefaultSeverity: "medium",
				Deduplication: contracts.RuntimeAlertDeduplication{
					Enabled: true,
					Window:  contracts.NewDuration(15 * time.Minute),
					Keys:    []string{"resource.id", "detection.id", "source.identity_or_ip"},
				},
			}},
		},
	}

	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded contracts.RuntimePolicyPack
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := decoded.Spec.ResponseRules[0].Then[0].Route; got != "alert-route.security-ops" {
		t.Fatalf("route = %q", got)
	}
	if got := decoded.Spec.ResponseRules[0].When.Detection; got != "admin-deny" {
		t.Fatalf("response detection = %q", got)
	}
	if got := decoded.Spec.DetectionRules[0].Subject.Ref; got != "kernloom-admins" {
		t.Fatalf("detection subject = %q", got)
	}
	if got := decoded.Spec.AlertRoutes[0].Deduplication.Window.Duration; got != 15*time.Minute {
		t.Fatalf("dedupe window = %s", got)
	}
	if len(decoded.Spec.AccessPolicies) != 1 {
		t.Fatalf("access policies = %d, want 1", len(decoded.Spec.AccessPolicies))
	}
	access := decoded.Spec.AccessPolicies[0]
	if access.Subject.Ref != "kernloom-admins" || access.Resource.Ref != "ziti-controller" || access.Effect != "allow" {
		t.Fatalf("access policy not preserved: %#v", access)
	}
	if len(access.Conditions) != 1 || access.Conditions[0].Signal != "session.authentication.strength" {
		t.Fatalf("access conditions not preserved: %#v", access.Conditions)
	}
}

func TestRuntimePolicyPackAutonomyLifecycleRoundTrip(t *testing.T) {
	pack := contracts.RuntimePolicyPack{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimePolicyPack,
		},
		Metadata: contracts.ObjectMeta{Name: "autonomy-pack"},
		Spec: contracts.RuntimePolicyPackSpec{
			AutonomyLifecycle: &contracts.RuntimeAutonomyLifecycleSpec{
				Hold: []contracts.RuntimeAutonomyHoldRule{{
					ID: "hold-enforcement-feedback",
					While: contracts.RuntimeAutonomyHoldCondition{
						EnforcementFeedbackActive: true,
						Levels:                    []string{"soft", "hard", "block"},
					},
					Action: contracts.RuntimeActionSpec{
						Capability: "enforce.traffic.rate_limit",
						Level:      "hard",
						TTL:        contracts.NewDuration(30 * time.Second),
						Params:     map[string]any{"rate_pps": 100},
					},
					ReasonCodes: []string{"enforcement_hold"},
				}},
				StepDown: contracts.RuntimeAutonomyStepDown{
					CleanAfter:   contracts.NewDuration(30 * time.Second),
					ObserveAfter: contracts.NewDuration(2 * time.Minute),
				},
				Allow: []contracts.RuntimeAutonomyAllowance{{
					Action:  "enforce.traffic.rate_limit",
					Subject: contracts.RuntimeAutonomySubject{Type: "source", Ref: "unknown"},
				}, {
					Action:                 "enforce.traffic.drop",
					RequiresPreviousAction: "enforce.traffic.rate_limit",
				}},
				ApprovalRequired: []contracts.RuntimeAutonomyApprovalRequirement{{
					Action: "enforce.identity.disable",
				}},
				MaxActionDuration: []contracts.RuntimeAutonomyActionDurationLimit{{
					Action:   "enforce.traffic.drop",
					Duration: contracts.NewDuration(15 * time.Minute),
				}},
				BlastRadius: []contracts.RuntimeAutonomyBlastRadiusLimit{{
					Action:     "enforce.traffic.drop",
					MaxTargets: 100,
					Scope:      "tenant",
					Window:     contracts.NewDuration(10 * time.Minute),
				}},
				MaxRenewals:             3,
				RestorePreviousOnResume: true,
				RequiresAudit:           true,
			},
		},
	}

	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded contracts.RuntimePolicyPack
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	lifecycle := decoded.Spec.AutonomyLifecycle
	if lifecycle == nil || len(lifecycle.Hold) != 1 {
		t.Fatalf("autonomy lifecycle = %#v", lifecycle)
	}
	if got := lifecycle.Hold[0].Action.TTL.Duration; got != 30*time.Second {
		t.Fatalf("hold ttl = %s", got)
	}
	if got := lifecycle.StepDown.ObserveAfter.Duration; got != 2*time.Minute {
		t.Fatalf("observe_after = %s", got)
	}
	if lifecycle.MaxRenewals != 3 || !lifecycle.RequiresAudit {
		t.Fatalf("autonomy bounds = %#v", lifecycle)
	}
	if !lifecycle.RestorePreviousOnResume || len(lifecycle.Allow) != 2 || len(lifecycle.BlastRadius) != 1 {
		t.Fatalf("autonomy lifecycle = %#v", lifecycle)
	}
}

func TestPolicySemanticContractsRoundTrip(t *testing.T) {
	payload := struct {
		Condition contracts.RequirementConditionContract `json:"condition"`
		Evaluator contracts.DetectionEvaluatorContract   `json:"evaluator"`
		State     contracts.RuntimeActionState           `json:"state"`
		Truth     contracts.TruthValue                   `json:"truth"`
	}{
		Condition: contracts.RequirementConditionContract{
			ID:             "require-low-risk",
			Signal:         "subject.risk.level",
			Operator:       "eq",
			Value:          "low",
			Freshness:      contracts.RequirementFreshnessContract{MaxAge: contracts.NewDuration(30 * time.Minute), Require: true},
			MinConfidence:  0.8,
			MissingContext: contracts.MissingContextDeny,
		},
		Evaluator: contracts.DetectionEvaluatorContract{
			Type:              contracts.DetectionEvaluatorWindowed,
			StateRequired:     true,
			PreferredRuntimes: []string{"kliq-local-windowed"},
			AllowedRuntimes:   []string{"kliq-local-windowed", "correlate"},
		},
		State: contracts.RuntimeActionState{
			ActionID:  "enforce.traffic.rate_limit",
			Level:     "hard",
			SourceID:  "10.0.0.8",
			Active:    true,
			AppliedAt: time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2026, 6, 22, 10, 15, 0, 0, time.UTC),
			Evidence:  []string{"runtime_response_state"},
		},
		Truth: contracts.TruthUnknown,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		Condition contracts.RequirementConditionContract `json:"condition"`
		Evaluator contracts.DetectionEvaluatorContract   `json:"evaluator"`
		State     contracts.RuntimeActionState           `json:"state"`
		Truth     contracts.TruthValue                   `json:"truth"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Condition.Freshness.MaxAge.Duration != 30*time.Minute {
		t.Fatalf("freshness max age = %s", decoded.Condition.Freshness.MaxAge.Duration)
	}
	if decoded.Evaluator.Type != contracts.DetectionEvaluatorWindowed || !decoded.Evaluator.StateRequired {
		t.Fatalf("evaluator = %#v", decoded.Evaluator)
	}
	if !decoded.State.Active || decoded.State.ActionID != "enforce.traffic.rate_limit" {
		t.Fatalf("runtime action state = %#v", decoded.State)
	}
	if decoded.Truth != contracts.TruthUnknown {
		t.Fatalf("truth = %s", decoded.Truth)
	}
}

func TestContextRiskContractsRoundTrip(t *testing.T) {
	now := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	snapshot := contracts.ContextSnapshot{
		TypeMeta: contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindContextSnapshot},
		Metadata: contracts.ObjectMeta{
			ID: "snapshot-fixture",
		},
		SnapshotAt:             now,
		ValidUntil:             now.Add(30 * time.Minute),
		ContextRegistryVersion: "0.2.0",
		Facts: []contracts.ContextFact{{
			Key:    "device.posture.status",
			Value:  "unhealthy",
			Entity: contracts.EntityRef{Kind: "device", ID: "device:alice-laptop"},
			Status: "known",
			Quality: contracts.DataQuality{
				Confidence: 0.95,
				MaxAge:     contracts.NewDuration(30 * time.Minute),
			},
			ObservedAt: now.Add(-time.Minute),
			ValidUntil: now.Add(29 * time.Minute),
			Provenance: contracts.ContextProvenance{
				SourceAdapter:  "openziti-fixture",
				SourceType:     "pip_fixture",
				CollectedAt:    now,
				MappingVersion: "fixture-mapping@1.0.0",
			},
		}},
		VendorAssessments: []contracts.VendorAssessment{{
			TypeMeta: contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindVendorAssessment},
			Metadata: contracts.ObjectMeta{
				ID: "vendor-openziti-posture",
			},
			Vendor:     "openziti",
			Key:        "openziti.posture_result",
			Value:      "fail",
			Entity:     contracts.EntityRef{Kind: "device", ID: "device:alice-laptop"},
			MappedTo:   "device.posture.status",
			ObservedAt: now.Add(-time.Minute),
			Provenance: contracts.ContextProvenance{
				SourceAdapter: "openziti-fixture",
				SourceType:    "pip_fixture",
				CollectedAt:   now,
			},
		}},
		PIPHealth: []contracts.PIPHealth{{
			TypeMeta:      contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindPIPHealth},
			SourceAdapter: "openziti-fixture",
			Status:        "healthy",
			Healthy:       true,
			LastSeenAt:    now,
		}},
	}

	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var decoded contracts.ContextSnapshot
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if decoded.Facts[0].Key != "device.posture.status" || decoded.VendorAssessments[0].MappedTo != "device.posture.status" {
		t.Fatalf("bad snapshot roundtrip: %#v", decoded)
	}

	assessment := contracts.RiskAssessment{
		TypeMeta:     contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindRiskAssessment},
		Metadata:     contracts.ObjectMeta{ID: "risk-fixture"},
		Scope:        contracts.EntityRef{Kind: "subject", ID: "subject:alice@example.com"},
		Score:        73,
		Level:        contracts.RiskHigh,
		Confidence:   0.91,
		Completeness: 0.75,
		Model:        "fixture-enterprise-access-risk",
		ModelVersion: "1.0.0",
		CalculatedAt: now,
		ValidUntil:   now.Add(30 * time.Minute),
		Contributions: []contracts.RiskContribution{{
			Model:          "fixture-enterprise-access-risk",
			ModelVersion:   "1.0.0",
			RuleID:         "device_posture_unhealthy",
			ContextKey:     "device.posture.status",
			BaseValue:      45,
			Direction:      "increase",
			EffectiveValue: 41.2,
		}},
		MissingInputs: []string{"session.authentication.strength"},
	}
	raw, err = json.Marshal(assessment)
	if err != nil {
		t.Fatalf("marshal assessment: %v", err)
	}
	var decodedAssessment contracts.RiskAssessment
	if err := json.Unmarshal(raw, &decodedAssessment); err != nil {
		t.Fatalf("unmarshal assessment: %v", err)
	}
	if decodedAssessment.Contributions[0].RuleID != "device_posture_unhealthy" {
		t.Fatalf("bad assessment roundtrip: %#v", decodedAssessment)
	}
}

func TestKLIQForgeFeedbackContractsRoundTrip(t *testing.T) {
	now := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	payload := struct {
		Inventory       contracts.ComponentInventory     `json:"inventory"`
		Health          contracts.HealthReport           `json:"health"`
		DecisionSummary contracts.RuntimeDecisionSummary `json:"decision_summary"`
		AdapterStatus   contracts.AdapterStatus          `json:"adapter_status"`
		Failover        contracts.FailoverStatus         `json:"failover"`
		Baseline        contracts.BaselineProposal       `json:"baseline"`
		Graph           contracts.GraphProposal          `json:"graph"`
	}{
		Inventory: contracts.ComponentInventory{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindComponentInventory,
			Metadata:   contracts.ComponentInventoryMetadata{ID: "klshield-node-1", Timestamp: now},
			ControlledBy: contracts.ComponentInventoryControl{
				NodeID:        "node-1",
				PluginAdapter: "builtin-klshield",
			},
			Component: contracts.ComponentInventoryProduct{Product: "kernloom-shield", Version: "0.4.0"},
			Roles:     []string{"pep", "sensor"},
			Profiles:  []string{"network.l3_l4_filter"},
			EffectiveCapabilities: []contracts.ComponentCapabilityStatus{{
				ID:          "enforce.traffic.rate_limit",
				Status:      "available",
				Granularity: []string{"src_ip"},
			}},
			OS:         "linux",
			Arch:       "amd64",
			ReportedAt: now,
		},
		Health: contracts.HealthReport{
			TypeMeta:             contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindHealthReport},
			NodeID:               "node-1",
			Status:               "healthy",
			Healthy:              true,
			LastBundleGeneration: 7,
			UptimeSeconds:        3600,
			ReportedAt:           now,
		},
		DecisionSummary: contracts.RuntimeDecisionSummary{
			TypeMeta:         contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindRuntimeDecisionSummary},
			NodeID:           "node-1",
			WindowStart:      now.Add(-5 * time.Minute),
			WindowEnd:        now,
			DecisionCount:    3,
			ByLevel:          map[string]int{"observe": 1, "soft": 2},
			ActiveLeaseCount: 1,
			ReportedAt:       now,
		},
		AdapterStatus: contracts.AdapterStatus{
			TypeMeta:           contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindAdapterStatus},
			NodeID:             "node-1",
			AdapterID:          "klshield",
			Kind:               "pep",
			Healthy:            true,
			ActiveCapabilities: []string{"enforce.traffic.rate_limit"},
			LastTelemetryAt:    now,
			ReportedAt:         now,
		},
		Failover: contracts.FailoverStatus{
			TypeMeta:                  contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindFailoverStatus},
			NodeID:                    "node-1",
			ForgeReachable:            false,
			LastSuccessfulHeartbeatAt: now.Add(-time.Minute),
			BundleAgeSeconds:          120,
			ContextTTLStatus:          "fresh",
			ActiveMode:                "degraded",
			ReportedAt:                now,
		},
		Baseline: contracts.BaselineProposal{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindBaselineProposal,
			Metadata:   contracts.ProposalMetadata{NodeID: "node-1", GeneratedAt: now},
			Spec: contracts.BaselineProposalSpec{
				BootstrapAutotune: contracts.BootstrapProposalSummary{
					Phase:           "ready",
					ObservedSeconds: 900,
					CleanRatio:      0.98,
					Triggers:        contracts.TriggerSet{PPS: 420},
				},
			},
		},
		Graph: contracts.GraphProposal{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindGraphProposal,
			Metadata:   contracts.ProposalMetadata{NodeID: "node-1", GeneratedAt: now},
			Spec: contracts.GraphProposalSpec{
				Summary: contracts.GraphProposalSummary{LearnedEdges: 1},
				Edges: []contracts.GraphEdgeEntry{{
					Source:      contracts.EdgeEntity{Kind: "ip", ID: "10.0.0.8"},
					Destination: contracts.EdgeEntity{Kind: "service", ID: "public-edge"},
					Predicate:   "network.connects_to",
				}},
			},
		},
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		Inventory       contracts.ComponentInventory     `json:"inventory"`
		Health          contracts.HealthReport           `json:"health"`
		DecisionSummary contracts.RuntimeDecisionSummary `json:"decision_summary"`
		AdapterStatus   contracts.AdapterStatus          `json:"adapter_status"`
		Failover        contracts.FailoverStatus         `json:"failover"`
		Baseline        contracts.BaselineProposal       `json:"baseline"`
		Graph           contracts.GraphProposal          `json:"graph"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Inventory.EffectiveCapabilities[0].ID != "enforce.traffic.rate_limit" {
		t.Fatalf("inventory roundtrip: %#v", decoded.Inventory)
	}
	if decoded.DecisionSummary.ByLevel["soft"] != 2 || decoded.Graph.Spec.Edges[0].Predicate != "network.connects_to" {
		t.Fatalf("feedback roundtrip: %#v", decoded)
	}
}

func sampleRuntimeBundle(now time.Time) contracts.RuntimeBundle {
	return contracts.RuntimeBundle{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimeBundle,
		},
		Metadata: contracts.ObjectMeta{
			NodeID:     "node-1",
			Generation: 1,
			IssuedAt:   now,
			ExpiresAt:  now.Add(time.Hour),
		},
		Spec: contracts.RuntimeBundleSpec{
			RuntimePolicyPack: contracts.RuntimePolicyPack{
				TypeMeta: contracts.TypeMeta{
					APIVersion: contracts.RuntimeAPIVersion,
					Kind:       contracts.KindRuntimePolicyPack,
				},
				Metadata: contracts.ObjectMeta{Name: "default-runtime-policy"},
				Spec: contracts.RuntimePolicyPackSpec{
					DefaultEffect: "deny",
					Guardrails: []contracts.RuntimeGuardrail{{
						ID:   "never-auto-block-admins",
						Type: "never",
						Subject: contracts.RuntimeGuardrailSubject{
							Type: "group",
							Ref:  "kernloom-admins",
						},
						ForbiddenActions: []string{"enforce.access.deny"},
						Enforcement: contracts.RuntimeGuardrailEnforcement{
							ViolationBehavior: "reject_action",
							UnknownBehavior:   "reject_hard_action",
						},
					}},
					DetectionRules: []contracts.RuntimeDetectionRule{{
						ID:          "admin-deny",
						Type:        "access.denied_threshold",
						ResourceRef: "ziti-controller",
						Subject: contracts.RuntimeDetectionSubject{
							Type: "group",
							Ref:  "kernloom-admins",
						},
						Threshold: 5,
						Window:    contracts.NewDuration(15 * time.Minute),
						Scope:     "source",
					}},
					ResponseRules: []contracts.RuntimeResponseRule{{
						ID: "denied-access-alert",
						When: contracts.RuntimeResponseTrigger{
							Detection: "admin-deny",
						},
						Then: []contracts.RuntimeResponseAction{{
							ID:       "notify.alert.emit",
							Route:    "alert-route.security-ops",
							Severity: "medium",
							Dedupe:   contracts.NewDuration(15 * time.Minute),
						}},
					}},
					AlertRoutes: []contracts.RuntimeAlertRoute{{
						ID: "alert-route.security-ops",
						Audience: contracts.RuntimeAlertAudience{
							Type: "group",
							Ref:  "group.kernloom-security-ops",
						},
						Channels: []contracts.RuntimeAlertChannel{{
							Type: "slack",
							Ref:  "channel.security-ops",
						}},
						DefaultSeverity: "medium",
					}},
					Rules: []contracts.RuntimePolicyRule{{
						ID:   "risk-high-rate-limit",
						When: "risk.level in ['high', 'critical']",
						Then: contracts.RuntimeActionSpec{
							Capability: "enforce.traffic.rate_limit",
							Level:      "soft",
							TTL:        contracts.NewDuration(10 * time.Minute),
						},
					}},
				},
			},
			RuntimePDPProfile: contracts.RuntimePDPProfile{
				Name: "local-risk-v1",
				Variables: []contracts.RuntimeInput{{
					Name:     "risk",
					Required: true,
					Source:   "localrisk",
				}},
			},
			EnforcementBounds: contracts.EnforcementBounds{
				MaxActionDuringBootstrap: "observe",
				AllowBlock:               false,
			},
		},
	}
}
