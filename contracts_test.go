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
