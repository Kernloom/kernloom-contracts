// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package contracts

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// RuntimeBundleSigningPayload returns canonical JSON bytes for the unsigned
// RuntimeBundle. Forge signs these bytes; KLIQ verifies these same bytes.
func RuntimeBundleSigningPayload(bundle RuntimeBundle) ([]byte, error) {
	unsigned := struct {
		TypeMeta
		Metadata ObjectMeta        `json:"metadata"`
		Spec     RuntimeBundleSpec `json:"spec"`
	}{
		TypeMeta: bundle.TypeMeta,
		Metadata: bundle.Metadata,
		Spec:     bundle.Spec,
	}
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("runtime bundle signing payload: %w", err)
	}
	return payload, nil
}

func SignRuntimeBundle(bundle RuntimeBundle, keyID string, privateKey ed25519.PrivateKey) (RuntimeBundle, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return RuntimeBundle{}, fmt.Errorf("invalid Ed25519 private key size: got %d want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	payload, err := RuntimeBundleSigningPayload(bundle)
	if err != nil {
		return RuntimeBundle{}, err
	}
	sig := ed25519.Sign(privateKey, payload)
	bundle.Signature = Signature{
		Algorithm: SignatureAlgorithmEd25519,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(sig),
	}
	return bundle, nil
}

func VerifyRuntimeBundle(bundle RuntimeBundle, publicKey ed25519.PublicKey, now time.Time) error {
	if err := ValidateRuntimeBundle(bundle, now); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key size: got %d want %d", len(publicKey), ed25519.PublicKeySize)
	}
	if bundle.Signature.Algorithm != SignatureAlgorithmEd25519 {
		return fmt.Errorf("runtime bundle signature algorithm %q is not supported", bundle.Signature.Algorithm)
	}
	if bundle.Signature.Value == "" {
		return fmt.Errorf("runtime bundle signature value is required")
	}
	sig, err := base64.StdEncoding.DecodeString(bundle.Signature.Value)
	if err != nil {
		return fmt.Errorf("decode runtime bundle signature: %w", err)
	}
	payload, err := RuntimeBundleSigningPayload(bundle)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return fmt.Errorf("runtime bundle signature verification failed")
	}
	return nil
}

func ValidateRuntimeBundle(bundle RuntimeBundle, now time.Time) error {
	if bundle.APIVersion != RuntimeAPIVersion {
		return fmt.Errorf("runtime bundle apiVersion %q is not supported", bundle.APIVersion)
	}
	if bundle.Kind != KindRuntimeBundle {
		return fmt.Errorf("runtime bundle kind %q is not supported", bundle.Kind)
	}
	if bundle.Metadata.NodeID == "" {
		return fmt.Errorf("runtime bundle metadata.node_id is required")
	}
	if bundle.Metadata.Generation <= 0 {
		return fmt.Errorf("runtime bundle metadata.generation must be > 0")
	}
	if bundle.Metadata.IssuedAt.IsZero() {
		return fmt.Errorf("runtime bundle metadata.issued_at is required")
	}
	if !bundle.Metadata.ExpiresAt.IsZero() && !now.IsZero() && !now.Before(bundle.Metadata.ExpiresAt) {
		return fmt.Errorf("runtime bundle generation %d expired at %s", bundle.Metadata.Generation, bundle.Metadata.ExpiresAt.Format(time.RFC3339))
	}
	if bundle.Spec.RuntimePolicyPack.Kind != KindRuntimePolicyPack {
		return fmt.Errorf("runtime bundle spec.runtime_policy_pack.kind must be %q", KindRuntimePolicyPack)
	}
	return nil
}
