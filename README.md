# Kernloom Contracts

Wire-level schemas shared by Kernloom Forge and KLIQ.

This module contains data contracts only:

- RuntimeBundle and RuntimePolicyPack
- LocalRiskAssessment
- RuntimeDecision
- EnforcementReceipt
- RuntimeBundleAck and RuntimeFinding
- Canonical RuntimeBundle signing/verification helpers

The canonical signing payload for RuntimeBundle is deterministic JSON of the
unsigned bundle envelope. Forge signs those bytes with Ed25519; KLIQ verifies
the same bytes.

Module path:

```text
github.com/kernloom/kernloom-contracts
```

## Tests

```sh
go test ./...
```

## Versioning

The current schema version is:

```text
kernloom.io/runtime/v1alpha1
```

Breaking wire changes should add a new API version instead of mutating this one
in place.

