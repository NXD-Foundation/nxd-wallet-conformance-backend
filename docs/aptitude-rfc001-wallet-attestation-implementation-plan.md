# APTITUDE RFC001 Wallet Attestation Implementation Plan

This note defines the implementation plan for aligning the `wallet-client` on the `aptitude` branch with:

- APTITUDE RFC-01 Credential Issuance Profile
- OpenID4VCI 1.0
- OpenID4VC High Assurance Interoperability Profile 1.0
- ETSI TS 119 472-3 V1.1.1

The plan is limited to the wallet attestation and credential-binding parts of the issuance flow.

## Target Model

The target interoperability shape is:

- `PAR` and `Token`:
  - one Wallet Instance Attestation (`WIA`) based client authentication mechanism
  - proof of possession of the key referenced in the `WIA.cnf` claim
  - no parallel OAuth body `client_assertion`
- `Credential`:
  - Wallet Unit Attestation (`WUA`) based binding proof
  - either:
    - `proofs.jwt` with `key_attestation`
    - or `proofs.attestation`

This is the model described by APTITUDE RFC001:

- `WIA` at `PAR` and `Token`
- `WUA` at `Credential`

## Current Implementation Summary

The current `aptitude` implementation already has the right high-level split:

- OAuth client attestation material for `PAR` and `Token`
- `WUA` for `Credential` binding
- `proofs.jwt` and `proofs.attestation` support
- `DPoP` for sender-constrained tokens

However, it still mixes attestation modes at `PAR` and `Token`.

### Current `PAR` / `Token` Behavior

Current helper:

- [wallet-client/src/lib/walletProviderIdentity.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/walletProviderIdentity.js)

Current request assembly:

- [wallet-client/src/server.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/server.js)
- [wallet-client/src/lib/issuance.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/issuance.js)

Current behavior:

1. Build OAuth client attestation headers:
  - `OAuth-Client-Attestation`
  - `OAuth-Client-Attestation-PoP`
2. Also derive a body `client_assertion`
3. Send both in the same `PAR` / `Token` exchange

That means the current wallet is using a mixed mode:

- header-based attestation
- plus body `client_assertion`

This is not the clean RFC001 target shape.

### Current `Credential` Behavior

Current helper:

- [wallet-client/src/lib/credentialRequestProofs.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/credentialRequestProofs.js)

Current behavior:

- `proofs.jwt` sends a proof JWT and places `WUA` in `key_attestation`
- `proofs.attestation` sends `WUA` directly

This part is already structurally close to RFC001.

## Normative Alignment Summary

The relevant profile reading is:

- OpenID4VCI 1.0 allows wallet attestation ecosystems and supports:
  - `proofs.jwt`
  - `proofs.attestation`
  - `scope` or `authorization_details`
- HAIP 1.0 requires Wallet Attestation at OAuth endpoints that support client authentication
- ETSI TS 119 472-3 requires:
  - `WIA` at `PAR`
  - `WIA` at `Token`
  - proof of possession for the key in `WIA.cnf`
  - `WUA` at `Credential`

For this implementation plan, the key consequence is:

- `PAR` and `Token` should use one `WIA`-based mechanism only
- `Credential` should use `WUA`-based binding proof only

## Plan Overview

The implementation should be delivered in six phases.

## Phase 1: Normalize Terminology and Internal Roles

Goal:

- make the code reflect the RFC001 mental model directly

Required code changes:

- treat the `PAR` / `Token` attestation object as `WIA`
- treat the `Credential` attestation object as `WUA`
- stop using helper names and comments that blur:
  - OAuth client attestation
  - `WIA`
  - `WUA`
  - body `client_assertion`

Current files to update:

- [wallet-client/src/lib/walletProviderIdentity.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/walletProviderIdentity.js)
- [wallet-client/src/lib/crypto.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/crypto.js)
- [wallet-client/src/lib/credentialRequestProofs.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/credentialRequestProofs.js)
- [wallet-client/src/server.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/server.js)

Acceptance criteria:

- code comments and function names clearly separate:
  - `WIA` for `PAR` / `Token`
  - `WUA` for `Credential`

## Phase 2: Remove Mixed Attestation Mode at `PAR` and `Token`

Goal:

- enforce one attestation-based client authentication mechanism at `PAR` / `Token`

Required code changes:

- stop sending OAuth body `client_assertion`
- stop sending `client_assertion_type`
- keep only:
  - `OAuth-Client-Attestation`
  - `OAuth-Client-Attestation-PoP`

Current files to update:

- [wallet-client/src/lib/walletProviderIdentity.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/walletProviderIdentity.js)
- [wallet-client/src/lib/issuance.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/issuance.js)
- [wallet-client/src/server.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/server.js)
- [wallet-client/src/index.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/index.js)

Implementation details:

- replace `resolveAttestationForEndpoint()` return shape
- return one object focused on:
  - WIA header JWT
  - WIA PoP JWT
  - metadata describing the authenticated wallet identity
- do not expose `clientAssertionJwt` in the primary RFC001 path

Acceptance criteria:

- `PAR` requests no longer contain body `client_assertion`
- `Token` requests no longer contain body `client_assertion`
- request logs no longer show mixed auth construction for the RFC001 path

## Phase 3: Make `WIA` + PoP the Only `PAR` / `Token` Authentication Path

Goal:

- align request construction and retry behavior with RFC001 Section 7.3 / 7.4

Required code changes:

- make `resolveAttestationForEndpoint()` or its replacement produce:
  - `WIA`
  - PoP for `WIA.cnf`
- explicitly validate locally before send:
  - WIA audience matches endpoint
  - PoP audience matches AS issuer
  - `client_id` consistency
- keep attestation refresh / rotation logic, but tie it only to WIA regeneration

Current files to update:

- [wallet-client/src/lib/walletProviderIdentity.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/walletProviderIdentity.js)
- [wallet-client/src/lib/issuance.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/issuance.js)
- [wallet-client/src/server.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/server.js)

Open design point:

- if external pre-minted attestation tokens remain supported, they should also be normalized to:
  - header WIA
  - header PoP
  - no body `client_assertion`

Acceptance criteria:

- one code path exists for WIA-based client authentication
- all `PAR` / `Token` retries regenerate only WIA-related material
- there is no secondary OAuth auth channel in the RFC001 path

## Phase 4: Tighten `client_id`, Subject, and Scope Handling

Goal:

- align request semantics with profile expectations around wallet identity and authorization request construction

Required code changes:

- keep one source of truth for wallet identity used across:
  - `PAR`
  - `Token`
  - WIA subject or profiled client identity
- replace `scope: configurationId` with metadata-driven scope resolution
- keep `authorization_details` support where required

Current files to update:

- [wallet-client/src/server.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/server.js)
- [wallet-client/src/lib/issuance.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/issuance.js)

Why this is in scope:

- OpenID4VCI 1.0 explicitly allows Wallets to derive the correct `scope` from issuer metadata for a selected credential configuration
- the current use of `configurationId` as `scope` is a compatibility shortcut, not the clean profile target

Acceptance criteria:

- `scope` is resolved from offer or issuer metadata
- `client_id` is consistent across `PAR` and `Token`
- wallet identity semantics are explicit and stable

## Phase 5: Preserve and Harden `WUA`-Based Credential Binding

Goal:

- keep the current `Credential` flow but make it explicitly RFC001-aligned

Required code changes:

- preserve both supported proof modes:
  - `proofs.jwt`
  - `proofs.attestation`
- ensure `proofs.jwt` always:
  - contains exactly one JWT proof
  - carries `WUA` in `key_attestation`
  - is signed with the private key corresponding to the first `attested_keys` element
- ensure `proofs.attestation` always:
  - contains exactly one `WUA`

Current files to update:

- [wallet-client/src/lib/credentialRequestProofs.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/credentialRequestProofs.js)
- [wallet-client/src/lib/walletProviderIdentity.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/walletProviderIdentity.js)
- [wallet-client/src/lib/crypto.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/crypto.js)

Additional hardening:

- validate locally that `WUA.attested_keys[0]` matches the proof signing key in `proofs.jwt`
- validate locally that multi-key issuance inputs remain ordered and stable

Acceptance criteria:

- credential proof generation remains functionally equivalent
- proof binding rules are explicit and locally checked before request dispatch

## Phase 6: Split Request-Shape Conformance from Trust-Framework Integration (out of scope for now)

Goal:

- separate protocol conformance from trust-material completeness

Required code changes:

- define two explicit implementation levels:
  - `request-shape conformant`
  - `trust-framework integrated`
- keep current local/external attestation material support only as an implementation source
- document that full RFC001 / ETSI trust validation ultimately depends on:
  - trusted Wallet Provider public key material
  - trusted list validation by the Issuer

Current files to update:

- [wallet-client/src/lib/walletProviderIdentity.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/walletProviderIdentity.js)
- [wallet-client/README.md](/home/ni/code/js/rfc-issuer-v1/wallet-client/README.md)
- a dedicated implementation note for RFC001 attestation alignment

Important distinction:

- the wallet can become request-shape conformant before ecosystem trust integration is complete
- that means:
  - correct WIA placement
  - correct PoP placement
  - correct WUA placement
  - no mixed OAuth auth channels
- but it does not yet mean:
  - trusted-list-backed production interoperability is complete

Acceptance criteria:

- docs and code clearly distinguish request-shape conformance from trust integration

## Recommended Delivery Order

The lowest-risk order is:

1. Phase 1: terminology cleanup
2. Phase 2: remove body `client_assertion`
3. Phase 3: normalize WIA + PoP helper path
4. Phase 4: scope and identity cleanup
5. Phase 5: harden WUA credential proof path
6. Phase 6: document trust-framework gap explicitly

## Test Plan

The minimum test additions or updates should cover:

### `PAR` / `Token`

- `PAR` request contains:
  - `OAuth-Client-Attestation`
  - `OAuth-Client-Attestation-PoP`
  - no body `client_assertion`
- `Token` request contains:
  - `OAuth-Client-Attestation`
  - `OAuth-Client-Attestation-PoP`
  - no body `client_assertion`
- retry after expired or rejected WIA refreshes only WIA material

### `Credential`

- `proofs.jwt` contains:
  - one JWT proof
  - `key_attestation`
  - proof key matches first `attested_keys` element
- `proofs.attestation` contains:
  - one WUA
- multi-key issuance preserves attested-key ordering

### Metadata and request construction

- `scope` is derived from offer or issuer metadata
- `client_id` stays consistent across `PAR` and `Token`
- authorization-code flow still uses PAR
- pre-authorized flow still uses sender-constrained token handling and credential proofing

## Definition of Done

The `wallet-client` can be considered aligned on this topic when:

- `PAR` uses one WIA-based client authentication mechanism with PoP
- `Token` uses one WIA-based client authentication mechanism with PoP
- neither `PAR` nor `Token` sends parallel OAuth body `client_assertion`
- `Credential` uses `WUA` through:
  - `proofs.jwt` with `key_attestation`, or
  - `proofs.attestation`
- `scope` resolution is metadata-driven
- `client_id` handling is consistent and explicit
- the implementation clearly distinguishes:
  - request-shape conformance
  - trust-framework completeness

## Sources

- APTITUDE RFC-01 Credential Issuance Profile v0.1 (Draft)
- OpenID4VCI 1.0: [https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- OpenID4VC HAIP 1.0: [https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- ETSI TS 119 472-3 V1.1.1: [https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf)

