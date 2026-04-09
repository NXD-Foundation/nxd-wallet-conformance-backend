# RFC Issuer / Verifier Implementation Backlog

## Goal

This backlog translates the gap analysis into concrete implementation and test work for `/home/ni/code/js/rfc-issuer-v1`.

Priority levels:

- P1: strong spec/conformance value, likely worth doing first
- P2: important but not immediate
- P3: useful hardening or completeness work

## P1 Backlog

### 1. Reject access tokens in query parameters on issuance endpoints

**Why**

The OIDF suite includes an explicit negative test for access tokens sent in the query string. This is currently not clearly enforced.

**Suggested implementation**

- In `routes/issue/sharedIssuanceFlows.js`:
  - reject `req.query.access_token` on `/credential`
  - reject `req.query.access_token` on `/credential_deferred`
  - return a clear OAuth-style error

**Suggested tests**

- Add a negative test in `tests/sharedIssuanceFlows.test.js`:
  - `/credential?access_token=...` must fail
  - `/credential_deferred?access_token=...` must fail

**Acceptance criteria**

- Access token is only accepted through the intended header/mechanism
- Query-parameter token use is rejected deterministically

### 2. Add signed metadata support

**Why**

The OIDF issuer test plan includes explicit signed metadata testing. The current metadata router only returns JSON.

**Suggested implementation**

- In `routes/metadataroutes.js`:
  - support an alternative signed metadata response mode for credential issuer metadata
  - support signed OAuth metadata if you want broader parity
  - use JOSE signing with the repo’s configured issuer signing key
  - set `Content-Type: application/jwt`

**Suggested tests**

- Add tests in `tests/metadataDiscovery.test.js` or a new `tests/signedMetadata.test.js`:
  - request signed issuer metadata
  - verify `application/jwt`
  - decode and verify payload semantics
  - verify signature with published JWKS

**Acceptance criteria**

- Signed metadata can be requested and verified
- Unsigned JSON metadata remains supported where needed

### 3. Verify outer `direct_post.jwt` cryptography strictly

**Why**

The current verifier flow appears to decrypt/process JWT responses but may not fully verify the outer response JWT signature in all cases. This is both a conformance and security issue.

**Suggested implementation**

- In `routes/verify/verifierRoutes.js`:
  - ensure outer JWT signature validation always happens before claims are trusted
  - if JWE is used, decrypt first, then verify the nested signed object as required
  - fail closed on unsupported/invalid signature states

**Suggested tests**

- Extend `tests/verifierRoutesDirectPostJwt.test.js`:
  - invalid outer signature must fail
  - corrupted signed JWT inside decrypted response must fail
  - valid signed response must still succeed

**Acceptance criteria**

- No `direct_post.jwt` success path bypasses cryptographic verification of the response object actually being consumed

### 4. Make standardized VP flow consistently Final/DCQL-only

**Why**

The codebase currently mixes Final/DCQL behavior with legacy `presentation_definition` loading in the standardized verifier route path.

**Suggested implementation**

- In `routes/verify/vpStandardRoutes.js`:
  - decide whether this endpoint is Final-only or mixed-mode
  - if Final-only, remove or fence off PEX/presentation-definition-based generation
  - normalize request-generation behavior so it matches `utils/cryptoUtils.js`

**Suggested tests**

- Add route-level tests ensuring:
  - Final/DCQL profile emits `dcql_query`
  - Final/DCQL profile does not emit `presentation_definition`
  - unsupported legacy combinations fail clearly

**Acceptance criteria**

- The standardized VP endpoint has one unambiguous semantic contract

## P2 Backlog

### 5. Add compressed encrypted credential-response test coverage

**Why**

The implementation supports compression via `credential_response_encryption.zip = DEF`, but this is not explicitly tested end-to-end.

**Suggested implementation**

- No major code change may be needed if runtime already works

**Suggested tests**

- Add to `tests/sharedIssuanceFlows.test.js`:
  - successful credential response encryption with `zip: "DEF"`
  - client can decrypt and inspect payload
  - unsupported `zip` is rejected as `invalid_encryption_parameters`

**Acceptance criteria**

- Compression support is regression-safe

### 6. Add explicit “skip notification” conformance regression

**Why**

OIDF treats “wallet never calls notification” as a valid scenario. That should be pinned by a regression test.

**Suggested tests**

- Add a test showing a full issuance flow completes successfully without calling `/notification`
- Confirm no later state transition incorrectly depends on notification arrival

**Acceptance criteria**

- Notification remains optional from the wallet side

### 7. Strengthen notification endpoint validation

**Why**

OIDF wallet-side logic validates notification request shape more strictly than the current repo tests.

**Suggested implementation**

- In `routes/issue/sharedIssuanceFlows.js`:
  - validate allowed fields strictly
  - reject unknown fields if you want stricter conformance behavior
  - validate `event` values against supported semantics

**Suggested tests**

- Add negative tests for:
  - missing `notification_id`
  - unknown `notification_id`
  - malformed body
  - unknown extra fields
  - invalid `event`

**Acceptance criteria**

- Notification endpoint behavior is deterministic and spec-shaped

### 8. Add explicit multi-client sequential issuance regression

**Why**

OIDF includes a happy-flow using multiple clients. Your code supports multiple schemes, but not an obvious sequential multi-client conformance scenario.

**Suggested tests**

- Add one test that runs two sequential clients against the same issuer:
  - different client identifiers / client-id schemes
  - each gets valid token + credential
  - state/nonces/sessions do not bleed between clients

**Acceptance criteria**

- Multi-client isolation is explicitly protected

## P3 Backlog

### 9. Centralize metadata validation expectations

**Why**

Metadata requirements are already tested extensively, but in a very distributed way.

**Suggested implementation**

- Create a small validation helper for issuer metadata and OAuth metadata
- Reuse it across tests

**Suggested tests**

- Consolidate a smaller number of high-signal metadata semantic tests around the helper

**Acceptance criteria**

- Easier maintenance and clearer spec mapping

### 10. Tighten DCQL unknown-property and structural enforcement

**Why**

The OIDF suite validates DCQL schema and warns on unknown properties. Your repo currently appears permissive in some cases.

**Suggested implementation**

- In `routes/verify/verifierRoutes.js` and/or `utils/cryptoUtils.js`:
  - decide which unknown or structurally inconsistent conditions should be fatal
  - enforce stricter checks around expected credential IDs and object shape

**Suggested tests**

- Add negative tests for:
  - unknown credential IDs
  - missing requested credential IDs
  - malformed DCQL query object

**Acceptance criteria**

- DCQL handling is strict and predictable

### 11. Add emitted client metadata / JWK hygiene tests

**Why**

OIDF ID3 verifier checks cover client metadata and public-only JWK quality more explicitly than your current route tests.

**Suggested tests**

- Add tests ensuring generated `client_metadata.jwks`:
  - do not contain private parameters
  - do not contain symmetric keys
  - contain expected key IDs where required
  - match the client identification scheme

**Acceptance criteria**

- Emitted verifier metadata is explicitly safe and spec-clean

### 12. Consider additional operational/TLS conformance checks

**Why**

OIDF’s additional issuer requests include TLS/header behavior checks. These are not the highest-value semantic gaps, but they can matter if certification alignment is the target.

**Suggested work**

- Decide whether these checks belong in application tests, deployment tests, or infra validation

**Acceptance criteria**

- There is an explicit decision, not just an accidental omission

## Suggested Execution Order

1. Access-token-in-query rejection
2. Outer `direct_post.jwt` verification
3. Final/DCQL-only VP route normalization
4. Signed metadata support
5. Compression test coverage
6. Notification validation and skip-notification regression
7. Multi-client regression
8. DCQL strictness and metadata hygiene hardening

## Suggested Deliverables

For each backlog item, aim to land:

- implementation change
- one or more regression tests
- a short note in the relevant docs if external behavior changes

## Minimal First Milestone

If you want a compact first milestone with the best conformance payoff, do these four:

1. Reject access tokens in query on issuance endpoints
2. Verify outer `direct_post.jwt` cryptography
3. Normalize standardized VP route to DCQL-only Final semantics
4. Add signed metadata support
