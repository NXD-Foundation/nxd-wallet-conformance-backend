# CS-07 Digital Credentials API Verifier Implementation Plan

Status: planned  
Scope: verifier-side presentation only  
Target profile: WE BUILD CS-07 v0.2, constrained by CS-02 and `docs/knowledge.md`  
Prepared: 17 July 2026

## 1. Normative baseline

Implementation must follow this order of authority:

1. [W3C Digital Credentials Working Draft, 15 July 2026](./rfc/w3c-digital-credentials-WD-20260715.html)
2. [OpenID4VP 1.0](./rfc/openid-4-verifiable-presentations-1_0.html), especially Appendix A
3. [WE BUILD CS-07 v0.2](./core/cs-07-credential-presentation-dc-api-updated.md), especially verifier requirements VP-DC-01 through VP-DC-10
4. [WE BUILD CS-02](./core/cs-02-credential-presentation%20%281%29.md) for the credential query and verification semantics retained by CS-07
5. The project constraints and decisions in [knowledge.md](./knowledge.md)

The W3C snapshot is the exact version cited by CS-07, downloaded from
`https://www.w3.org/TR/2026/WD-digital-credentials-20260715/`. Its SHA-256 is
`0565c849fd99a307aad4b38fac98a71216bee68985f8e1f4f42a4b48519c722b`.
Do not silently replace it with the moving `/TR/digital-credentials/` or
editor's draft. A future profile upgrade must add a new snapshot and record
the behavioral differences.

## 2. Scope and non-goals

This plan adds a browser-mediated OpenID4VP presentation path under
`routes/verify`. It covers same-device and platform-mediated cross-device use
through the same browser API call.

In scope:

- `navigator.credentials.get()` using the `digital` member
- the `openid4vp-v1-signed` protocol
- a compact signed OpenID4VP request in `data.request`
- DCQL and the existing CS-02 credential verification behavior
- encrypted `dc_api.jwt` responses
- origin-bound response proof validation
- wallet protocol errors and browser/API-level failures
- an `openid4vp://` fallback without weakening either profile

Out of scope for this phase:

- DC API issuance and `navigator.credentials.create()`
- unsigned or multi-signed OpenID4VP DC API protocols
- browser extensions, wallet registration, polyfills, or a platform-specific
  cross-device transport
- new credential data models or rulebook validation
- making trust decisions that are currently outside the project trust scope

Existing credential signature, proof, status, structure, DCQL, and replay
checks remain mandatory. The new transport must not bypass or duplicate them.

## 3. Required wire contract

The verifier page invokes the browser only from a user-activation handler and
only in a secure context:

```javascript
const credential = await navigator.credentials.get({
  digital: {
    requests: [{
      protocol: "openid4vp-v1-signed",
      data: { request: signedRequestJwt }
    }]
  }
});
```

The signed request payload must be created from a DC-API-specific allowlist. It
must contain at least:

- `client_id`
- `response_type: "vp_token"`
- `response_mode: "dc_api.jwt"`
- a fresh `nonce`
- a non-empty `expected_origins` containing the exact calling origin
- `dcql_query`
- the applicable verifier metadata, including response-encryption material
- bounded `iat` and `exp` values required by the WE BUILD request-signing profile

It may contain applicable `transaction_data` and client-identifier-prefix
parameters. It must not inherit redirect-transport fields accidentally.
Specifically, response correlation must not rely on `state`, and response
delivery must not rely on `response_uri`. The browser returns the response to
the calling JavaScript promise.

The successful browser value must have this outer shape:

```json
{
  "protocol": "openid4vp-v1-signed",
  "data": { "response": "<compact JWE>" }
}
```

A wallet protocol error is a fulfilled promise whose `data` contains `error`.
It is distinct from a rejected promise such as `NotAllowedError`,
`AbortError`, or `SecurityError`.

## 4. Target architecture and routes

Add `routes/verify/dcApiRoutes.js` and mount it in `server.js`. Keep browser
transport normalization in this router and credential verification in shared
services.

Proposed endpoints:

| Method and path | Responsibility |
| --- | --- |
| `GET /vp/dc-api` | Serve a minimal verifier page with an explicit user-action button, feature/protocol detection, status display, and fallback link |
| `POST /vp/dc-api/request` | Create a single-use presentation session and return the signed request plus the exact DC API request descriptor |
| `POST /vp/dc-api/response/:sessionId` | Accept the serialized `DigitalCredential`, normalize `data`, record protocol/API errors, and invoke shared response verification |
| `GET /vp/dc-api/session/:sessionId` | Return the existing sanitized pending/success/failure status model for the page and test harness |

The request endpoint response should be explicit and frontend-independent:

```json
{
  "sessionId": "...",
  "protocol": "openid4vp-v1-signed",
  "request": {
    "protocol": "openid4vp-v1-signed",
    "data": { "request": "<signed JAR>" }
  },
  "fallback": { "deepLink": "openid4vp://present?..." }
}
```

Do not put the session identifier into the OpenID4VP response as `state`.
Correlation between the browser page and backend uses the locally retained
session identifier and the response endpoint URL; cryptographic replay
protection uses the request nonce and the existing single-use session policy.

## 5. Implementation phases

### Phase 1 — Profile configuration and request builder

1. Add a small `utils/cs07DcApi.js` module with constants and pure validation:
   protocol identifier, required response mode, canonical origin parsing,
   request descriptor construction, and response-envelope normalization.
2. Add `DC_API_VERIFIER_ORIGIN`, defaulting only to the origin component of
   `CONFIG.SERVER_URL`. Reject paths, credentials, fragments, opaque origins,
   and non-HTTPS origins outside an explicitly documented local-development
   mode. Do not derive security-sensitive origin data from untrusted `Host` or
   forwarded headers.
3. Refactor `buildVpRequestJWT` or add a dedicated wrapper so DC API requests
   use an explicit payload allowlist. Remove the hard-coded
   `https://dss.aegean.gr` origin.
4. Set `expected_origins` to the configured calling origin, set
   `response_mode` to `dc_api.jwt`, and omit redirect-only `state` and
   `response_uri` from this profile.
5. Preserve CS-02 DCQL, JAR signing, certificate-chain, encryption-metadata,
   transaction-data, timestamp, and nonce policies. Do not use the current
   generic `dc_api` option for the CS-07 conformance route.
6. Store the following immutable session facts: transport profile `dc_api`,
   protocol, verifier origin, expected proof audience, nonce, DCQL query,
   encryption key identifier, request expiry, and pending status.
7. Return the browser descriptor directly; do not make a QR code or deep link
   the primary result. Generate fallback data through the existing CS-02 path
   as a separate object/session so its response mode and correlation rules do
   not leak into the DC API session.

Acceptance criteria:

- decoding the returned compact JWS shows `dc_api.jwt`, the configured origin,
  DCQL, fresh nonce, and no redirect delivery dependency
- the protected header and signature satisfy the existing CS-02 JAR policy
- a missing/invalid origin or encryption configuration fails before a session
  is exposed

### Phase 2 — Browser verifier adapter

1. Add a small browser module, served by the verifier route, that checks:
   `window.isSecureContext`, `typeof DigitalCredential !== "undefined"`, and
   `DigitalCredential.userAgentAllowsProtocol("openid4vp-v1-signed")`.
2. Prefetch a short-lived request descriptor and enable the presentation
   button only when it is ready. In the button handler, call
   `navigator.credentials.get()` before any awaited operation so transient
   activation cannot expire while waiting on the network. Refresh an expired
   descriptor before re-enabling the button. Never invoke the DC API from a
   timer, page-load handler, or polling callback.
3. Validate the returned object is serializable and preserve only `protocol`
   and `data` when posting to the backend. Never log the JWE or presented
   credential content in browser diagnostics.
4. Handle a fulfilled `data.error` as a wallet protocol result and send it to
   the response endpoint. Handle rejected promises separately with stable UI
   categories for cancellation, permission/user-activation failure, abort,
   security failure, unsupported API/protocol, and unknown platform failure.
5. Supply an `AbortController` for explicit user cancellation and prevent a
   second request while one is active.
6. Set verifier-page headers deliberately: a restrictive CSP, no credential
   data caching, no framing by default, and a self-only
   `Permissions-Policy` for `digital-credentials-get`. If embedding is added
   later, make the permitted origin an explicit deployment decision.
7. Offer the existing CS-02 custom-scheme/cross-device fallback only when DC
   API or the protocol is unavailable. Do not automatically fall back after a
   wallet protocol error or user cancellation, which could bypass user intent.

Acceptance criteria:

- no DC API invocation occurs on page load
- the call is made from the button activation in a secure context
- unsupported browsers show the explicit fallback
- wallet errors and rejected promises produce distinguishable terminal states

### Phase 3 — Response transport normalization

1. Require outer `protocol` to equal `openid4vp-v1-signed`; reject unknown,
   unsigned, multi-signed, and ISO protocol envelopes on this route.
2. Apply body size/depth limits and require `data` to be a plain JSON object.
   Reject duplicate/ambiguous response members and unexpected success/error
   mixtures.
3. When `data.error` is present, validate it as an OpenID4VP protocol error,
   mark the session failed once, retain a sanitized description, and do not
   attempt credential verification.
4. For success require exactly one non-empty compact JWE in `data.response`.
   Reuse the existing OpenID4VP encrypted-response decryption primitive, but
   move it out of the mdoc-specific branch into a format-neutral service.
5. Parse the decrypted plaintext strictly as the top-level Authorization
   Response object. Require a `vp_token` object keyed by the DCQL credential
   query identifiers and reject keys/cardinalities not allowed by the stored
   query.
6. Pass normalized presentations into the existing SD-JWT VC and mdoc
   verification paths. Keep data-model/rulebook and trust decisions at their
   currently documented scope; all structural and cryptographic checks still
   run.
7. Enforce pending, unexpired, single-use sessions and make all terminal
   outcomes idempotent for status reads but non-reprocessable for submissions.

Acceptance criteria:

- browser envelopes cannot enter `/direct_post/:id` by shape coincidence
- malformed envelopes and JWE/plaintext failures produce stable 4xx protocol
  errors without exposing keys, tokens, or decrypted claims
- SD-JWT VC and mdoc use the same transport normalization and their existing
  format-specific verification

### Phase 4 — Origin-bound proof verification

1. Compute and store the expected proof audience as
   `origin:<canonical-verifier-origin>` for the DC API session.
2. Parameterize `validateCs02KeyBindingJwtClaims` and any response-JWT proof
   helper to accept an explicit expected audience instead of assuming
   `vpSession.client_id`.
3. Update all duplicate audience checks in `verifierRoutes.js` to call the
   shared helper. For redirect transports, continue using `client_id`; for DC
   API, use the stored origin audience.
4. Apply the same transport-aware audience rule to every supported proof or
   credential-format binding that carries an audience, including SD-JWT
   KB-JWT and applicable mdoc device-authentication/session-transcript input.
5. Continue validating nonce, signature, holder-key continuity, `sd_hash`,
   transaction-data hashes, DCQL matching, status, and replay markers.
6. Add a migration guard: an old session lacking a recorded transport/origin
   must not be interpreted as a DC API session.

Acceptance criteria:

- `aud=origin:<origin>` succeeds only for the matching DC API session
- `aud=<client_id>`, a different origin, missing `aud`, and origin spelling or
  port variations fail
- existing redirect-based CS-02 audience tests remain unchanged and green

### Phase 5 — Tests and conformance evidence

Add focused tests rather than expanding the already large route test file:

- `tests/cs07DcApiRequest.test.js`: origin canonicalization, descriptor shape,
  JAR claims/header/signature, required `dc_api.jwt`, no redirect-only fields,
  session facts, and invalid configuration
- `tests/cs07DcApiResponse.test.js`: outer protocol/data validation, protocol
  errors, JWE normalization, DCQL response shape, session expiry/single use,
  and sanitized failures
- `tests/cs07OriginBinding.test.js`: positive and negative audience cases for
  SD-JWT and supported mdoc bindings, plus redirect-mode regression tests
- `tests/cs07BrowserAdapter.test.js`: feature detection, protocol detection,
  user-activation wiring, API rejection mapping, abort, double-click guard,
  protocol-error posting, and fallback behavior using browser API stubs
- `tests/cs07SuccessfulFlow.test.js`: request to encrypted response to verified
  claims for at least one SD-JWT VC; add an mdoc structural flow without
  introducing new rulebook requirements

Add `npm run test:cs07` and keep `npm run test:cs02` green. Where a real browser
with a virtual wallet is available, add a separately runnable WebDriver/BiDi
smoke test based on the W3C draft's `digitalCredentials` automation module.
Do not make the core CI suite depend on a browser feature that the build agent
does not expose.

Maintain a requirement evidence table in this document or a companion matrix:

| Requirement | Primary evidence expected |
| --- | --- |
| VP-DC-01 | browser adapter invocation test |
| VP-DC-02 | request descriptor and signed-JAR test |
| VP-DC-03 | CS-02 request/verification regression suite |
| VP-DC-04 | feature/protocol fallback test |
| VP-DC-05 | secure-context and user-activation adapter test/config check |
| VP-DC-06 | transport-neutral invocation; no platform transport assumptions |
| VP-DC-07 | decoded request claim test |
| VP-DC-08 | configured-origin and invalid-origin tests |
| VP-DC-09 | origin audience verification tests across supported formats |
| VP-DC-10 | fulfilled protocol error versus rejected promise tests |

### Phase 6 — Documentation and operational readiness

1. Document configuration, HTTPS requirements, proxy/origin assumptions,
   browser support limitations, permissions policy, and the fallback policy.
2. Add an operator-facing startup/config validation that reports whether the
   DC API verifier route is safely enabled without printing key material.
3. Add structured, redacted events for request creation, browser outcome
   category, response normalization, verification outcome, and session replay.
   Do not log signed requests, JWEs, VP tokens, disclosures, or claims.
4. Update `docs/knowledge.md` from planned to current behavior only after the
   relevant phases and tests land.
5. Update the VP implementation matrix and the FAFC report after implementation
   so claims distinguish browser transport support, cryptographic enforcement,
   structural trust checks, and intentionally deferred trust/data-model work.

## 6. Current implementation findings

The existing code is useful groundwork but is not CS-07 verifier support yet:

- `routes/verify/vpStandardRoutes.js` accepts `dc_api`/`dc_api.jwt`, but returns
  QR/deep-link output rather than a browser `DigitalCredential` request.
- `utils/cryptoUtils.js` signs DC API-labeled requests and adds
  `expected_origins`, but the origin is hard-coded and the generic payload also
  carries `state`, `response_uri`, and a fixed request audience.
- `/direct_post/:id` contains a `dc_api.jwt` branch, but a DC API result is
  delivered to JavaScript, not posted by the wallet to `response_uri`.
- that branch assumes an mdoc-shaped presentation instead of normalizing the
  Authorization Response and dispatching by the stored DCQL query.
- shared and inline proof checks currently compare audience to verifier
  `client_id`; CS-07 requires `origin:<verifier-origin>` for DC API responses.
- there is no verifier browser page/adapter implementing feature detection,
  transient user activation, API rejection handling, or the `data.error`
  fulfilled-promise distinction.

Implementation should therefore reuse the request signing, Redis session,
JWE, DCQL, credential verification, logging, and fallback building blocks, but
must introduce a first-class DC API transport boundary rather than extending
the existing redirect handler with more shape heuristics.

## 7. Definition of done

Verifier-side CS-07 support is complete when all VP-DC-01 through VP-DC-10
have executable evidence, the happy path works through a real or standards-
based virtual wallet, the CS-02 regression suite remains green, and the
documentation accurately identifies any browser-dependent or structurally
tested limitation. Trust-list decisions and credential data-model rulebook
validation remain deferred and must not be represented as implemented.
