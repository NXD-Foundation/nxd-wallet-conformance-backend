# RFC001 Issuer Compliance Review

Reviewed against `~/Downloads/RFC001 (1).md` on 2026-04-16.
Validated and extended on 2026-04-16.

Scope of this review:
- Issuer-side behavior only.
- Current implementation only.
- Focus on RFC sections 1-10, with emphasis on normative issuer obligations in Sections 6-8.

## Validation Summary (added 2026-04-16)

All original findings in this report were re-verified against the current code. Every gap listed below has been confirmed with file:line evidence. In addition, the following previously-undocumented issuer-side gaps were found during validation and are captured in new section "Additional Findings Discovered During Validation" and in the revised Backlog.

Validation verdicts for original findings:

| Original finding | Verdict |
| --- | --- |
| PAR not enforced; direct `/authorize` accepted | **Fixed (2026-04-16)** for deployments with `require_pushed_authorization_requests: true` — `GET /authorize` now returns **400** `invalid_request` if `request_uri` is missing or unknown (P0-1). |
| WIA non-blocking at PAR | **Fixed (2026-04-16, P0-7)** — WIA required; **400** `invalid_client` if missing or invalid |
| WIA signature verification stubbed | **Partially fixed (P0-7)** — JWS verified via `jwk` / `x5c` / config JWKS; **no** WP trusted-list lookup (see P0-8) |
| WIA PoP for `cnf` not verified | Confirmed (`utils/routeUtils.js:1794-1814`) |
| `client_id` consistency PAR↔Token not enforced | **Fixed (2026-04-16)** — `authorizationRequestClientId` is set at authorize from PAR/merged request; token exchange enforces match when bound (`updateSessionForAuthorization`, `handleAuthorizationCodeFlow`; P0-2). |
| `redirect_uri` consistency not enforced at Token | **Fixed (2026-04-16)** — token body `redirect_uri` must match `session.requests.redirectUri` when set at authorize; else **400** `invalid_grant` (P0-3). |
| `/credential` does not validate sender-constraint | **Fixed (2026-04-16)** — JWT access tokens with `cnf.jkt` require a valid `DPoP` proof at `/credential` (`ath`, `htu`, `jkt` match; P0-4). |
| `/credential_deferred` only uses `transaction_id` | **Fixed (2026-04-16, P0-5)** — requires `Authorization`, `getSessionFromToken`, `transaction_id` bound to that session, and DPoP when `cnf.jkt`-bound |
| WUA non-blocking at `/credential` | Confirmed (`routes/issue/sharedIssuanceFlows.js:1271-1284`) |
| WUA trust policy stubbed `true`; revocation TODO | Confirmed (`utils/routeUtils.js:1560-1576`, `:1753-1768`) |
| Attestation signer trust stubbed `true` | Confirmed (`utils/keyAttestationProof.js:63-71`) |
| `proofs.jwt` cardinality too loose | Confirmed (`routes/issue/sharedIssuanceFlows.js:376-390`) |
| `key_attestation` not required on `proofs.jwt` | Confirmed (`utils/routeUtils.js:1824-1858`) |
| Multi-key issuance missing; always single credential | Confirmed (`routes/issue/sharedIssuanceFlows.js:762-768`, `utils/keyAttestationProof.js:195-204`) |
| `tx_code` advertised but not enforced at Token | **Fixed (2026-04-16, P0-6)** — when the session has `requireTxCode`, token exchange requires a non-empty `tx_code` (value not verified server-side) |
| `eu-eaa-offer://` not supported | Confirmed (`utils/routeUtils.js:75-79`) |
| `A128GCM` not advertised | Confirmed (`data/issuer-config.json:8-11`) |
| Signed issuer metadata with `x5c` not implemented | Confirmed (`routes/metadataroutes.js:36-73` returns plain JSON) |
| `issuer_info` not implemented | Confirmed (not present anywhere in `data/` or `routes/metadataroutes.js`) |
| OAuth `grant_types_supported` omits pre-auth | Confirmed (`data/oauth-config.json:28`) |
| `proofs.attestation` parser requires exactly one JWT | Confirmed (`utils/keyAttestationProof.js:32-61`) |
| Legacy `proof` rejected; `proofs` required | Confirmed (`routes/issue/sharedIssuanceFlows.js:339-353`) |
| `/nonce` POST returns `c_nonce` | Confirmed (`routes/issue/sharedIssuanceFlows.js:1793-1802`) |

## Additional Findings Discovered During Validation

These issuer-side gaps were not captured in the original report. Most of them are straightforward issuer bugs or omissions that can reasonably be read as non-conformance with OpenID4VCI 1.0, HAIP, and by extension the RFC001 baseline.

### A1. Proof JWT `typ` header is never validated

RFC alignment: OpenID4VCI §8.2 (profiled via RFC §7.5) requires `proofs.jwt` proofs to carry `typ = openid4vci-proof+jwt`. The issuer never checks it.

Evidence: `validateProofJWT()` only checks `alg`:

```443:481:routes/issue/sharedIssuanceFlows.js
const validateProofJWT = (proofJwt, effectiveConfigurationId, sessionId = null) => { ... }
```

Impact: accepts arbitrary-typed JWTs as proofs of possession. This is directly testable by ITB+ and will fail a strict profile check.

### A2. `iss` in proof JWT only enforced for code flow, not pre-authorized

The RFC does not relax proof JWT `iss` rules by flow. Current code only requires `iss` when `flowType === "code"`:

```501:504:routes/issue/sharedIssuanceFlows.js
if (!proofPayload.iss && flowType === "code") {
  throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_ISS}. ...`);
}
```

Impact: pre-authorized issuance accepts proof JWTs with no `iss`.

### A3. Token response does not return `c_nonce`

Both `handleAuthorizationCodeFlow` and `handlePreAuthorizedCodeFlow` return `{ access_token, refresh_token, token_type, expires_in[, authorization_details] }` only.

```611:624:routes/issue/sharedIssuanceFlows.js
const tokenResponse = {
  access_token: ...,
  refresh_token: ...,
  token_type: ...,
  expires_in: ...,
};
```

Wallets that depend on token-response `c_nonce` must call `/nonce` separately. This is tolerable under OID4VCI 1.0, but combined with A4 it weakens nonce binding to the issuance session.

### A4. `/nonce` endpoint has no access token check

Anyone can call `POST /nonce` and get a fresh `c_nonce`. The nonce is not bound to a specific access token or session.

```1793:1802:routes/issue/sharedIssuanceFlows.js
sharedRouter.post("/nonce", async (req, res) => { ... }
```

Impact: a nonce cannot be tied to the authenticated issuance transaction at validation time. This is a real replay-surface relaxation that should be fixed.

### A5. Deferred success response shape does not match immediate response

Immediate issuance returns `{ credentials: [{ credential }], notification_id }` (OID4VCI 1.0 shape), but deferred success returns `{ credential }` only:

```1754:1767:routes/issue/sharedIssuanceFlows.js
const payload = { credential };
...
return res.status(200).json(payload);
```

Impact: wallets that consume the v1.0 shape for immediate issuance cannot reuse the same code path for deferred. This is a clear RFC §7.6 ambiguity vs implementation reality.

### A6. `/credential_deferred` has no `issuance_pending` / `authorization_pending` path

There is no "not ready yet" response. Each call tries full generation and falls through to 500 `server_error` if generation is not possible. The RFC (§6.3, §7.6) expects the wallet to receive pending signals and retry guidance.

**Status: Fixed (2026-04-16).** `/credential_deferred` now returns
`400 issuance_pending` with a retry `interval` while the credential is not yet
ready, and `400 expired_transaction_id` once the session's deferred lifetime
elapses. Readiness is driven by `sessionObject.isCredentialReady` or, by
default, by a poll budget controlled per session via
`deferred_pending_polls_override` and globally via `DEFERRED_PENDING_POLLS`
(defaults to 0 to preserve the prior synchronous-on-poll behavior). Errors
from the deferred generator with `status === 400` are now mapped to
`invalid_credential_request` instead of leaking as `server_error` 500s.
See `routes/issue/sharedIssuanceFlows.js` (`handleDeferredCredentialIssuance`
and the `/credential_deferred` handler) and the new tests in
`tests/sharedIssuanceFlows.test.js` under `POST /credential_deferred`.

### A7. `authorization_details.credential_identifiers` is silently dropped by a JSON.stringify bug

`parsedAuthDetails` is an array, so assigning a named property does not survive JSON serialization:

```619:622:routes/issue/sharedIssuanceFlows.js
if (parsedAuthDetails) {
  parsedAuthDetails.credential_identifiers = [chosenCredentialConfigurationId];
  tokenResponse.authorization_details = parsedAuthDetails;
}
```

Impact: the token response advertised by the issuer does not contain the `credential_identifiers` the RFC-aligned wallet expects to use at the Credential Endpoint.

**Status: Fixed (2026-04-16).** Token responses now set `authorization_details` to a mapped array of plain objects via `buildTokenResponseAuthorizationDetails`, each entry carrying `credential_identifiers: [<credential_configuration_id>]` (with per-entry `credential_configuration_id` or fallback to the first entry’s id). See `routes/issue/sharedIssuanceFlows.js` and the strengthened test in `tests/sharedIssuanceFlows.test.js` (`should handle authorization_details in pre-authorized flow`).

### A8. `authorization_details` handler does not enforce `type = openid_credential`

`fetchVCTorCredentialConfigId()` resolves `credential_configuration_id` / `vct` by heuristics; it does not reject `authorization_details` entries that lack `type: "openid_credential"` (RFC 9396 / OID4VCI §5.1.1).

**Status: Fixed (2026-04-16).** The authorization endpoint rejects non-conformant entries in `fetchVCTorCredentialConfigId` (`routes/issue/codeFlowSdJwtRoutes.js`). The token endpoint’s `parseAuthorizationDetails` (`routes/issue/sharedIssuanceFlows.js`) requires every element to have `type: "openid_credential"` and returns OAuth `invalid_request` on failure. Tests: `tests/sharedIssuanceFlows.test.js` (`MUST return invalid_request when authorization_details omits type openid_credential`).

### A9. PKCE is only required when `authorization_details` is present

`validateAuthorizationRequest()` makes `code_challenge` conditional on `authorization_details`:

```169:186:routes/issue/codeFlowSdJwtRoutes.js
if (authorizationDetails) {
  ...
  if (!code_challenge) { errors.push(...); }
}
```

Under the RFC, PAR-based authorization-code flows SHALL use PKCE with `S256` unconditionally. Scope-based authorization paths currently bypass this.

**Status: Fixed (2026-04-16).** `validateAuthorizationRequest()` in `routes/issue/codeFlowSdJwtRoutes.js` now requires a non-empty `code_challenge` and `code_challenge_method: S256` whenever `response_type` is `code`, independent of `authorization_details`. The same checks run on `POST /par` before a PAR object is stored (`invalid_request` JSON on failure). Optional query `code_challenge` is read without throwing when absent. Tests: `tests/metadataDiscovery.test.js` (PAR reachability body includes PKCE; new `POST /par MUST return invalid_request when code_challenge is missing`).

### A10. `code_challenge_method` is never validated at authorize

There is no explicit rejection of `plain` or missing `code_challenge_method`. Token-time validation always computes `S256`, so `plain` is implicitly unsupported, but the authorize endpoint accepts it silently without returning `invalid_request`.

**Status: Largely addressed by A9 fix (2026-04-16).** Authorize and PAR now require `code_challenge_method: S256` via the shared `validateAuthorizationRequest()` used in both paths.

### A11. DPoP handling is weaker than HAIP / sender-constrained token profile

- When a `DPoP` header is present but lacks `jwk`, the issuer downgrades to a Bearer token instead of returning `invalid_dpop_proof`.

```1047:1055:routes/issue/sharedIssuanceFlows.js
// Header present but missing jwk -> will fall back to Bearer
```

**Status (partial, 2026-04-16):** A `DPoP` header that parses as a JWT but omits `jwk` in the protected header now fails with **`invalid_dpop_proof`** (no Bearer fallback). See `routes/issue/sharedIssuanceFlows.js` token handler and `tests/sharedIssuanceFlows.test.js` (`DPOP-02b`).

- `HAIP_PROFILE_REQUIRE_DPOP_FOR_TOKEN` only forces DPoP for `authorization_code` flow; pre-authorized flow can still issue Bearer even with HAIP enabled.

```1067:1085:routes/issue/sharedIssuanceFlows.js
if (requireDpopForToken && grant_type === "authorization_code") { ... }
```

**Status: Fixed (2026-04-16, reinforced).** The `HAIP_PROFILE_REQUIRE_DPOP_FOR_TOKEN` flag has been **removed**. RFC001 §7.4 mandates sender-constrained access tokens; since this issuer uses DPoP as the sender-constraining mechanism (RFC 9449), DPoP is now **always required** at the token endpoint for both **`authorization_code`** and **`urn:ietf:params:oauth:grant-type:pre-authorized_code`** — there is no more opt-in flag and no `Bearer` fallback. Successful token responses always carry `token_type: "DPoP"` and a `cnf.jkt`-bound access token. Expected-thumbprint (PAR) binding is enforced unconditionally. Tests: `tests/sharedIssuanceFlows.test.js` (`INT-01`, `INT-01a`, `INT-02`, `DPOP-02b`).

- DPoP `htu` check uses the static `SERVER_URL` constant rather than the request-resolved `getServerUrl()`:

```938:939:routes/issue/sharedIssuanceFlows.js
const expectedHtu = `${SERVER_URL}/token_endpoint`;
```

**Status: Fixed (2026-04-16).** Token-endpoint DPoP validation now uses **`getServerUrl()`** for the expected `htu` (aligned with `P3-5` / proxy-aware public URL).

**Note:** **`/credential` DPoP sender-constraint (P0-4)** and **`/credential_deferred` (P0-5)** are fixed (2026-04-16).

### A12. Notification endpoint does not verify that `notification_id` belongs to the access token's session

`/notification` resolves a session from the bearer token, but does not check that the supplied `notification_id` equals the `notification_id` previously stored for that session. Any valid bearer token could therefore be used to post notifications for arbitrary `notification_id` values.

**Status: Fixed (2026-04-16).** After resolving the session from the access token, the handler requires a stored `notification_id` on that session (set when a credential response includes `notification_id`, including deferred issuance). Missing stored id → `400 invalid_notification_request`. Mismatch → `403 invalid_notification_id`. Tests: `tests/sharedIssuanceFlows.test.js` (`POST /notification`).

### A13. `response_types_supported` advertises VP-layer types in OAuth metadata

`data/oauth-config.json:26` advertises `["code", "vp_token", "id_token"]`. For an RFC001 issuer these extra types are not applicable; they confuse wallets and validators consuming the metadata.

### A14. Typo bug in `utils/cryptoUtils.js` JAR token response

```834:836:utils/cryptoUtils.js
if (authorization_details) {
  jwtPayload.authorization_details = authorizatiton_details;
}
```

`authorizatiton_details` (typo) is not defined. If the code path runs with truthy `authorization_details`, it throws a `ReferenceError`.

**Status: Fixed (2026-04-16).** `jwtPayload.authorization_details` is now assigned `authorization_details`. The same typo was corrected in `wallet-client/utils/cryptoUtils.js` (mirrored helper).

### A15. OID4VCI error codes are not consistently used

The outer credential-endpoint catch uses a non-standard `credential_request_denied` code for generic failure:

```1698:1701:routes/issue/sharedIssuanceFlows.js
return res.status(400).json({
  error: "credential_request_denied",
  error_description: error.message,
});
```

Many non-OAuth errors in the token path fall through to `server_error` / HTTP 500 instead of the narrower OID4VCI error set (`invalid_grant`, `invalid_request`, `invalid_proof`, `invalid_nonce`, `unsupported_credential_format`, `invalid_credential_request`). RFC-aligned testing expects specific codes and shapes.

**Status: Partially fixed (2026-04-16).** The `/credential` catch-all that previously returned `credential_request_denied` now returns **`invalid_credential_request`** (`CREDENTIAL_REQUEST_ERROR_CODES.INVALID_CREDENTIAL_REQUEST`), matching OID4VCI 1.0 §8.3. Session `error` fields use the same code. Remaining gap: token-path and other fallbacks still need narrower mapping where applicable (see P1-15).

### A16. `batch_credential_endpoint` usage is inconsistent

`routes/metadataroutes.js:67-68` warns that `batch_credential_endpoint` was removed from spec draft -14, yet `routes/batchRequestRoutes.js` still exists and is mounted. Either remove the custom batch path or align it explicitly with RFC §7 "Batch Credential Requests" language.

**Status: Fixed (2026-04-16).** Aligned with OID4VCI 1.0 / RFC001 (which removed the `batch_credential_endpoint` metadata field in draft-14):

- `routes/metadataroutes.js` no longer merely *warns* about `batch_credential_endpoint`; it now **actively deletes** the key from the outgoing issuer metadata before responding, so stale config in `data/issuer-config.json` can never leak a non-1.0 field back to wallets.
- `routes/batchRequestRoutes.js` was renamed to `routes/multiCredentialOfferRoutes.js` and the router export renamed accordingly in `server.js`. The file's top-of-module comment makes explicit that these endpoints are **credential-offer helpers** (they issue a Credential Offer listing multiple `credential_configuration_ids`) — **not** a separate batch credential endpoint. Multi-credential issuance runs through the standard `POST /credential` endpoint using `proofs.jwt[]` per OID4VCI 1.0 §7 (see P1-12 for full multi-proof coverage).
- The old URL paths (`/offer-no-code-batch`, `/credential-offer-no-code-batch/:id`) are preserved for backwards compatibility with `testCaseRequests.yml` and existing wallet fixtures; only the internal naming changed.
- The historical `rfc-batch-credential-issuance.md` draft that proposed a custom `POST /batch-credential` endpoint now carries a "SUPERSEDED — DO NOT IMPLEMENT AS WRITTEN" banner pointing readers to OID4VCI 1.0 / RFC001.
- Updated test: `tests/metadataDiscovery.test.js` → `MUST NOT include batch_credential_endpoint in V1.0 metadata` now hard-asserts `expect(response.body).to.not.have.property('batch_credential_endpoint')` instead of logging a warning.
- README updated to describe `multiCredentialOfferRoutes.js` and explicitly note that RFC001 removes `batch_credential_endpoint`.

### A17. ETSI format identifiers are not advertised

RFC §5.1 ties X509-AC EAA, JSON-LD VC secured with JOSE, and JSON-LD VC secured with SD-JWT to the format identifiers `x509_attr`, `vc+jwt`, and `vc+sd-jwt`. None of these appear in `data/issuer-config.json`. This is fine only if the issuer does not claim ETSI-aligned support for those formats; otherwise it is a §5.1 / §7.7 gap.

**Status: Fixed (2026-04-16).** The issuer now claims RFC001 ETSI-aligned format support in metadata and implements matching issuance paths:

- **`data/issuer-config.json`** — Added three credential configurations: `ETSIRfc001PidVcSdJwt` (`format`: **`vc+sd-jwt`**), `ETSIRfc001PidVcJwt` (`format`: **`vc+jwt`**), and `ETSIRfc001PidX509Attr` (`format`: **`x509_attr`**), each with `vct`: `urn:eu.europa.ec.eudi:pid:1`. Also extended **`credential_response_encryption.enc_values_supported`** to **`["A128GCM", "A256GCM"]`** per RFC001 ETSI algorithm baseline (§5 intro).
- **`routes/issue/sharedIssuanceFlows.js`** — Maps ETSI **`vc+jwt`** to the existing OID4VCI **`jwt_vc_json`** issuance path; sets **`requestBody.vct`** from **`credConfig.vct` / `doctype`** when present so configuration IDs can differ from the VC type string.
- **`utils/credGenerationUtils.js`** — Handles **`x509_attr`** by issuing a **base64 DER RFC 5755 Attribute Certificate** via **`utils/issueX509AttrCredential.js`** (uses `@peculiar/asn1-x509-attr` + issuer ES256 key). Attribute payload uses a pilot OID-carried JSON claim blob (documented in the module header); full ETSI X509-AC EAA semantics remain pilot-extensible.
- **`tests/metadataDiscovery.test.js`** — Asserts all three ETSI format identifiers appear in at least one published credential configuration.

### A18. `pre-authorized_grant_anonymous_access_supported` is advertised

`data/oauth-config.json:33` sets `pre-authorized_grant_anonymous_access_supported: true`. Combined with the missing `tx_code` enforcement (original finding) and the lack of sender-constrained tokens at `/credential`, the issuer effectively allows anonymous pre-authorized issuance end-to-end. This should be reviewed against the pilot's RFC001 security expectations.

## Executive Summary

The issuer is partially aligned with the RFC baseline. It already implements the major issuance surfaces:
- issuer metadata
- OAuth metadata
- PAR endpoint
- authorization endpoint
- token endpoint
- credential endpoint
- nonce endpoint
- deferred credential endpoint
- notification endpoint
- issuer-initiated offers
- wallet-initiated authorization-code issuance
- pre-authorized issuance

The main compliance problem is not missing surface area. The main problem is that several RFC-required checks are advertised or partially implemented but not actually enforced at runtime.

Highest-impact gaps:
- ~~PAR is advertised as required, but direct `/authorize` requests are still accepted without a valid PAR step.~~ **Addressed (2026-04-16):** when `require_pushed_authorization_requests` is true, `/authorize` requires a valid PAR `request_uri` (JSON **400** on failure).
- ~~WIA validation at PAR and Token is non-blocking~~ **Presence + JWS verification (P0-7, 2026-04-16);** Wallet Provider **trusted-list** policy for `iss` remains **open** (P0-8).
- ~~`/credential` does not validate sender constraint on the access token~~ **Addressed (2026-04-16, P0-4):** DPoP-bound access tokens (`cnf.jkt`) require a valid `DPoP` proof on `/credential`.
- ~~`/credential_deferred` is effectively protected only by `transaction_id`~~ **Addressed (2026-04-16, P0-5):** bearer resolves the issuance session; `transaction_id` must belong to that session; DPoP when the token is sender-constrained.
- ~~Pre-authorized `tx_code` is offered but not enforced at token redemption.~~ **Addressed (2026-04-16, P0-6):** presence-only enforcement when the offer path sets `requireTxCode` on the session.
- ETSI-aligned metadata obligations are not implemented: no signed issuer metadata, no `x5c` protected header for issuer metadata, no `issuer_info`, no `eu-eaa-offer://`.
- Multi-key attestation handling does not satisfy the RFC text that requires issuing as many credentials as there are attested keys.

Overall assessment:
- Core issuance flow support: present
- RFC baseline conformance: partial
- ETSI-aligned profile conformance: not currently achieved

## Section-by-Section Review

### 1. Introduction

Assessment: Informational only.

Implementation status:
- The service clearly targets OpenID4VCI-style issuance and includes both authorization-code and pre-authorized flows.

No issuer-side compliance finding from this section alone.

### 2. Scope

Assessment: Mostly aligned with the intended issuer scope.

Implemented:
- wallet-initiated issuance
- issuer-initiated issuance via credential offers
- authorization-code flow
- pre-authorized code flow
- deferred issuance
- nonce endpoint
- notification endpoint

Notes:
- The repo also includes verifier/presentation logic, which is out of scope for this RFC, but that does not create an issuer compliance issue by itself.

### 3. Normative Language

Assessment: Informational only.

No direct code finding.

### 4. Roles and Components

Assessment: Informational/model section.

Implementation mapping:
- issuer metadata and credential issuance are implemented in [routes/metadataroutes.js](/home/ni/code/js/rfc-issuer-v1/routes/metadataroutes.js:36) and [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:803)
- authorization flow is implemented in [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:560)

### 5. Protocol Overview

Assessment: Partially aligned.

Implemented:
- authorization-code flow
- pre-authorized flow
- issuer-initiated offers
- wallet-initiated issuance
- PAR support
- PKCE checking
- deferred issuance
- `proofs.jwt`
- `proofs.attestation`
- nonce endpoint
- notification endpoint
- credential response encryption

Partially or not aligned:
- Sender-constrained tokens are optional in practice, not enforced across the whole issuance flow.
  Evidence: token endpoint requires DPoP for code/pre-auth grants; `/credential` validates DPoP for JWT access tokens that carry `cnf.jkt` (P0-4) [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js).
- ETSI-specific additions are incomplete:
  - `A128GCM` is not advertised; only `A256GCM` is published in issuer metadata [data/issuer-config.json](/home/ni/code/js/rfc-issuer-v1/data/issuer-config.json:8).
  - signed issuer metadata with `x5c` is not implemented; metadata is returned as plain JSON [routes/metadataroutes.js](/home/ni/code/js/rfc-issuer-v1/routes/metadataroutes.js:42).
  - `issuer_info` is not published in metadata [routes/metadataroutes.js](/home/ni/code/js/rfc-issuer-v1/routes/metadataroutes.js:49).
  - `eu-eaa-offer://` invocation scheme is not supported; only `openid-credential-offer://`, `haip://`, and `openid4vp://` are defined [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:75).

### 6. High-level Flows

#### 6.1 Wallet-initiated Issuance Flow

##### 6.1.1 Configuration and discovery

Assessment: Mostly aligned, with ETSI metadata gaps.

Implemented:
- issuer metadata endpoint [routes/metadataroutes.js](/home/ni/code/js/rfc-issuer-v1/routes/metadataroutes.js:36)
- OAuth metadata endpoint [routes/metadataroutes.js](/home/ni/code/js/rfc-issuer-v1/routes/metadataroutes.js:78)
- credential endpoint, deferred endpoint, nonce endpoint, notification endpoint are published in issuer metadata [routes/metadataroutes.js](/home/ni/code/js/rfc-issuer-v1/routes/metadataroutes.js:49)
- PAR, authorization, token, JWKS are published in OAuth metadata [routes/metadataroutes.js](/home/ni/code/js/rfc-issuer-v1/routes/metadataroutes.js:86)

Missing/wrong:
- ETSI signed issuer metadata not implemented.
- `issuer_info` not implemented.
- OAuth metadata advertises only `authorization_code` in `grant_types_supported`, but runtime also supports pre-authorized token exchange. This is a metadata/runtime mismatch [data/oauth-config.json](/home/ni/code/js/rfc-issuer-v1/data/oauth-config.json:28), [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1096).

##### 6.1.2 User selects credential

Assessment: Broadly aligned.

Implemented:
- wallet can select via scope or `authorization_details` and the issuer resolves requested credential config [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:733).

##### 6.1.3 Pushed Authorisation Request (PAR)

Assessment: PAR surface is implemented; **PAR-first authorization is now enforced** when metadata requires it.

Implemented:
- PAR endpoint exists and returns `request_uri` and `expires_in` [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:94), [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:650)
- OAuth metadata advertises `require_pushed_authorization_requests = true` [data/oauth-config.json](/home/ni/code/js/rfc-issuer-v1/data/oauth-config.json:5)
- **P0-1 (2026-04-16):** `GET /authorize` reads `data/oauth-config.json`; when `require_pushed_authorization_requests` is **true**, a missing or unknown `request_uri` yields **HTTP 400** with `error: invalid_request` and no query-parameter fallback. Valid `request_uri` still merges the PAR payload into the authorization request.

Missing/wrong:
- WIA at PAR is optional in practice, and invalid WIA does not block the request [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:623).
- WIA signature verification against Wallet Provider trust material is not implemented; `validateWIA()` performs only structural and TTL checks and explicitly leaves signature verification as TODO [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1646).
- No proof-of-possession check is performed for the key referenced by WIA `cnf` at PAR.
- ~~No clear runtime check enforces `client_id` consistency between PAR and token redemption.~~ **Addressed (2026-04-16, P0-2):** when authorize persists a non-empty `client_id`, the token endpoint rejects a missing or differing `client_id` with **`invalid_grant`**.

##### 6.1.4 User authorisation

Assessment: Implemented in a simplified issuer-specific way.

Implemented:
- authorization endpoint exists [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:675)
- code redirect is returned on success [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:805)

Missing/wrong:
- ~~Because direct `/authorize` is accepted without PAR, the RFC’s required PAR-first flow is not enforced.~~ **Superseded:** PAR-first behavior is enforced when `require_pushed_authorization_requests` is true (see above).

##### 6.1.5 Token request

Assessment: Partially aligned.

Implemented:
- token endpoint exists [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:803)
- authorization-code flow is supported [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:627)
- PKCE is validated [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:646)
- optional DPoP-bound access tokens are supported [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:903)
- `c_nonce` is returned via the token response path [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:700)

Missing/wrong:
- WIA is optional in practice and invalid WIA does not block issuance [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:841).
- WIA signature/trust validation is not implemented; only basic decode/TTL checks are done [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1591).
- The token path does not verify WIA proof-of-possession for the key in `cnf`.
- **`client_id` and `redirect_uri` consistency** with the authorization request are enforced at the token endpoint when non-empty values were bound at authorize (P0-2, P0-3) [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js).
- ~~Pre-authorized flow does not enforce `tx_code`~~ **P0-6 (2026-04-16):** sessions created for tx-code offers set `requireTxCode`; `/token_endpoint` requires a non-empty `tx_code` (no issuer value check) [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js) (`handlePreAuthorizedCodeFlow`).

##### 6.1.6 Credential request

Assessment: Mixed. Proof syntax validation is strong; token binding and attestation enforcement are weak.

Implemented:
- `/credential` exists [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1212)
- request requires exactly one of `credential_identifier` or `credential_configuration_id` [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:289)
- legacy `proof` is rejected; `proofs` is required [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:339)
- exactly one proof type is required [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:360)
- proof nonce is required and single-use [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1327)
- `proofs.attestation` is parsed as exactly one JWT [utils/keyAttestationProof.js](/home/ni/code/js/rfc-issuer-v1/utils/keyAttestationProof.js:33)
- proof signing algorithm is checked against credential metadata for JWT proofs [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1364)

Missing/wrong:
- ~~Access token validation is incomplete~~ **P0-4 (2026-04-16):** `/credential` verifies DPoP (`ath`, `htu`, `jkt`) when the access token JWT includes `cnf.jkt` [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js). Opaque tokens skip the check (legacy).
- Invalid/missing access token currently yields `server_error` via missing session, not an explicit token validation failure [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1247).
- WUA is treated as optional, and invalid WUA does not block issuance [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1261).
- WUA trust policy is stubbed and revocation/status checking is still TODO [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1740), [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1753).
- `proofs.jwt` does not enforce the RFC requirement that exactly one JWT element be present. The current code accepts a string or a non-empty array and uses only the first element [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:378). That is looser than RFC 7.5.1.
- `proofs.jwt` does not require `key_attestation` in the protected header when using the RFC’s device-bound `proofs.jwt` path. WUA is optional and only conditionally used if present [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1824), [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1261).

##### 6.1.7 Storage

Assessment: Wallet-side only.

No issuer-side compliance finding.

#### 6.2 Issuer-initiated Issuance via Credential Offer

##### 6.2.1 Issuance decision

Assessment: Application/business-process dependent.

No protocol-level issue identified.

##### 6.2.2 Credential Offer creation

Assessment: Implemented.

Implemented:
- credential offers include `credential_issuer`, `credential_configuration_ids`, and grant information [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:827)
- both authorization-code and pre-authorized offers are supported [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:836), [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:841)

Missing/wrong:
- ~~If tx-code is advertised, server-side enforcement is absent at token redemption.~~ **P0-6 (2026-04-16):** presence of `tx_code` is enforced when `requireTxCode` is set on the session.

##### 6.2.3 Credential Offer delivery and Wallet invocation

Assessment: Partially aligned.

Implemented:
- same-device `openid-credential-offer://` support [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:75)
- QR-based delivery is implemented via offer-generation helpers/routes [routes/issue/preAuthSDjwRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/preAuthSDjwRoutes.js:78), [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:468)

Missing/wrong:
- `eu-eaa-offer://` is not implemented for ETSI-aligned same-device invocation [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:75).

##### 6.2.4 Wallet processes the offer

Assessment: Wallet-side.

No issuer-side finding.

##### 6.2.5 Authorization Code Flow variant

Assessment: Present, but same PAR/WIA enforcement gaps apply.

Missing/wrong:
- PAR not enforced
- WIA non-blocking
- no PoP validation for WIA `cnf`

##### 6.2.6 Pre-Authorised Code Flow variant

Assessment: **Updated (2026-04-16, P0-6).** Tx-code offers require a non-empty `tx_code` at `/token_endpoint` when the session was created with `requireTxCode`.

Implemented:
- pre-authorized token exchange supported [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1096)
- `tx_code` presence enforced for those sessions (`handlePreAuthorizedCodeFlow`)

Missing/wrong:
- Issuer does not verify `tx_code` against a stored secret (presence-only policy).

##### 6.2.7 Credential request

Assessment: Same as 6.1.6.

##### 6.2.8 Deferred issuance continuation

Assessment: Surface is present, protection model is insufficient.

Missing/wrong:
- deferred retrieval should be tied to authorization and transaction state, but current implementation only uses `transaction_id` and does not validate an access token [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1712).

#### 6.3 Deferred Credential Request

Assessment: Partially aligned.

Implemented:
- deferred response from `/credential` returns `transaction_id` and polling `interval` [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:772)
- deferred endpoint exists [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1709)

Missing/wrong:
- no bearer/access token validation on deferred retrieval
- no explicit pending status path; the endpoint directly tries to generate and return a credential
- no explicit terminal errors for denied/expired deferred transactions beyond generic `server_error`

### 7. Normative Requirements

#### 7.1 Common requirements

Assessment: Partially aligned.

Met:
- OpenID4VCI-style issuance
- metadata discovery
- wallet-initiated issuance
- issuer-initiated offers
- authorization-code and pre-authorized flow support
- deferred issuance support

Not fully met:
- sender-constrained access tokens are not consistently enforced at credential/deferred endpoints
- ETSI `A128GCM` support missing in metadata
- ETSI `eu-eaa-offer://` missing

#### 7.2 Credential Offer

Assessment: Mostly aligned.

Gap:
- tx-code is advertised but not enforced
- ETSI same-device `eu-eaa-offer://` missing

#### 7.3 Authorisation Endpoint and PAR

Assessment: Not compliant.

Major gaps:
- PAR not required in practice
- direct front-channel `/authorize` not rejected
- WIA not required when RFC profile says it shall be
- WIA signature/trust verification not implemented
- WIA key PoP validation not implemented
- ~~no runtime check for `client_id` consistency between PAR and token~~ **Addressed (P0-2)** when `client_id` was bound at authorize

#### 7.4 Token Endpoint and Wallet Attestation

Assessment: Partially compliant.

Met:
- token endpoint exists
- grant type handling exists
- PKCE validation exists
- optional DPoP support exists

Gaps:
- WIA non-blocking
- WIA cryptographic trust verification missing
- WIA PoP missing
- ~~no `redirect_uri` consistency validation in auth-code exchange~~ **Addressed (P0-3)** when `redirect_uri` was bound at authorize; **`client_id`** (P0-2) same
- tx-code enforcement missing for pre-authorized flow

#### 7.5 Credential Endpoint

Assessment: Partially compliant.

Met:
- endpoint exposed
- credential config validation
- `proofs` model enforced
- nonce and proof validation present
- response can be immediate or deferred

Gaps:
- access token sender constraint not validated
- WUA not enforced when required by selected proof/profile
- WUA trust and revocation policy incomplete
- JWT proof cardinality is too loose

#### 7.5.1 Credential Request using `proofs.jwt`

Assessment: Not fully compliant.

Met:
- JWT proof signature verification
- nonce validation
- proof key vs first WUA attested key check when WUA is supplied and valid [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1869), [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1382)

Gaps:
- RFC requires exactly one element in the `jwt` array; current implementation allows a string or any non-empty array and uses element 0 only [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:378)
- RFC requires `key_attestation` header carrying WUA; current implementation does not require it
- RFC requires WUA signature validation under Wallet Provider trusted list; only partial/stubbed implementation exists
- RFC text requires generating as many credentials as there are attested public keys where applicable; current implementation always returns a single credential [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:765)

#### 7.5.2 Credential Request using `proofs.attestation`

Assessment: Not fully compliant.

Met:
- parser enforces exactly one JWT in `proofs.attestation` [utils/keyAttestationProof.js](/home/ni/code/js/rfc-issuer-v1/utils/keyAttestationProof.js:33)
- attested keys are extracted and used for binding [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1346)

Gaps:
- issuer trust policy for attestation signer is stubbed `true` [utils/keyAttestationProof.js](/home/ni/code/js/rfc-issuer-v1/utils/keyAttestationProof.js:66), [utils/keyAttestationProof.js](/home/ni/code/js/rfc-issuer-v1/utils/keyAttestationProof.js:227)
- multi-key issuance is not implemented; first key only [utils/keyAttestationProof.js](/home/ni/code/js/rfc-issuer-v1/utils/keyAttestationProof.js:196), [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:765)

#### 7.6 Deferred Credential Endpoint

Assessment: Not compliant enough for RFC wording.

Met:
- endpoint exists
- published in metadata

Gaps:
- deferred retrieval token/access token validation missing
- no pending-status behavior
- no explicit terminal error model for denied/expired transactions

#### 7.7 Server Metadata

Assessment: Partially compliant.

Met:
- OAuth metadata published
- issuer metadata published
- credential endpoint and deferred endpoint published
- proof types and configuration data are published

Gaps:
- OAuth metadata says PAR is required, but runtime does not enforce it
- OAuth metadata omits pre-authorized flow in `grant_types_supported` despite runtime support [data/oauth-config.json](/home/ni/code/js/rfc-issuer-v1/data/oauth-config.json:28)
- signed issuer metadata with `x5c` protected header not implemented
- `issuer_info` not implemented
- ETSI `A128GCM` not advertised

### 8. Interface Definitions

#### 8.1 Wallet Invocation Interface

Assessment: Partial.

Met:
- same-device and QR-based mechanisms exist

Gap:
- no `eu-eaa-offer://`

#### 8.2 Credential Offer Interface

Assessment: Largely aligned.

Gap:
- tx-code enforcement absent at runtime.

#### 8.3 PAR Endpoint

Assessment: Exists, but validation is weaker than required.

Gaps:
- no mandatory WIA enforcement
- no WIA PoP enforcement
- no strong PAR-only gating of subsequent authorization requests

#### 8.4 Token Endpoint

Assessment: Exists, but request validation is incomplete.

Gaps:
- ~~missing auth-code `redirect_uri` consistency check~~ **Addressed (P0-3)** when bound at authorize (**`client_id`:** P0-2)
- missing tx-code enforcement
- missing mandatory WIA enforcement where required

#### 8.5 Credential Endpoint

Assessment: Exists and validates proof syntax well.

Gap:
- ~~missing sender-constraint enforcement for access token use at `/credential`~~ **Addressed (P0-4)** for `cnf.jkt`-bound tokens; ~~**`/credential_deferred`**~~ **Addressed (P0-5)** for the same binding at the deferred endpoint

#### 8.6 Nonce Endpoint

Assessment: Implemented and aligned enough.

Implemented:
- `POST /nonce` returns `c_nonce` and `c_nonce_expires_in` [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1793)

#### 8.7 Notification Interface

Assessment: Implemented.

Gap:
- request is bearer-token protected, but again without sender-constrained token enforcement.

#### 8.8 Deferred Credential Endpoint

Assessment: **Updated (2026-04-16, P0-5).** Deferred polling requires the same access token (and DPoP proof when the token is `cnf.jkt`-bound) as `/credential`, and the `transaction_id` must match the session resolved from that token.

#### 8.9 Metadata Endpoints

Assessment: Implemented with ETSI-profile gaps.

Gaps:
- no signed metadata JWS with `x5c`
- no `issuer_info`

### 9. Conformance

Assessment: The service is not yet conformant as an issuer against the full RFC text.

Reason:
- several SHALL-level checks are either omitted or downgraded to optional/non-blocking behavior.

### 10. Conformance Check Catalogue and Deployed Test Matrix

Assessment: The current implementation can likely satisfy part of this matrix, but not all RFC-defined checks.

Checks at clear risk:
- `VCI-CHECK-03A` WIA handling: partial only, non-blocking, no trusted-list validation
- `VCI-CHECK-04` pre-authorized validation: tx-code branch incomplete
- `VCI-CHECK-06A` WUA handling: trust and revocation incomplete; multi-key issuance missing
- `VCI-CHECK-10` `A128GCM`: not currently advertised in issuer metadata

## Missing or Omitted Checks

These are the main issuer-side checks defined by the RFC that are currently omitted or insufficiently enforced:

1. Enforce PAR as mandatory for authorization-code flow.
2. Reject direct `/authorize` requests not backed by a valid PAR `request_uri`.
3. ~~Enforce WIA presence at PAR and Token when RFC profile requires it.~~ **Done (2026-04-16, P0-7).**
4. Verify WIA signature against **trusted** Wallet Provider keys (beyond self-contained `jwk` / `x5c`; P0-8).
5. Verify proof-of-possession for the key referenced by WIA `cnf`.
6. ~~Enforce `client_id` consistency between PAR and Token.~~ **Done (2026-04-16, P0-2)** when authorize records a non-empty `client_id`.
7. ~~Enforce `redirect_uri` consistency in authorization-code token redemption.~~ **Done (2026-04-16, P0-3)** when authorize records a non-empty `redirect_uri`.
8. ~~Enforce `tx_code` on pre-authorized token redemption when the offer advertises it.~~ **Done (2026-04-16, P0-6)** — require non-empty `tx_code` when `requireTxCode` is set (no value matching).
9. ~~Validate sender-constrained access-token use at `/credential`.~~ **Done (2026-04-16, P0-4)** for JWT tokens with `cnf.jkt`.
10. Validate sender-constrained access-token use at `/notification`.
11. ~~Protect `/credential_deferred` with access-token validation instead of only `transaction_id`.~~ **Done (2026-04-16, P0-5).**
12. Require `key_attestation` for the RFC `proofs.jwt` device-bound path.
13. Reject invalid/missing WUA when the selected proof/profile requires it.
14. Implement real Wallet Provider trust policy for WUA and attestation proofs.
15. Implement WUA status/revocation checking.
16. Enforce RFC cardinality for `proofs.jwt` as exactly one element.
17. Implement multi-key issuance behavior for attestation/WUA cases where the RFC requires one credential per attested key.
18. Publish metadata consistent with runtime support for pre-authorized flow.
19. Implement ETSI signed issuer metadata with `x5c`.
20. Publish `issuer_info` when ETSI alignment is intended.
21. Support `eu-eaa-offer://` when ETSI alignment is intended.
22. Publish/support `A128GCM` in addition to `A256GCM` when ETSI alignment is intended.

## Backlog for Alignment

The detailed, actionable backlog is maintained as a separate file: `reports/rfc001-alignment-backlog.md`.

The backlog is organized into:

- **P0 - Critical (RFC baseline, security-relevant)**: items that currently make the issuer non-compliant with the RFC's SHALL-level obligations on PAR, WIA, sender-constrained tokens, `tx_code`, and deferred-endpoint protection.
- **P1 - High (RFC baseline, correctness)**: `client_id`/`redirect_uri` consistency, `proofs.jwt` cardinality, `key_attestation` enforcement, WUA trust/revocation, proof JWT `typ`/`iss` handling, PKCE universality, deferred response shape, notification binding, metadata vs runtime grant types, DPoP strictness.
- **P2 - Medium (ETSI-aligned profile)**: signed issuer metadata with `x5c`, `issuer_info`, `eu-eaa-offer://`, `A128GCM`, ETSI format identifiers, multi-key issuance semantics.
- **P3 - Low (hygiene)**: metadata advertising, known typos/bugs, batch endpoint cleanup, error code alignment.

Each backlog item references the RFC section, the current code location, and a clear acceptance criterion.

## Bottom Line

The issuer already has the right protocol shape, but it is not yet compliant with the RFC as written.

If you want a strict summary:
- Baseline OpenID4VCI issuer: mostly there
- RFC001 issuer compliance: partial
- RFC001 plus ETSI-aligned profile: no

All findings in this report have been validated against the current code, and eighteen additional issuer-side gaps were identified during validation (see "Additional Findings Discovered During Validation" above). Fixing the P0 and P1 items in the separate backlog brings the issuer into RFC baseline compliance. P2 is required only if ETSI TS 119 472-3 alignment is a target.

