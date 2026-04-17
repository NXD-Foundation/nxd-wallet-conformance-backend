# RFC001 Alignment Backlog

Source: `reports/rfc001-issuer-compliance-review.md`
RFC reference: `~/Downloads/RFC001 (1).md` (APTITUDE RFC-01 Credential Issuance Profile, v0.1 Draft)
Target: issuer-side only. Created 2026-04-16.

Priority scheme:
- **P0** - Blocks RFC baseline compliance, security-relevant. Do before any conformance run.
- **P1** - Needed for RFC baseline conformance or clear implementation bug.
- **P2** - Needed only for the ETSI TS 119 472-3 aligned profile path.
- **P3** - Hygiene, metadata cleanup, known bugs not on the compliance-critical path.

Each item lists: **RFC anchor**, **code location**, **what to do**, **acceptance criterion**.

---

## P0 - Critical

### P0-1. Enforce PAR for all Authorization Code Flow requests — **Done (2026-04-16)**

- RFC: §7.3 Issuer SHALL, items 1-3; §6.1.3; §6.2.5.
- Done:
  - `routes/issue/codeFlowSdJwtRoutes.js` loads `data/oauth-config.json` and, when `require_pushed_authorization_requests === true`, **`GET /authorize`** requires a non-empty **`request_uri`** and a matching PAR cache entry from `handlePARRequest()`.
  - Missing **`request_uri`**: HTTP **400** JSON `{ error: "invalid_request", error_description: "…" }` (no redirect, no query-parameter fallback).
  - Unknown **`request_uri`**: same **400** response (no silent continue).
  - When the flag is **false**, behavior is unchanged: PAR is optional; if **`request_uri`** is present and valid, parameters are merged from the PAR entry.
- Tests: `tests/metadataDiscovery.test.js` (two API-backed `/authorize` cases); `tests/codeFlowSdJwtRoutes.test.js` (mock router aligned; PAR-02 enabled; authorize tests supply **`request_uri`**).

### P0-2. Enforce `client_id` consistency between PAR and Token — **Done (2026-04-16)**

- RFC: §7.3 Issuer SHALL item 6; §7.4 Issuer SHALL items 1-6.
- **PAR:** `client_id` is stored on the pushed authorization request (`createPARRequest` in `routes/issue/codeFlowSdJwtRoutes.js`).
- **Authorize:** `updateSessionForAuthorization()` persists **`authorizationRequestClientId`** on the code session from the merged PAR/authorize request (`routes/issue/codeFlowSdJwtRoutes.js`).
- **Token:** `handleAuthorizationCodeFlow()` compares **`req.body.client_id`** to the bound value when it is non-empty; mismatch or omission yields **HTTP 400** **`invalid_grant`** (`routes/issue/sharedIssuanceFlows.js`).
- **Note:** If the authorization phase recorded no non-empty `client_id`, no binding is stored and the token step does not apply this check (legacy/test sessions).
- Tests: `tests/sharedIssuanceFlows.test.js` (`P0-2`, `P0-2b`; existing auth-code tests pass **`client_id`** aligned with the session).

### P0-3. Enforce `redirect_uri` consistency at Token Endpoint — **Done (2026-04-16)**

- RFC: §6.1.5 Wallet SHALL send `redirect_uri`; §7.4 Issuer SHALL validate.
- **Authorize:** `updateSessionForAuthorization()` already persists **`requests.redirectUri`** (`routes/issue/codeFlowSdJwtRoutes.js`).
- **Token:** `handleAuthorizationCodeFlow()` reads **`redirect_uri`** from the token request body and compares it to the bound value when **`requests.redirectUri`** is non-empty; mismatch or omission → **HTTP 400** **`invalid_grant`** (`routes/issue/sharedIssuanceFlows.js`).
- **Note:** Same as P0-2: if authorize did not record a non-empty redirect URI, no binding check runs (legacy/test sessions).
- Tests: `tests/sharedIssuanceFlows.test.js` (`P0-3`, `P0-3b`; happy paths send **`redirect_uri`** aligned with the session).

### P0-4. Enforce sender-constrained access tokens at `/credential` — **Done (2026-04-16)**

- RFC: §5 baseline choices; §7.1 SHALL 8; §7.5 Issuer SHALL 3; §8.5.
- **Detection:** Access token JWT payload **`cnf.jkt`** (same binding the token endpoint embeds via RFC 9449). Opaque or non-JWT tokens skip the check (legacy/tests).
- **Validation (before credential request shape checks):** `DPoP` header required; **`htm`=`POST`**, **`htu`=`${getServerUrl()}/credential`**, **`ath`=`base64url(SHA-256(access token))`**, **`iat`/replay (`jti`)** per token-endpoint policy, proof **`jkt`** must equal **`cnf.jkt`** (`getDpopBoundJktFromAccessToken`, `validateDpopProofForCredentialRequest` in `routes/issue/sharedIssuanceFlows.js`).
- **Errors:** missing `DPoP` → **401** **`invalid_token`**; malformed / mismatch → **400** **`invalid_dpop_proof`**.
- Tests: `tests/sharedIssuanceFlows.test.js` (`P0-4`, `P0-4b`).

### P0-5. Require access-token validation at `/credential_deferred` — **Done (2026-04-16)**

- RFC: §6.3, §7.6, §8.8. Deferred retrieval must be tied to authorisation / transaction state.
- Code: `routes/issue/sharedIssuanceFlows.js` (`POST /credential_deferred`).
- Done:
  - Require `Authorization: Bearer|DPoP <token>`.
  - Resolve the session the same way as `/credential` via `getSessionFromToken`.
  - Require `transaction_id` and verify it belongs to that session (`resolveDeferredIssuanceContext` + session key match; mismatch → **400** `invalid_grant`).
  - Same DPoP sender-constraint as P0-4 when the access token is JWT `cnf.jkt`-bound (`validateDpopProofForResourceRequest` with **`htu`** for `/credential_deferred`).
- Acceptance:
  - `/credential_deferred` without `Authorization` returns HTTP 401 `invalid_token`.
  - Using a different token than the one that initiated the deferred transaction returns `invalid_grant` or `invalid_token`.
- Tests: `tests/sharedIssuanceFlows.test.js` (`POST /credential_deferred`); `tests/metadataDiscovery.test.js` (basic contract + encryption override fixture).
- Wallet: `wallet-client/src/server.js` and `wallet-client/src/index.js` send `Authorization: Bearer` and per-poll DPoP when the token is DPoP-bound.

### P0-6. Enforce `tx_code` at the Pre-Authorized Token Endpoint when advertised — **Done (2026-04-16)**

- RFC: §6.2.6, §7.4 Wallets-for-pre-auth items 1-2.
- Code: Pre-auth sessions that were created for offers with `tx_code` carry **`requireTxCode: true`** (`routes/issue/preAuthSDjwRoutes.js`, `routes/issue/vciStandardRoutes.js`, `routes/pidroutes.js`, `routes/paymentRoutes.js`). Token handler: `handlePreAuthorizedCodeFlow` in `routes/issue/sharedIssuanceFlows.js`.
- Done:
  - When `requireTxCode` is set on the session, the token request **must** include a **non-empty** `tx_code` (after trim). **No issuer-side value check** — any submitted code is accepted (PIN/OTP verification is out of scope here).
  - Missing or whitespace-only `tx_code` → **400** `invalid_grant`.
- Acceptance:
  - Token redemption for an offer that included `tx_code` without `tx_code` returns `invalid_grant`.
  - With any non-empty `tx_code`, redemption succeeds.
- Tests: `tests/sharedIssuanceFlows.test.js` (pre-auth token + `requireTxCode`); `tests/preAuthSDjwRoutes.test.js` (session shape).

### P0-7. Enforce WIA at PAR and Token — **Done (2026-04-16)**

- RFC: §5 baseline; §7.3 SHALL 7-11; §7.4 SHALL Wallet 2-3, Issuer 4.
- Code: `routes/issue/codeFlowSdJwtRoutes.js` (`POST /par`), `routes/issue/sharedIssuanceFlows.js` (`POST /token_endpoint`), `utils/routeUtils.js` (`validateWIA`, `verifyWiaJwtSignature`, `extractWIAFromTokenRequest`).
- Done (always on; **no feature flag**):
  - **Carrier:** `client_assertion` + `client_assertion_type` = `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` (same as before).
  - **PAR and Token:** missing WIA → **400** **`invalid_client`**. Invalid/expired/malformed JWT or bad signature → **400** **`invalid_client`** with `error_description` from validation.
  - **Signature:** JWS verified using optional issuer-config `wallet_instance_attestation_jwks`, else **`jwk`** in the protected header, else first **`x5c`** leaf cert → public key. **No Wallet Provider trusted-list / `iss` policy** (any key that verifies is accepted until P0-8 / trust framework).
- Tests: `tests/sharedIssuanceFlows.test.js` (incl. negative “no WIA”); `tests/metadataDiscovery.test.js` (PAR + token fixtures).

### P0-8. Verify WIA signature against the Wallet Provider trusted list and PoP against `cnf`

- RFC: §7.3 Issuer SHALL 9-11; §7.4 Issuer SHALL 4.
- Code: `utils/routeUtils.js` (`validateWIA`, `verifyWiaJwtSignature`). **Note:** JWS verification against header `jwk` / `x5c` or config JWKS is **done (P0-7)**; trusted-list resolution of WP keys by `iss` is still **open** below.
- Do:
  - Resolve signing keys from a **Trusted List / WP JWKS** keyed by `iss` instead of (or in addition to) self-contained `jwk` / `x5c` in the WIA.
  - Verify `iss`, `iat`, `nbf`, `exp`, and that `cnf.jwk` or `cnf.jkt` is present and well-formed.
  - Require a `OAuth-Client-Attestation-PoP` JWT carrying `iss`, `aud` (= issuer URL), `jti`, fresh `iat`, signed by the key referenced in WIA `cnf`. Verify that signature.
  - Any failure in any of these checks returns a top-level rejection.
- Acceptance:
  - An expired, re-signed-by-unknown-key, or unsigned WIA is rejected.
  - Token/PAR without PoP (when required) is rejected.
  - `isWuaWalletProviderTrustedByPolicy` and `isKeyAttestationTrustedByIssuer` stubs are replaced with actual trusted-list lookups.

---

## P1 - High

### P1-1. Require `key_attestation` protected header on `proofs.jwt` device-bound path - **done**

- RFC: §7.5.1 Wallets SHALL 3-6; Issuers SHALL 1-3.
- Code: `utils/routeUtils.js:1824-1858` (extractor), proof validation pipeline in `routes/issue/sharedIssuanceFlows.js`.
- Do:
  - When the selected proof method is `proofs.jwt` and the RFC profile requires device-bound issuance, require a `key_attestation` parameter in the protected header.
  - Validate the WUA carried there (see P0-8 / P1-3).
  - Verify the JWT proof signature under the first public key in WUA `attested_keys`.
- Acceptance:
  - `proofs.jwt` without `key_attestation` header is rejected with `invalid_proof`.
  - JWT proof signed by a key not in `attested_keys[0]` is rejected.

### P1-2. Enforce `proofs.jwt` cardinality = exactly one element -- **done** 

- RFC: §7.5.1 Wallets SHALL 1.
- Code: `routes/issue/sharedIssuanceFlows.js:376-390`.
- Do:
  - Require `proofs.jwt` to be an array of length exactly one.
  - Reject strings and multi-element arrays with `invalid_proof`.
- Acceptance:
  - `proofs.jwt = "..."` (string) returns `invalid_proof`.
  - `proofs.jwt = [a, b]` returns `invalid_proof`.
  - `proofs.jwt = [a]` proceeds as today.

### P1-3. Replace WUA trust/revocation stubs with real policy - **out of scope!** 

- RFC: §7.5.1 Issuers SHALL 1; §7.5.2 Issuers SHALL 1.
- Code: `utils/routeUtils.js:1560-1576`, `:1740`, `:1753-1768`, `utils/keyAttestationProof.js:63-71`, `:225-235`.
- Do:
  - Implement Wallet Provider trust-list resolution (config-driven JWKS URL(s) or static JWKS, plus `iss` allow-list).
  - Validate WUA signature against that trust material.
  - Implement status/revocation checking using `status_list` (OAuth Status List draft) when present.
- Acceptance:
  - WUA signed by an untrusted key is rejected.
  - WUA flagged as revoked via `status_list` is rejected.

### P1-4. Validate proof JWT `typ` header -- **done**

- RFC anchor: §7.5 / OpenID4VCI §8.2.
- Code: `routes/issue/sharedIssuanceFlows.js` (`validateProofJWT`).
- Do:
  - Require `header.typ === "openid4vci-proof+jwt"`.
  - Reject otherwise with `invalid_proof`.
- Acceptance:
  - Proofs lacking the correct `typ` header are rejected.

### P1-5. Require proof JWT `iss` uniformly -- **done**

- RFC: §7.5 Wallets SHALL 5 (issuer binding).
- Code: `routes/issue/sharedIssuanceFlows.js` (`verifyProofJWT`).
- Do:
  - Remove the `flowType === "code"` gate. Require `iss` for any proof JWT that the wallet generates on its own behalf.
  - Keep exceptions only where the RFC or applicable proof-type spec explicitly removes `iss` (document them).
- Acceptance:
  - Pre-authorized proof JWT without `iss` is rejected when flow is holder-authenticated wallet-generated.

### P1-6. Make PKCE `S256` universally required for Authorization Code Flow -- **done**

- RFC: §5 baseline; §7.1 Auth-code SHALL 2; §7.3 Issuer SHALL 5.
- Code: `routes/issue/codeFlowSdJwtRoutes.js` (`validateAuthorizationRequest`), `/authorize` and `/par`.
- Do:
  - Require `code_challenge` and `code_challenge_method = S256` whenever `response_type = code` is requested, regardless of `authorization_details`.
  - Reject `plain` and missing `code_challenge_method` explicitly with `invalid_request` at `/authorize` (and at `/par`).
- Acceptance:
  - Auth request with `code_challenge_method=plain` returns `invalid_request`.
  - Auth request with no `code_challenge` returns `invalid_request`, even with scope-only selection.

### P1-7. Fix deferred success response shape and add pending path -- **done**

- RFC: §6.3, §7.6; OIDC4VCI 1.0 §9 (`issuance_pending` for deferred polling; not OAuth’s `authorization_pending`).
- Code: `routes/issue/sharedIssuanceFlows.js` — `handleDeferredCredentialIssuance`, `POST /credential_deferred`.
- Done:
  - Success: `{ credentials: [{ credential }], notification_id }` (same envelope as immediate `/credential`; JWE when encryption requested).
  - Pending: `400` + `error: issuance_pending` + `interval` + `error_description`.
  - Terminal: `400` + `invalid_transaction_id` or `expired_transaction_id` (not 500).
- Tests: `tests/sharedIssuanceFlows.test.js` (`POST /credential_deferred`: pending, expired, invalid tx, success shape).

### P1-8. Bind `notification_id` to the access token's session — **Done (2026-04-16)**

- RFC: §7.1 SHOULD 3; §8.7.
- Code: `routes/issue/sharedIssuanceFlows.js` (`POST /notification`).
- Done:
  - `notification_id` is already persisted on the session at credential issuance (immediate and deferred paths).
  - On `POST /notification`, `req.body.notification_id` MUST equal the session's stored value (string-normalized). No stored id yet (credential response not received) → `400 invalid_notification_request`. Mismatch → `403 invalid_notification_id`.
- Tests: `tests/sharedIssuanceFlows.test.js` — `POST /notification` (no id / mismatch / success).

### P1-9. Strengthen DPoP handling — **Done (2026-04-16)**

- RFC: §7.1 SHALL 8; §7.4 Issuer SHALL 5-6.
- Code: `routes/issue/sharedIssuanceFlows.js` (token endpoint DPoP parsing, `handleAuthorizationCodeFlow` thumbprint binding).
- Done:
  - DPoP proofs without `jwk` in the protected header now fail with `invalid_dpop_proof` (no Bearer fallback).
  - Expected `htu` is computed from `getServerUrl()` per request (proxy-aware).
  - **DPoP is now mandatory and unconditional** at the token endpoint for both `authorization_code` and `urn:ietf:params:oauth:grant-type:pre-authorized_code`. The `HAIP_PROFILE_REQUIRE_DPOP_FOR_TOKEN` environment flag has been **removed** — RFC001 §7.4 requires sender-constrained tokens and this issuer uses DPoP as the sender-constraining mechanism.
  - Successful token responses always carry `token_type: "DPoP"` and an access token with `cnf.jkt` matching the DPoP public key thumbprint.
  - PAR-bound DPoP thumbprint (`expectedDpopJkt`) is now enforced unconditionally at the token endpoint; mismatches yield `invalid_dpop_proof`.
- Tests: `tests/sharedIssuanceFlows.test.js` — `INT-01`, `INT-01a`, `INT-02`, `DPOP-02`, `DPOP-02b`, `DPOP-03..07`.
- ~~Remaining follow-up: enforce DPoP proof on **`/credential_deferred`**~~ **Addressed (P0-5, 2026-04-16)** alongside **P0-4** `/credential`.

### P1-10. Emit `c_nonce` from the Token Endpoint -- **done**

- RFC: §6.1.5, §7.4 Issuer SHALL 7.
- Code: `routes/issue/sharedIssuanceFlows.js` — `handlePreAuthorizedCodeFlow`, `handleAuthorizationCodeFlow`; `POST /nonce`.
- Done:
  - On success, both grants generate a fresh `c_nonce` (`generateNonce`), `storeNonce(…, NONCE_EXPIRES_IN)`, set `session.c_nonce`, persist the session, and return `c_nonce` + `c_nonce_expires_in` on the token JSON.
  - `POST /nonce` remains an alternate refresh path and requires `Authorization: Bearer|DPoP` + an access token tied to an issuance session (`401` otherwise).
- Tests: `tests/sharedIssuanceFlows.test.js` — e.g. `MUST include c_nonce and c_nonce_expires_in on success (pre-authorized_code|authorization_code)`, session persistence checks.

### P1-11. Protect `/nonce` and bind nonces to sessions -- **done**

- RFC: §6.1.6, §8.6.
- Code: `routes/issue/sharedIssuanceFlows.js` — `POST /nonce`, `/credential` proof nonce checks.
- Done:
  - `POST /nonce` requires `Authorization: Bearer|DPoP` and an access token tied to an issuance session (`401` otherwise).
  - New `c_nonce` is stored on the session and in the nonce cache.
  - `/credential` requires proof JWT `nonce` to equal the current session `c_nonce` before `checkNonce` (so another session’s unexpired nonce is rejected).
- Tests: `tests/sharedIssuanceFlows.test.js` — `POST /nonce` coverage; `MUST reject proof nonce valid in store but not this session c_nonce`.

### P1-12. Implement multi-key issuance -- **done**

- RFC: §7.5.1 Issuer SHALL 4-6; §7.5.2 Issuer SHALL 2-4.
- Code: `routes/issue/sharedIssuanceFlows.js` (`dedupeAttestedKeysToCnfList`, `/credential`, `/credential_deferred`), `utils/credGenerationUtils.js` (`_overrideHolderCnf`, deferred override), `utils/routeUtils.js` (`proofKeyMatchesAnyWUAAttestedKey`).
- Done:
  - **Attestation** (`proofs.attestation`): after `verifyKeyAttestationProofChain`, builds a deduped `_credentialBindingCnfList` (by JWK thumbprint) and issues one SD-JWT per entry.
  - **Device-bound JWT** (`key_attestation` in proof header, RFC001 PID / `key_attestation_required`): resolves the proof signing JWK, requires it to match **any** WUA `attested_keys` entry (`proofKeyMatchesAnyWUAAttestedKey`), verifies PoP, then issues one credential per distinct attested key.
  - **Deferred** completion loops the same list when `requestBody._credentialBindingCnfList` is present.
- Tests: `tests/sharedIssuanceFlows.test.js` — `P1-12 — MUST return one credential per WUA attested key`; `tests/wuaValidation.test.js` — `proofKeyMatchesAnyWUAAttestedKey`.

### P1-13. Enforce `authorization_details` schema and preserve `credential_identifiers` — **done**

- RFC / spec: OID4VCI 1.0 §6.1.5 (token success response); credential entries use RFC 9396 RAR type `openid_credential`.
- Code: `utils/routeUtils.js` (`OPENID_CREDENTIAL_AUTH_DETAILS_TYPE`, `assertOpenidCredentialAuthorizationDetails`, `resolveCredentialIdentifierFromOpenidCredentialEntry`, `parseAuthorizationDetailsParameterRaw`), `routes/issue/sharedIssuanceFlows.js` (`parseAuthorizationDetails`, `buildTokenResponseAuthorizationDetails` — used for **pre-authorized_code** and **authorization_code** token responses), `routes/issue/codeFlowSdJwtRoutes.js` (`POST /par` and `GET /authorize` via `parseValidateAndNormalizeAuthorizationDetails`).
- Done:
  - Every entry must be an object with `type: "openid_credential"` and a resolvable credential id (`credential_configuration_id`, `vct`/`doctype`, `credential_definition.type`, etc.); otherwise OAuth **`invalid_request`** (token, PAR, and `/authorize`).
  - Token response sets **`authorization_details`** via an explicit per-entry map: `{ ...entry, credential_identifiers: [resolvedId] }` (per-entry resolution, not only the first element’s `credential_configuration_id`).
- Tests: `tests/sharedIssuanceFlows.test.js` — `should handle authorization_details in pre-authorized flow`; `should set credential_identifiers per authorization_details entry (not only from the first)`; `MUST return invalid_request when authorization_details omits type openid_credential`; `tests/metadataDiscovery.test.js` — `POST /par MUST return invalid_request when authorization_details omits type openid_credential`.

### P1-14. Align OAuth metadata with runtime

- RFC: §7.7.
- Code: `data/oauth-config.json:28`.
- Do:
  - Add `urn:ietf:params:oauth:grant-type:pre-authorized_code` to `grant_types_supported`.
  - Remove `vp_token` and `id_token` from `response_types_supported` (these are VP-layer, not issuance).
- Acceptance:
  - OAuth metadata advertises exactly the grants and response types that the runtime supports for issuance.

### P1-15. Map errors to OID4VCI codes

- RFC: §7.5 requires meaningful errors; §8.
- Code: `routes/issue/sharedIssuanceFlows.js` (token + credential paths), various throwers.
- Do:
  - Map known failure classes to `invalid_request`, `invalid_grant`, `invalid_proof`, `invalid_nonce`, `invalid_credential_request`, `unsupported_credential_format`, `invalid_token`, `invalid_dpop_proof`, `invalid_notification_id`, `issuance_pending`, `invalid_transaction_id`, `expired_transaction_id`.
  - Replace remaining generic `server_error` returns with specific codes where the spec defines them.
- **Partial (2026-04-16, verified 2026-04-16):**
  - Non-standard **`credential_request_denied`** is **gone** from the codebase (only mentioned in older compliance notes).
  - **`POST /credential`**: after branches for `invalid_token`, `invalid_dpop_proof`, `invalid_proof`, `invalid_nonce`, encryption params, and structured `credentialValidationError` codes, the **default outer `catch`** returns **`invalid_credential_request`** (400) with a useful `error_description` (see `sharedIssuanceFlows.js` — final `catch` before `/credential_deferred`).
  - **`POST /credential` — issuance generation**: failures inside **`handleImmediateCredentialIssuance`** are still **`server_error`** (500) (inner `catch` around immediate issuance); that remains a P1-15 gap where OID4VCI might allow a narrower client-visible code.
  - **`POST /credential_deferred`**: generator/request-shape failures with **`error.status === 400`** map to **`invalid_credential_request`**; other uncaught errors still **`server_error`** (500).
  - **Still missing in code (gap):** e.g. **`unsupported_credential_format`** is not returned anywhere yet; notification path uses **`invalid_notification_request`** in addition to **`invalid_notification_id`**.
- Acceptance:
  - Representative failure cases return the specific OID4VCI codes listed above, each with a useful `error_description`.

---

## P2 - ETSI-aligned profile

Only required if the pilot claims RFC001 used as an ETSI TS 119 472-3 aligned profile.

### P2-1. Signed Issuer Metadata with `x5c`

- RFC: §5 (ETSI additions), §7.7 SHALL 7, §8.9.
- Code: `routes/metadataroutes.js:36-73`.
- Do:
  - Return a JWS (compact or JSON form, per the format the wallet-under-test consumes) whose payload is the current `issuerConfig`.
  - Protected header MUST include `x5c` carrying the Issuer access certificate chain.
  - Key the signature to the certificate's subject key.
- Acceptance:
  - Metadata endpoint returns a signed JWS when `Accept` requests the signed form (or unconditionally, per the chosen media type handling).
  - The JWS verifies under the certificate in `x5c`.

### P2-2. `issuer_info` metadata parameter — **done (2026-04-17, self-signed dev material)**

- RFC: §5, §7.7 SHALL 8, §8.9.
- Code: `utils/issuerInfo.js` (`buildIssuerInfo`), `routes/metadataroutes.js` (attaches `issuer_info` to `/.well-known/openid-credential-issuer`), `data/issuer-registration.json` (registrar dataset placeholder), `x509EC/client_certificate.crt` (registration certificate; self-signed dev material, reused from mdoc issuance).
- Done:
  - `/.well-known/openid-credential-issuer` returns a non-empty `issuer_info` object containing:
    - `registration_certificate` — base64-encoded DER of `x509EC/client_certificate.crt`.
    - `registration_certificate_pem` — full PEM for display.
    - `registration_certificate_summary` — parsed `subject`, `issuer`, `serial_number`, `not_before`, `not_after`, `sha256_thumbprint`, `self_signed`.
    - `registration_information` — registrar dataset from `data/issuer-registration.json` (`legal_name`, `organization_identifier`, `country`, `registrar`, `registered_on`, `homepage_uri`, `self_registered: true`).
    - `profile: "ETSI TS 119 472-3 (APTITUDE RFC001 §7.7 SHALL 8)"`.
  - Paths are overridable via env: `ISSUER_REGISTRATION_CERT_PATH`, `ISSUER_REGISTRATION_INFO_PATH`.
- Note: the certificate is **self-signed** (no APTITUDE registrar available yet) and `registration_information.self_registered` is set to `true` so wallets do not treat this as production trust material. Replace both files once a registrar issues real material.
- Tests: `tests/metadataDiscovery.test.js` — `MUST include issuer_info with registration certificate and registrar dataset (RFC001 §7.7 SHALL 8)`.

### P2-3. Same-device `eu-eaa-offer://` invocation — **done (2026-04-17)**

- RFC: §5, §6.2.3, §7.1 SHALL 13, §7.2 SHALL 8, §8.1.
- Code: `utils/routeUtils.js` — `URL_SCHEMES.EU_EAA`, `resolveCredentialOfferUrlScheme`, `getCredentialOfferSchemeFromRequest`; offer routes: `routes/issue/codeFlowSdJwtRoutes.js` (`/offer-code-sd-jwt`, `/offer-code-sd-jwt-dynamic`, `/offer-code-defered`), `routes/issue/preAuthSDjwRoutes.js` (`/offer-tx-code`, `/offer-no-code` GET/POST), `routes/issue/vciStandardRoutes.js` (`/vci/offer`), `routes/multiCredentialOfferRoutes.js` (`/offer-no-code-batch`).
- Done:
  - **`EU_EAA: "eu-eaa-offer://"`** added to `URL_SCHEMES`.
  - **Selection:** query or JSON body **`offer_scheme`** (preferred) or **`url_scheme`** (backward compatible). Short values: `eu_eaa`, `eu-eaa`, `eaa`; also `haip`, `standard` / `openid`, or full prefixes `eu-eaa-offer://`, `haip://`, `openid-credential-offer://`. Unknown values default to **`openid-credential-offer://`**.
  - **HAIP-specific routes** (`/haip-offer-tx-code`, etc.) unchanged — still force `haip://`.
- Tests: `tests/routeUtils.test.js` (resolver + request helper); `tests/metadataDiscovery.test.js` — API-backed `GET /offer-code-sd-jwt` and `GET /offer-no-code` with `offer_scheme=eu_eaa`.

### P2-4. `A128GCM` support and advertisement — **done (verified 2026-04-17)**

- RFC: §5, §7.1 SHALL 12, §7.7.
- Code: `data/issuer-config.json` (`credential_response_encryption.enc_values_supported`), `utils/credentialResponseEncryption.js` (`encryptCredentialResponseToJwe` — passes wallet `enc` into JWE protected header; `validateCredentialResponseEncryptionParams` checks against metadata).
- Done:
  - Metadata advertises **`["A128GCM", "A256GCM"]`** (`data/issuer-config.json`).
  - Runtime: any `enc` in the advertised list is accepted; **jose** `CompactEncrypt` encrypts with the requested content encryption algorithm (no A256-only branch in issuer code).
- Tests: `tests/metadataDiscovery.test.js` — issuer metadata includes both enc values; `tests/credentialResponseEncryption.test.js` — round-trip decrypt for **A128GCM** and **A256GCM** with ECDH-ES.

### P2-5. ETSI format identifiers — **Done (2026-04-16)**

- RFC: §5.1, §7.7 SHALL 6.
- Done:
  - `data/issuer-config.json`: `ETSIRfc001PidVcSdJwt` / `ETSIRfc001PidVcJwt` / `ETSIRfc001PidX509Attr` with formats `vc+sd-jwt`, `vc+jwt`, `x509_attr` (shared `vct` `urn:eu.europa.ec.eudi:pid:1`).
  - `routes/issue/sharedIssuanceFlows.js`: `vc+jwt` → `jwt_vc_json` path; `vct` from `credConfig.vct` / `doctype`.
  - `utils/issueX509AttrCredential.js` + `utils/credGenerationUtils.js`: `x509_attr` issuance (RFC 5755 AC, base64 DER).
  - `tests/metadataDiscovery.test.js`: asserts all three formats appear in metadata.
- Note: P2-4 (runtime `A128GCM` for encrypted credential responses) may still need verification if pilots negotiate `A128GCM`; metadata now advertises it alongside `A256GCM`.

---

## P3 - Hygiene

### P3-1. Fix `authorizatiton_details` typo in JAR token response — **Done (2026-04-16)**

- Code: `utils/cryptoUtils.js` (JAR payload builder); duplicate fixed in `wallet-client/utils/cryptoUtils.js`.
- Done: `jwtPayload.authorization_details = authorization_details` (typo removed).
- Acceptance: no `ReferenceError` when that branch executes.

### P3-2. Resolve batch endpoint ambiguity — **Done (2026-04-16)**

- Code: `routes/metadataroutes.js` (metadata handler), `routes/multiCredentialOfferRoutes.js` (renamed from `batchRequestRoutes.js`), `server.js` (import/mount), `rfc-batch-credential-issuance.md` (banner), `tests/metadataDiscovery.test.js` (hard assert).
- Done:
  - Metadata handler now **deletes** `batch_credential_endpoint` from outgoing metadata instead of warning — aligns with OID4VCI 1.0 (draft-14 removed the field) and RFC001.
  - Router renamed to `multiCredentialOfferRouter` and file header clarifies these are multi-credential **offer** helpers (the Credential Offer may list multiple `credential_configuration_ids`), not a custom batch endpoint. URL paths preserved for backwards compatibility with `testCaseRequests.yml`.
  - Historical `rfc-batch-credential-issuance.md` marked as superseded by OID4VCI 1.0 / RFC001.
  - Metadata discovery test hard-asserts absence of `batch_credential_endpoint`.
- Acceptance: no `batch_credential_endpoint` field ever appears in the issuer metadata response, no code path advertises a bespoke batch endpoint, and internal naming no longer conflicts with the RFC001-aligned single `/credential` + `proofs.jwt[]` model (full multi-proof coverage tracked under P1-12).

### P3-3. Review anonymous pre-authorized access advertisement — **done (2026-04-17)**

- Code: `data/oauth-config.json`.
- Decision: **`pre-authorized_grant_anonymous_access_supported: false`** — OAuth AS metadata no longer advertises anonymous pre-authorized grant access; RFC001 pilots should rely on WIA/client attestation at PAR/token, optional `tx_code`, and sender-constrained tokens as implemented elsewhere.
- Acceptance: `/.well-known/oauth-authorization-server` exposes `pre-authorized_grant_anonymous_access_supported: false`.

### P3-4. Tighten `scope`-based offer construction — **done (2026-04-17)**

- Code: `utils/routeUtils.js` (`createCredentialOfferConfig`), `routes/multiCredentialOfferRoutes.js` (`/credential-offer-no-code-batch/:id`).
- Done:
  - **`createCredentialOfferConfig`** accepts **`string | string[]`** for credential configuration ids; **`credential_configuration_ids`** is always a normalized array.
  - **`authorization_code`** grant: **`scope`** is **`ids.join(" ")`** (OAuth space-separated), including a single id (unchanged semantics).
  - **`pre-authorized_code`** grant: **`scope`** is **omitted** for a **single** id (previous behavior); for **multiple** ids, **`scope`** is set to the same space-separated string so scope-based clients can request all advertised configs; wallets may still use **`authorization_details`** / **`credential_configuration_ids`** without relying on `scope`.
  - Multi-credential offer document is built via **`createCredentialOfferConfig`** so `credential_issuer` and grants stay consistent with other offer endpoints.
- Tests: `tests/routeUtils.test.js` — multi-id `scope` for both grant types; single pre-auth has no `scope`.

### P3-5. Use `getServerUrl()` consistently in security checks — **done (2026-04-17)**

- Code: `utils/routeUtils.js` (`getPublicIssuerBaseUrl(req)`), `routes/issue/sharedIssuanceFlows.js` (token, credential, credential_deferred, DPoP `htu`, proof JWT `aud`, attestation issuer, `buildAccessToken` / credential generation issuer URL).
- Done:
  - **`getPublicIssuerBaseUrl(req)`** returns `process.env.SERVER_URL` (or localhost default). When **`TRUST_FORWARDED_ISSUER_URL=true`** and `req` has **`X-Forwarded-Proto`** + **`X-Forwarded-Host`**, returns that public origin (first hop) so DPoP **`htu`** and proof **`aud`** match what wallets use behind a reverse proxy. **Enable only behind a trusted proxy** that sets/forwards these headers safely.
  - Replaced ad-hoc `getServerUrl` / unused `SERVER_URL` in shared issuance with **`getPublicIssuerBaseUrl(req)`** everywhere security-relevant; **`req`** is threaded through token handlers → access token issuance, credential → proof verification and issuance, deferred completion.
- Tests: `tests/routeUtils.test.js` — forwarded vs fallback behavior.

---

## Traceability Matrix (summary)

| Item | RFC §§ | ARF/CIR linkage (per Check Catalogue §10.1) |
| --- | --- | --- |
| P0-1, P0-2, P0-3 | 7.3, 7.4 | `VCI-CHECK-02`, `VCI-CHECK-03` |
| P0-4, P0-5 | 7.1, 7.5, 7.6 | `VCI-CHECK-05`, `VCI-CHECK-06`, `VCI-CHECK-06A` |
| P0-6 | 6.2.6, 7.4 | `VCI-CHECK-04`, `VCI-CHECK-09` |
| P0-7, P0-8 | 7.3, 7.4 | `VCI-CHECK-03A` |
| P1-1, P1-2, P1-3, P1-12 | 7.5, 7.5.1, 7.5.2 | `VCI-CHECK-05`, `VCI-CHECK-06A` |
| P1-4, P1-5 | 7.5 | `VCI-CHECK-06` |
| P1-6 | 7.3 | `VCI-CHECK-03` |
| P1-7 | 6.3, 7.6 | issuance matrix column for deferred |
| P1-8 | 7.1, 8.7 | notification section |
| P1-9 | 7.1, 7.4 | sender-constraint across `VCI-CHECK-02/03/04` |
| P1-10, P1-11 | 6.1.6, 7.4, 8.6 | nonce path feeding `VCI-CHECK-06` |
| P1-13 | 6.1.5 | `VCI-CHECK-02` |
| P1-14, P1-15 | 7.7, 8 | metadata and error-shape checks |
| P2-1..P2-5 | 5, 5.1, 7.7, 8.9 | `VCI-CHECK-10`, `VCI-CHECK-11`, ETSI profile |
| P3-* | hygiene | n/a |

## Suggested Phasing

1. **Phase 1 (security baseline)**: P0-1, ~~P0-3~~ (done 2026-04-16), ~~P0-4~~ (done 2026-04-16), P0-5, P0-6, P1-9, P1-11, ~~P3-5~~ (done 2026-04-17).
2. **Phase 2 (attestation path)**: P0-7, P0-8, P1-1, P1-2, P1-3, P1-12.
3. **Phase 3 (protocol correctness)**: ~~P0-2~~ (done 2026-04-16), P1-4, P1-5, P1-6, P1-7, P1-8, P1-10, P1-13, P1-14, P1-15.
4. **Phase 4 (ETSI profile)**: P2-1..P2-5.
5. **Phase 5 (hygiene)**: remaining P3 items.
