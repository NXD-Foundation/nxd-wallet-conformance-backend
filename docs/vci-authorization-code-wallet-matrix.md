# VCI 1.0 Wallet Matrix for Authorization Code Flow Endpoints

This note covers the authorization-code issuance routes centered on:

- [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L428)
- [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L583)

It is the authorization-code counterpart to [docs/vci-preauth-pid-x509-wallet-matrix.md](/home/ni/code/js/rfc-issuer-v1/docs/vci-preauth-pid-x509-wallet-matrix.md).

## Endpoint Families

The current code-flow surface is:

- offer endpoints
  - [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L428) `/offer-code-sd-jwt`
  - [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L464) `/offer-code-sd-jwt-dynamic`
  - [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L498) `/offer-code-defered`
- credential offer config
  - [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L534) `/credential-offer-code-sd-jwt/:id`
- authorization setup
  - [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L550) `/par`
  - [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L639) `/authorize`
- dynamic wallet interaction
  - [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L811) `/x509VPrequest_dynamic/:id`
  - [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L824) `/didJwksVPrequest_dynamic/:id`
  - [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L837) `/id_token_x509_request_dynamic/:id`
  - [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L851) `/id_token_did_request_dynamic/:id`
  - [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L867) `/direct_post_vci/:id`
- token and credential endpoints
  - [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L755) `/token_endpoint`
  - [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L1076) `/credential`
  - [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L1539) `/credential_deferred`

## Baseline Authorization-Code Test Case

The simplest code-flow test case in this repo is:

- offer from `/offer-code-sd-jwt`
- `grant_type = authorization_code`
- `credential_configuration_id = urn:eu.europa.ec.eudi:pid:1`
- `client_id_scheme = redirect_uri` or `x509_san_dns` or DID-based variant
- wallet performs authorization with PKCE
- wallet redeems code at `/token_endpoint`
- wallet requests credential at `/credential` with `proofs.jwt`

The issuer metadata relevant to this flow is advertised in:

- OAuth metadata: [data/oauth-config.json](/home/ni/code/js/rfc-issuer-v1/data/oauth-config.json#L1)
- credential metadata: [data/issuer-config.json](/home/ni/code/js/rfc-issuer-v1/data/issuer-config.json#L994)

## Summary Matrix

| Dimension | Baseline Authorization-Code Case | Other Values Advertised or Implemented Here |
|---|---|---|
| Grant Type | `authorization_code` | `pre-authorized_code` also supported elsewhere |
| Offer Shape | `credential_offer_uri` pointing to `authorization_code` grant config | dynamic and deferred offer variants |
| Authorization Bootstrap | direct `/authorize` call works in current code | `/par` is also implemented; OAuth metadata advertises PAR as required, but runtime does not enforce it |
| Credential Request Selector | `credential_configuration_id` | `credential_identifier` also accepted at `/credential` |
| Credential Format | `dc+sd-jwt` for PID | `jwt_vc_json`, `mso_mdoc` also advertised |
| Client ID Scheme | commonly `redirect_uri` | `x509_san_dns`, `did:web`, `did:jwk`, `payment` |
| Wallet Invocation Scheme | `openid-credential-offer://` | `haip://` if requested on offer endpoints |
| Wallet Auth at Token Endpoint | `public` works | OAuth client attestation is enforced for `/par` and `/token_endpoint` (unless validator returns `skip`) |
| PKCE | required in practice for successful token redemption | challenge validated server-side during code redemption |
| Token Type | bearer by default | `DPoP` if valid DPoP proof is supplied |
| HAIP DPoP Policy | optional by default | can become mandatory for `authorization_code` if `HAIP_PROFILE_REQUIRE_DPOP_FOR_TOKEN=true` |
| Proof Container | `proofs` | legacy `proof` rejected |
| Proof Type for Credential Request | `proofs.jwt` | also supports `proofs.attestation` (key-attestation+jwt) when credential config advertises `proof_types_supported.attestation` |
| Proof Signing Alg | `ES256` | `ES256` only for PID JWT proof metadata |
| Credential Signing Alg | `ES256` | `-7`, `-9` for `mso_mdoc` configs |
| Issuance Mode | immediate | deferred via `/offer-code-defered` and `/credential_deferred` |
| Issuer Signature Reference | often `x5c` for X.509 sessions | also `jwk`, `kid`, `did:web` depending on session signature type |

## Wallet Unit Flow Matrix

For a wallet unit, the authorization-code flow here breaks into these combinations:

| Step | What Wallet Must Support | Variants in This Repo |
|---|---|---|
| Offer Consumption | resolve `credential_offer_uri`, read `authorization_code.issuer_state` | static offer, dynamic offer, deferred offer |
| Authorization Request | call `/authorize` or use `request_uri` from `/par` | scope-based, `authorization_details`-based |
| PKCE | generate `code_verifier`, `S256` `code_challenge`, persist verifier | mandatory for successful token exchange |
| Client Identification | choose correct wallet-facing auth pattern | `redirect_uri`, `x509_san_dns`, `did:web`, `did:jwk`, `payment` |
| Wallet Response to Authorization | process redirect or OpenID4VP request | immediate redirect with code, dynamic `openid4vp://` handoff, callback via `direct_post_vci` |
| Token Request | redeem code with verifier | bearer or DPoP |
| Credential Request | send `proofs.jwt` (holder PoP) or `proofs.attestation` (key-attestation-only, typically a single element) plus chosen credential config | immediate or deferred issuance |
| Deferred Polling | handle `transaction_id` and `interval` | `/credential_deferred` |

## Wallet Checks Required

To support the complete authorization-code family in this repo, the wallet unit should implement these checks and behaviors:

1. Parse the offer and detect `authorization_code` grant metadata.
2. Preserve `issuer_state` from the credential offer.
3. Support `scope`-driven and `authorization_details`-driven authorization requests.
4. Generate PKCE values using `S256`.
5. Persist the `code_verifier` until token redemption.
6. Support authorization requests sent directly to `/authorize`.
7. Support PAR, because OAuth metadata advertises `require_pushed_authorization_requests = true`, even though current runtime behavior still accepts direct `/authorize` without PAR.
8. Accept and follow a 302 redirect from `/authorize`.
9. Support dynamic `openid4vp://` handoff when the issuer redirects into wallet interaction instead of returning the authorization code immediately.
10. Support `client_id_scheme` variants used by this issuer: `redirect_uri`, `x509_san_dns`, `did:web`, `did:jwk`, `payment`.
11. For X.509 or DID-based dynamic flows, fetch and process `request_uri` content.
12. Be able to answer with the expected direct-post response to `/direct_post_vci/:id`.
13. Redeem the resulting authorization code at `/token_endpoint` with `grant_type=authorization_code`.
14. Send the matching `code_verifier`; otherwise PKCE fails.
15. Capture `c_nonce` from the token response and use it in the proof JWT.
16. Build the credential request with exactly one of `credential_configuration_id` or `credential_identifier`.
17. Use `proofs` rather than `proof`.
18. Send exactly one proof type.
19. For JWT-based credentials, send `proofs.jwt` signed with `ES256`.
20. Include proof `aud` set to the issuer URL.
21. Include proof `iss` for authorization-code flow; this is explicitly checked in proof verification.
22. Include a valid, unused nonce in the proof.
23. Handle `invalid_proof` responses, including nonce refresh and retry.
24. Handle `invalid_grant` for expired code or PKCE mismatch.
25. Handle `invalid_dpop_proof` if HAIP policy or malformed DPoP proof applies.
26. Handle deferred issuance by polling `/credential_deferred` with `transaction_id`.

## Issuer-Enforced Checks

These are the main checks the issuer actually enforces for authorization-code issuance:

- `/authorize` requires `response_type=code`
- when `authorization_details` is used, `code_challenge` must be present
- authorization request must contain either usable `scope` or usable `authorization_details`
- `issuer_state` must map to a stored code-flow session
- token redemption requires a valid authorization code
- OAuth client attestation is validated for `/par` and `/token_endpoint`
- PKCE verifier must match the stored challenge
- if HAIP token policy is enabled, missing DPoP on `authorization_code` redemption is rejected
- if HAIP expected DPoP thumbprint is stored on session, DPoP key mismatch is rejected
- credential request must use `proofs`
- exactly one proof type is allowed
- nonce is mandatory and single-use
- proof JWT signature and `aud` are verified
- proof `iss` is required for code flow
- proof key must resolve from `jwk`, `did:key`, `did:jwk`, or `did:web`
- if WUA is present and valid, proof key must match the primary `attested_keys[0]` (not any key in the list)
- WUA signature is verified (issuer Trusted-List policy checks are stubbed until trust framework is wired)
- proofs.attestation is supported as a dedicated attestation proof type; invalid key-attestation JWT signatures are rejected as `invalid_proof`
- credential response encryption is supported: if `credential_response_encryption` is requested and supported by metadata, issuer returns encrypted JWE; unsupported encryption parameters are rejected as `invalid_encryption_parameters`
- nonce failures are returned as `invalid_nonce` (with optional refreshed `c_nonce`)
- unknown `credential_configuration_id` / `credential_identifier` are mapped to `unknown_credential_configuration` / `unknown_credential_identifier`

Relevant code:

- authorization request validation: [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L151)
- authorization session handling: [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L639)
- PKCE enforcement: [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L602)
- PKCE comparison helper: [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L1801)
- proof validation: [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L1200)

## Important Gaps and Repo-Specific Behaviors

These are the main cases where the wallet should distinguish VCI intent from current implementation details:

- OAuth metadata advertises `require_pushed_authorization_requests = true`, but `/authorize` still accepts non-PAR requests in current code, so PAR is supported but not currently enforced.
- WIA is accepted at `/par` and `/token_endpoint`, but validation failure does not currently block the flow.
- Dynamic PID issuance can generate `id_token`-only request URIs, but the callback endpoint [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js#L867) currently only reads `req.body.vp_token`.
- `/offer-code-defered` is the actual route spelling in code.
- The dynamic callback path mints an authorization code after wallet callback, but it does not perform deep validation of the returned VP or ID Token in this route itself.

## Practical Conformance Matrix

If you want to turn the authorization-code family into wallet test cases, the minimum matrix should cover:

| Dimension | Test Rows |
|---|---|
| Offer Type | static, dynamic, deferred |
| Client ID Scheme | `redirect_uri`, `x509_san_dns`, `did:web`, `did:jwk` |
| Authorization Transport | direct `/authorize`, PAR + `/authorize` |
| Dynamic Wallet Request Type | VP request, ID Token request |
| Token Binding | bearer, DPoP |
| Credential Format | `dc+sd-jwt`, `jwt_vc_json`, `mso_mdoc` |
| Issuance Timing | immediate, deferred |
| Issuer Signature Reference | `x5c`, embedded `jwk`, `kid`, `did:web` |
| Failure Handling | missing PKCE, bad PKCE, expired code, invalid proof, invalid nonce, invalid DPoP (also: invalid key-attestation JWT -> `invalid_proof`; WUA validation failure does not currently block issuance) |

## Recommended Single-Line Test Case Description

Authorization-code VCI 1.0 issuance with PKCE, issuer-state-based offer resolution, optional PAR, optional DPoP-bound token redemption, `proofs.jwt` (holder PoP) or `proofs.attestation` (key-attestation-only) at `/credential`, and optional encrypted credential response via `credential_response_encryption`, across static, dynamic, and deferred variants and common client identification schemes.
