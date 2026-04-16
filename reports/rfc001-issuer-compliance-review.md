# RFC001 Issuer Compliance Review

Reviewed against `~/Downloads/RFC001 (1).md` on 2026-04-16.

Scope of this review:
- Issuer-side behavior only.
- Current implementation only.
- Focus on RFC sections 1-10, with emphasis on normative issuer obligations in Sections 6-8.

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
- PAR is advertised as required, but direct `/authorize` requests are still accepted without a valid PAR step.
- WIA validation at PAR and Token is non-blocking and does not verify Wallet Provider trust/signature as required by the RFC.
- `/credential` does not validate sender constraint on the access token; it only resolves a stored session from the bearer token.
- `/credential_deferred` is effectively protected only by `transaction_id`; it does not require or validate an access token.
- Pre-authorized `tx_code` is offered but not enforced at token redemption.
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
  Evidence: token endpoint can issue bearer tokens when DPoP is absent [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1066), and `/credential` does not perform DPoP verification or sender-constraint validation before issuing [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1213).
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

Assessment: Supported, but not RFC-compliant as enforced behavior.

Implemented:
- PAR endpoint exists and returns `request_uri` and `expires_in` [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:94), [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:650)
- OAuth metadata advertises `require_pushed_authorization_requests = true` [data/oauth-config.json](/home/ni/code/js/rfc-issuer-v1/data/oauth-config.json:5)

Missing/wrong:
- Direct `/authorize` requests are still accepted without PAR. If `request_uri` is absent, `handlePARRequest()` returns `null` and the flow continues [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:188), [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:710). This violates RFC 7.3 requirement to require PAR for all authorization requests.
- WIA at PAR is optional in practice, and invalid WIA does not block the request [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:623).
- WIA signature verification against Wallet Provider trust material is not implemented; `validateWIA()` performs only structural and TTL checks and explicitly leaves signature verification as TODO [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1646).
- No proof-of-possession check is performed for the key referenced by WIA `cnf` at PAR.
- No clear runtime check enforces `client_id` consistency between PAR and token redemption.

##### 6.1.4 User authorisation

Assessment: Implemented in a simplified issuer-specific way.

Implemented:
- authorization endpoint exists [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:675)
- code redirect is returned on success [routes/issue/codeFlowSdJwtRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/codeFlowSdJwtRoutes.js:805)

Missing/wrong:
- Because direct `/authorize` is accepted without PAR, the RFC’s required PAR-first flow is not enforced.

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
- Authorization-code token redemption does not validate `redirect_uri` or `client_id` consistency against the authorization request. `handleAuthorizationCodeFlow()` accepts only `code`, `code_verifier`, `authorizationDetails`, and optional DPoP binding [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:627).
- Pre-authorized flow does not enforce `tx_code` even when the offer advertises it. The offer builder includes `tx_code` [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:845), but the token endpoint contains no tx-code handling for pre-authorized redemption [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1096).

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
- Access token validation is incomplete. The endpoint resolves a stored session from the bearer token but does not verify sender-constraining material or DPoP on `/credential` [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1213). This is a direct gap against RFC 6.1.6(6) and 7.5(3).
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
- If tx-code is advertised, server-side enforcement is absent at token redemption.

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

Assessment: Implemented with a major omitted check.

Implemented:
- pre-authorized token exchange supported [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1096)

Missing/wrong:
- `tx_code` is included in offer metadata when requested [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:845), but there is no corresponding runtime validation at `/token_endpoint`.

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
- no runtime check for `client_id` consistency between PAR and token

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
- no `redirect_uri`/`client_id` consistency validation in auth-code exchange
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
- missing auth-code `redirect_uri`/`client_id` consistency checks
- missing tx-code enforcement
- missing mandatory WIA enforcement where required

#### 8.5 Credential Endpoint

Assessment: Exists and validates proof syntax well.

Gap:
- missing sender-constraint enforcement for access token use

#### 8.6 Nonce Endpoint

Assessment: Implemented and aligned enough.

Implemented:
- `POST /nonce` returns `c_nonce` and `c_nonce_expires_in` [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js:1793)

#### 8.7 Notification Interface

Assessment: Implemented.

Gap:
- request is bearer-token protected, but again without sender-constrained token enforcement.

#### 8.8 Deferred Credential Endpoint

Assessment: Exists but insufficiently protected.

Gap:
- transaction identifier alone is enough to retrieve the credential.

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
3. Enforce WIA presence at PAR and Token when RFC profile requires it.
4. Verify WIA signature against trusted Wallet Provider keys.
5. Verify proof-of-possession for the key referenced by WIA `cnf`.
6. Enforce `client_id` consistency between PAR and Token.
7. Enforce `redirect_uri` consistency in authorization-code token redemption.
8. Enforce `tx_code` on pre-authorized token redemption when the offer advertises it.
9. Validate sender-constrained access-token use at `/credential`.
10. Validate sender-constrained access-token use at `/notification`.
11. Protect `/credential_deferred` with access-token validation instead of only `transaction_id`.
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

## Backlog for Alignment Planning

### Critical

1. Make PAR mandatory and reject non-PAR authorization requests.
2. Enforce WIA validation at PAR and Token instead of logging-and-continuing.
3. Implement WIA signature trust and PoP validation.
4. Enforce sender-constrained token use at `/credential`.
5. Require authenticated access-token validation at `/credential_deferred`.
6. Enforce `tx_code` for pre-authorized offers that include it.

### High

1. Enforce `client_id` and `redirect_uri` consistency in auth-code token exchange.
2. Require `key_attestation` for `proofs.jwt` where the RFC profile expects device-bound issuance.
3. Turn WUA trust/revocation checks from stubs into real policy.
4. Fix `proofs.jwt` cardinality to exactly one element.
5. Return explicit deferred pending/terminal responses instead of implicit success-or-500 behavior.

### Medium

1. Add ETSI signed issuer metadata and `issuer_info`.
2. Add `eu-eaa-offer://`.
3. Add `A128GCM` support/advertisement if ETSI alignment is a target.
4. Align metadata with runtime grant support for pre-authorized flow.
5. Implement multi-key issuance semantics for attested-key flows if this RFC profile will be claimed strictly.

## Bottom Line

The issuer already has the right protocol shape, but it is not yet compliant with the RFC as written.

If you want a strict summary:
- Baseline OpenID4VCI issuer: mostly there
- RFC001 issuer compliance: partial
- RFC001 plus ETSI-aligned profile: no

