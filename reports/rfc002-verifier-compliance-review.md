# RFC002 Verifier Compliance Review

Reviewed against `~/Downloads/RFC002 (1).md` on 2026-04-16.

Scope of this review:
- Verifier-side behavior only.
- Current implementation only.
- Focus on RFC sections 1-11, with emphasis on verifier obligations in Sections 6-10.

## Executive Summary

The verifier implementation is materially closer to RFC compliance than the issuer side. It already supports:
- signed request-object generation
- `request_uri`-based OpenID4VP requests
- same-device and cross-device OpenID4VP invocation patterns
- `direct_post`, `direct_post.jwt`, and `dc_api.jwt` style response handling
- state and nonce correlation checks
- SD-JWT key-binding `aud` and `sd_hash` validation
- DCQL request generation and DCQL-shaped response checks
- mdoc request generation and mdoc response parsing
- encrypted response handling for `direct_post.jwt` and `dc_api.jwt`

The main compliance gaps are:
- the verifier defaults to `x509_san_dns:` client identifiers, while RFC002 requires `x509_hash` for the ETSI-aligned scope
- the request objects do not appear to carry RFC-required ETSI `verifier_info`
- the verifier metadata/config does not publish `verifier_info`-style structured verifier data
- the codebase does not implement the RFC’s `eu-eaap://` same-device ETSI invocation
- the mdoc path does not actually validate ISO `SessionTranscript` / handover binding even though helper code exists
- the mdoc flow does not use `mdoc-openid4vp://`
- some older verifier routes still use legacy/non-DCQL or weaker processing paths

Overall assessment:
- Baseline OpenID4VP verifier: mostly there
- RFC002 verifier compliance: partial to good, depending on track
- SD-JWT VC track: partially aligned, with ETSI-profile gaps
- ISO/IEC 18013-7 remote mdoc track: only partially aligned

## Section-by-Section Review

### 1. Introduction

Assessment: Informational only.

Implementation status:
- The verifier clearly targets OpenID4VP presentation and verification flows across multiple request-generation schemes and response modes [routes/verify/x509Routes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/x509Routes.js:131), [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:228)

### 2. Scope

Assessment: Broadly aligned with verifier-side scope.

Implemented:
- verifier request construction
- verifier-side response validation
- same-device and cross-device flow support
- SD-JWT presentation handling
- mdoc request/response handling

Notes:
- The repo contains several verifier variants and some legacy routes. Not all of them line up equally well with the RFC002 baseline.

### 3. Normative Language

Assessment: Informational only.

### 4. Roles and Components

Assessment: Informational/model section.

Implementation mapping:
- verifier backend behavior is mainly in [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:253), [routes/verify/x509Routes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/x509Routes.js:131), [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1208)

### 5. Protocol Overview

Assessment: Partially aligned.

Implemented:
- signed request-object generation via `buildVpRequestJWT()` [utils/cryptoUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/cryptoUtils.js:313)
- `request_uri`-based invocation URL generation [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1182), [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1327)
- SD-JWT validation paths including nonce, audience, and `sd_hash` [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:1492), [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:1986), [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:1364)
- encrypted response handling for `direct_post.jwt` and `dc_api.jwt` [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:924), [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:656)
- mdoc/DCQL request generation [routes/verify/mdlRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/mdlRoutes.js:61)

Missing/wrong:
- ETSI-aligned `client_id` requirement is not the default. The main x509 verifier config uses `x509_san_dns:${hostname}`, not `x509_hash:...` [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:103).
- `verifier_info` is required by RFC002 for ETSI-aligned requests, but it is not present in the request-object payload construction path [utils/cryptoUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/cryptoUtils.js:313).
- mdoc same-device invocation should use `mdoc-openid4vp://`, but the shared request URL helper emits `openid4vp://` [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1327), including the mdoc route [routes/verify/mdlRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/mdlRoutes.js:61).
- mdoc `SessionTranscript`/handover cryptographic validation is not actually enforced in the mdoc verifier path. Helper code exists, but the active verification path only decodes CBOR and checks extracted claims [utils/mdlVerification.js](/home/ni/code/js/rfc-issuer-v1/utils/mdlVerification.js:1), [utils/mdlVerification.js](/home/ni/code/js/rfc-issuer-v1/utils/mdlVerification.js:248).

### 6. High-Level Flows

#### 6.1 Same-Device Presentation Flow

##### 6.1.1 Presentation Request Creation

Assessment: Mostly aligned.

Implemented:
- request generation stores session-bound `nonce`, `state`, response mode, and either DCQL or presentation definition data [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1094)
- request-object JWT is signed and exposed via `request_uri` endpoints [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1160), [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1208)

Missing/wrong:
- the request-object payload does not carry RFC-required ETSI `verifier_info`
- for ETSI scope, RFC requires `client_id` with `x509_hash`; the main route uses `x509_san_dns`

##### 6.1.2 Wallet Invocation

Assessment: Partial.

Implemented:
- `openid4vp://` invocation URLs with `request_uri` [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1327)
- GET and POST `request_uri_method` variants [routes/verify/x509Routes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/x509Routes.js:143), [routes/verify/x509Routes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/x509Routes.js:184)

Missing/wrong:
- no `eu-eaap://` support found for ETSI authorization-endpoint invocation
- no `mdoc-openid4vp://` support for ISO remote mdoc

##### 6.1.3 Wallet Validation

Assessment: Wallet-side.

No verifier finding.

##### 6.1.4 Holder Consent

Assessment: Wallet-side.

No verifier finding.

##### 6.1.5 Presentation Generation

Assessment: Wallet-side.

No verifier finding.

##### 6.1.6 Presentation Submission

Assessment: Aligned.

Implemented:
- direct post response endpoints for multiple modes [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:253), [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:2298)

##### 6.1.7 Result Handling

Assessment: Broadly aligned.

Implemented:
- success/failure is persisted in session state and returned clearly in many flows [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:1455), [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:1652)

Gap:
- outcome handling is not uniform across all older routes; for example, `/direct_post_jwt/:id` still uses legacy in-memory session arrays rather than the Redis-backed session model [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:2365)

#### 6.2 Cross-Device Presentation Flow

Assessment: Broadly aligned for SD-JWT track.

Implemented:
- QR/deep-link request generation for verifier requests [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1191)

Missing/wrong:
- RFC002 excludes cross-device ISO mdoc. The codebase does not clearly separate the mdoc track from generic invocation mechanics, which risks profile ambiguity.

### 7. Normative Requirements

#### 7.1 Wallet Requirements

Assessment: Wallet-side, not reviewed here.

#### 7.2 Verifier Requirements

Assessment: Partially aligned.

Met:
- OpenID4VP request/response handling is present
- same-device and cross-device non-API-mediated support exists
- requests include anti-replay state and nonce
- response endpoint exists
- received responses are validated before success
- request-response correlation is enforced
- SD-JWT audience and `sd_hash` validation are implemented
- transaction data is stored with session and validated in request construction [utils/cryptoUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/cryptoUtils.js:370)

Missing/wrong:
- `APT-PRES-VER-13` signed request objects: implemented
- `APT-PRES-VER-14` structured verifier metadata including `verifier_info`: not implemented in the request payload path
- ETSI `client_id` prefix requirement is not met by default
- `APT-PRES-VER-MDOC-03` request available via `request_uri`: implemented
- `APT-PRES-VER-MDOC-04` include inputs needed for `SessionTranscript`: partial only
- `APT-PRES-VER-MDOC-10` reconstruct and validate `SessionTranscript`: not implemented in the active mdoc verification logic

### 8. Interface Definitions

#### 8.1 Wallet Invocation Interface

Assessment: Partial.

Implemented:
- `openid4vp://?request_uri=...&client_id=...` deep links [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1327)
- QR generation for these links [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1191)

Missing/wrong:
- RFC002 says `mdoc-openid4vp://` SHALL be used for ISO remote mdoc; not implemented
- RFC002 says `eu-eaap://` SHOULD be supported in ETSI same-device flows; not implemented

#### 8.2 Presentation Request Interface

Assessment: Partially aligned.

Implemented:
- request object includes `client_id`, `nonce`, `state`, `response_mode`, `response_uri`, `aud`, and either `dcql_query` or transaction data [utils/cryptoUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/cryptoUtils.js:313)
- request object is integrity protected with JOSE signing [utils/cryptoUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/cryptoUtils.js:426)
- `x509_hash` is supported by the signing code path when the caller chooses that client ID [utils/cryptoUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/cryptoUtils.js:471)

Missing/wrong:
- main x509 flow does not actually use `x509_hash`; it uses `x509_san_dns` [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:106), [routes/verify/x509Routes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/x509Routes.js:148)
- no `verifier_info` field in generated request objects
- verifier metadata/config does not include structured `verifier_info` registrar/registration data [data/verifier-config.json](/home/ni/code/js/rfc-issuer-v1/data/verifier-config.json:1)
- the RFC allows credential-query parameters; the implementation has standardized on DCQL and explicitly rejects Presentation Exchange input in `buildVpRequestJWT()` [utils/cryptoUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/cryptoUtils.js:358)

#### 8.2.1 Baseline structural requirements

Assessment: Partial.

Met:
- verifier identifier
- response destination
- nonce/state validity context
- request object integrity

Missing:
- user-displayable structured verifier info beyond `client_metadata`
- privacy-policy reference in request payload
- purpose information in `verifier_info`

#### 8.2.2 ETSI-aligned request-object requirements

Assessment: Not compliant as written.

Met:
- signed request object
- `client_metadata` included for non-redirect URI schemes [utils/cryptoUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/cryptoUtils.js:321)

Missing/wrong:
- `client_id` SHALL use `x509_hash` for ETSI-aligned scope, but the main x509 flow uses `x509_san_dns`
- `verifier_info` not included
- registrar/registry/verifier-certificate material not carried in `verifier_info`

#### 8.2.3 Credential-format considerations

Assessment: Mostly aligned.

Implemented:
- SD-JWT/DCQL support
- mdoc/DCQL support
- transaction-data binding for CSC/CS-03 style flows

#### 8.2.3.1 ISO/IEC 18013-7 remote mdoc request requirements

Assessment: Only partially aligned.

Met:
- mdoc request uses DCQL query with `format: "mso_mdoc"` [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:478), [routes/verify/mdlRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/mdlRoutes.js:70)
- request is exposed by `request_uri` [routes/verify/mdlRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/mdlRoutes.js:95)

Missing/wrong:
- no `mdoc-openid4vp://` invocation
- no explicit `verifier_info`
- no real ISO `SessionTranscript` enforcement in validation

#### 8.2.4 Request validation expectations

Assessment: Wallet-side.

No verifier finding.

#### 8.2.5 ISO/IEC 18013-7 session binding

Assessment: Not implemented as required.

Evidence:
- helper to compute session transcript exists [utils/mdlVerification.js](/home/ni/code/js/rfc-issuer-v1/utils/mdlVerification.js:248)
- alternate helper exists in verifier route [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:52)
- active mdoc verification does not reconstruct and verify the transcript; it decodes the `DeviceResponse`, extracts claims, and checks requested fields only [utils/mdlVerification.js](/home/ni/code/js/rfc-issuer-v1/utils/mdlVerification.js:1)
- device nonce extraction is a placeholder returning `null` [utils/mdlVerification.js](/home/ni/code/js/rfc-issuer-v1/utils/mdlVerification.js:266)

#### 8.3 Presentation Response Interface

Assessment: Broadly aligned.

Implemented:
- `direct_post` with `state` and `vp_token`
- `direct_post.jwt` with `response` JWT/JWE parameter
- `dc_api.jwt` handling
- DCQL response-shape checks

#### 8.3.1 Baseline response requirements

Assessment: Mostly aligned.

Implemented:
- state correlation in `direct_post` [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:1492)
- nonce correlation [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:1748)
- audience check for SD-JWT key binding [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:1986)
- only requested claims are accepted in some flows through `hasOnlyAllowedFields()` / `validateMdlClaims()` [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:1434), [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:828)

Gap:
- `/direct_post_jwt/:id` legacy route does not enforce the richer correlation and proof-validation logic used by the main `/direct_post/:id` path [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:2298)

#### 8.3.2 ETSI-aligned response protection

Assessment: Partially aligned.

Implemented:
- encrypted response handling for `direct_post.jwt` JWE [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:924)
- encrypted response handling for `dc_api.jwt` [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:656)
- verifier metadata advertises encryption support [data/verifier-config.json](/home/ni/code/js/rfc-issuer-v1/data/verifier-config.json:21)

Missing/wrong:
- RFC text says encrypted responses are mandatory in ETSI-aligned scope, but verifier request generation still defaults to `direct_post` in several routes [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:114), [routes/verify/x509Routes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/x509Routes.js:137)

#### 8.3.3 Credential-format considerations

Assessment: Mostly aligned for SD-JWT; partial for mdoc.

Met:
- SD-JWT key-binding `aud` and `sd_hash` checks [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:1340), [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:1364)

Gap:
- mdoc validation is structural/claim-based, not full ISO-bound validation.

#### 8.3.3.1 ISO/IEC 18013-7 remote mdoc response requirements

Assessment: Only partially aligned.

Met:
- verifier expects a base64url CBOR-like `vp_token` and decodes it [utils/mdlVerification.js](/home/ni/code/js/rfc-issuer-v1/utils/mdlVerification.js:74)
- document structure and docType presence are checked [utils/mdlVerification.js](/home/ni/code/js/rfc-issuer-v1/utils/mdlVerification.js:96)
- claims are filtered against requested fields [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js:828)

Missing/wrong:
- no actual `DeviceResponse` cryptographic validation against reconstructed `SessionTranscript`
- no handover consistency validation
- no device nonce extraction/validation
- no explicit document type match against the request beyond generic `docType` presence and downstream field checks

#### 8.3.4 Error responses

Assessment: Implemented well enough.

### 8.4 Verifier Metadata Interface

Assessment: Partially aligned.

Implemented:
- local verifier config contains supported formats and encryption keys [data/verifier-config.json](/home/ni/code/js/rfc-issuer-v1/data/verifier-config.json:1)

Missing/wrong:
- no dedicated published verifier metadata interface/endpoint was found
- no published `verifier_info`

### 9. Privacy and Security Considerations

Assessment: Mixed.

Strengths:
- state and nonce are enforced in the main direct-post paths
- SD-JWT `aud` and `sd_hash` are verified
- encrypted responses are supported
- transaction data is bound to session state

Gaps:
- ETSI mandatory encrypted mode is not the default request mode
- mdoc session-binding and replay-resistance are incomplete because `SessionTranscript` is not validated
- older `/direct_post_jwt/:id` path does not apply the same security checks as the main modern path

### 10. Conformance

Assessment:
- SD-JWT verifier conformance: partial
- ISO mdoc verifier conformance: partial, but not enough for a strong RFC002 track claim

Reason:
- several SHALL-level ETSI requirements are missing (`x509_hash`, `verifier_info`, `eu-eaap://`)
- several SHALL-level ISO mdoc requirements are missing (`mdoc-openid4vp://`, `SessionTranscript` reconstruction and validation)

### 11. Wallet-Under-Test Conformance Catalogue and Deployed Test Matrix

Assessment: The current verifier can likely support a large subset of this matrix, especially:
- `VP-CHECK-01`
- `VP-CHECK-05`
- `VP-CHECK-06`
- `VP-CHECK-07`
- `VP-CHECK-08`
- `VP-CHECK-09`
- `VP-CHECK-10`
- `VP-CHECK-12`

Checks at clear risk:
- `VP-CHECK-02` ETSI verifier identification, because default `client_id` is `x509_san_dns`, not `x509_hash`
- `VP-CHECK-04` structured verifier-information processing, because `verifier_info` is not implemented
- `VP-CHECK-11` mdoc `DeviceResponse` validation, because ISO session-binding validation is incomplete
- `VP-CHECK-13` ISO mdoc invocation method, because `mdoc-openid4vp://` is not implemented
- `VP-CHECK-15` ISO `SessionTranscript` binding, because helpers exist but active validation does not enforce it
- `VP-CHECK-17` `eu-eaap://`, not implemented
- `VP-CHECK-18` remote verifier registration information transport, because `verifier_info` is absent

## Missing or Omitted Checks

These are the main verifier-side checks or requirements from RFC002 that are currently omitted or insufficient:

1. Use `x509_hash` as the verifier `client_id` for ETSI-aligned flows by default.
2. Include RFC-required ETSI `verifier_info` in request objects.
3. Carry registrar/registration-certificate material in `verifier_info` when ETSI profile expects it.
4. Publish or expose structured verifier metadata beyond local config files.
5. Support `eu-eaap://` for ETSI same-device authorization-endpoint invocation.
6. Support `mdoc-openid4vp://` for ISO remote mdoc same-device invocation.
7. Reconstruct and validate `SessionTranscript` for mdoc responses.
8. Validate handover consistency for mdoc responses.
9. Extract and validate device nonce / ISO session-binding inputs for mdoc.
10. Make encrypted response modes the default for ETSI-aligned verifier flows if strict profile conformance is the goal.
11. Remove or harden legacy verifier paths that bypass the stronger modern validation stack.
12. Add explicit `verifier_info`/privacy-policy/purpose fields so wallet UX can display transparent verifier context per RFC text.

## Backlog for Alignment Planning

### Critical

1. Switch ETSI-aligned x509 verifier flows from `x509_san_dns` to `x509_hash`.
2. Add `verifier_info` to request objects and populate it from structured config.
3. Implement real ISO mdoc `SessionTranscript` reconstruction and verification.
4. Implement `mdoc-openid4vp://` invocation for ISO remote mdoc.

### High

1. Add `eu-eaap://` support for ETSI same-device flows.
2. Make encrypted response modes the default for ETSI-aligned routes.
3. Unify verifier response handling so legacy `/direct_post_jwt/:id` no longer skips the stronger validation stack.
4. Publish a verifier metadata interface if the deployment profile expects discoverable verifier metadata.

### Medium

1. Add explicit privacy-policy and purpose information into structured verifier request data.
2. Separate “strict RFC002/ETSI mode” from “interop/legacy mode” in routes and docs.
3. Tighten mdoc document-type and requested-element consistency checks against stored request context.

## Bottom Line

The verifier implementation is stronger than the issuer implementation and already enforces several important response-side checks correctly.

If you want a strict summary:
- baseline OpenID4VP verifier: mostly there
- RFC002 SD-JWT verifier compliance: partial, with good foundations
- RFC002 ETSI-aligned verifier compliance: not yet
- RFC002 ISO/IEC 18013-7 remote mdoc verifier compliance: not yet

