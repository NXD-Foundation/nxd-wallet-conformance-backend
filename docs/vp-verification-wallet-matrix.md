# OpenID4VP Verifier Flow Matrix

This note summarizes what the verifier flows in this repo support and what they actually enforce at runtime.

Primary entry points:

- standardized verifier request API: [routes/verify/vpStandardRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/vpStandardRoutes.js#L55)
- core verification response handler: [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js#L240)
- VP request generation utility: [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js#L757)
- VP request JWT builder: [utils/cryptoUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/cryptoUtils.js#L220)
- verifier metadata/config used in requests: [data/verifier-config.json](/home/ni/code/js/rfc-issuer-v1/data/verifier-config.json#L1)

## Scope

This doc covers the active verification flows exposed through:

- `/vp/request`
- `/vp/x509VPrequest/:id`
- `/vp/didVPrequest/:id`
- `/vp/didJwkVPrequest/:id`
- `/direct_post/:id`

It also notes the attestation-specific verifier variant as an alternative family, but the main matrix below is centered on the standard verifier flows.

## Summary Matrix

| Dimension | Supported in This Repo | Enforced at Runtime |
|---|---|---|
| Client ID Scheme | `x509`, `did:web`, `did:jwk` via `/vp/request` | invalid scheme rejected at request generation |
| Request URI Method | `get`, `post` | request URL is generated accordingly |
| Response Mode | `direct_post`, `direct_post.jwt`, `dc_api.jwt`, `dc_api` in JWT builder | invalid `response_mode` rejected by request builder |
| Credential Query Style | DCQL is supported; presentation-definition-based legacy paths still exist in code | JWT builder rejects `presentation_definition` and requires DCQL for OpenID4VP 1.0 |
| Credential Formats Advertised | `jwt_vc_json`, `dc+sd-jwt`, `mso_mdoc` | response validation branches exist for SD-JWT/JWT and mdoc |
| Transaction Data | supported | `credential_ids` are validated against DCQL credential ids when transaction data is present |
| Encrypted Wallet Responses | supported for `direct_post.jwt` and `dc_api.jwt` | decrypt path enforced when encrypted response is received |
| Wallet Metadata | supported on request URI endpoints | request object may be encrypted using wallet-provided `wallet_metadata.jwks` |
| direct_post State Check | supported | required and checked for regular `direct_post` |
| direct_post.jwt Nonce Check | supported | required and checked |
| SD-JWT Key Binding | supported | nonce, `aud`, and `sd_hash` checks enforced when key-binding JWT is present |
| DCQL Response Shape | supported | object shape enforced for DCQL responses |
| mdoc Verification | supported | token structure and requested-claim matching enforced |
| Wallet Error Surface | supported | wallet-reported `error` is surfaced back to caller |

## Configuration Matrix

| Dimension | Typical Baseline | Other Variants Supported |
|---|---|---|
| Request Entry | `/vp/request` | legacy route families under `/verify/x509`, `/verify/did`, `/verify/did-jwk`, verifier attestation routes |
| Client ID Scheme | `x509` | `did:web`, `did:jwk` |
| Request Transport | `openid4vp://?request_uri=...` | GET or POST `request_uri_method` |
| Query Model | `dcql` | `tx`, `mdl`; legacy PEX-style code still present upstream |
| Credential Profile | `pid` | `mdl` |
| Response Mode | `direct_post` | `direct_post.jwt`, `dc_api.jwt`, `dc_api` |
| Credential Type Handling | SD-JWT / JWT VC | `mso_mdoc` branch |
| Request Object Protection | signed JAR | encrypted to wallet key when `wallet_metadata.jwks` is supplied |
| Transaction Data | absent | present and bound to DCQL credential ids |

## What The Verifier Actually Supports

From the current codebase, the verifier can generate and process:

- OpenID4VP deep links using `request_uri`
- X.509 verifier identifiers
- `did:web` verifier identifiers
- `did:jwk` verifier identifiers
- `direct_post` responses
- `direct_post.jwt` responses
- HAIP-style `dc_api.jwt` responses
- DCQL request objects
- SD-JWT presentation processing
- JWT VC / JWT VP style processing
- mdoc presentation processing
- transaction data requests
- encrypted authorization responses using verifier encryption metadata from [data/verifier-config.json](/home/ni/code/js/rfc-issuer-v1/data/verifier-config.json#L20)

The main generation path is assembled in:

- [routes/verify/vpStandardRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/vpStandardRoutes.js#L55)
- [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js#L757)
- [utils/cryptoUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/cryptoUtils.js#L244)

## What The Verifier Actually Enforces

The main runtime checks currently enforced are:

- unsupported `client_id_scheme` is rejected at request generation
- unsupported `response_mode` is rejected at JWT build time
- `presentation_definition` is rejected by the JWT builder for OpenID4VP 1.0 flows
- when DCQL is used, `vp_token` must be a JSON object, not a bare string
- for DCQL, object shape must be non-null and non-array
- for mdoc flows, `vp_token` must be present and mdoc verification must succeed
- for mdoc flows, extracted claims must match requested claims when selective disclosure was requested
- for `direct_post`, `state` must be present and must match the stored session
- for `direct_post` and `direct_post.jwt`, a nonce must be recoverable from the presentation or key-binding context
- submitted nonce must match the stored verifier session nonce
- if a key-binding JWT is present, `aud` must match verifier `client_id`
- if a key-binding JWT is present for SD-JWT, `sd_hash` must be present
- if `sd_hash` is present, it must match the presented SD-JWT
- if requested claims are narrower than presented claims, claim-set mismatch is rejected

Key enforcement points:

- DCQL response object validation: [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js#L282)
- mdoc verification and claim matching: [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js#L405)
- `direct_post.jwt` response extraction, nonce, audience, and `sd_hash`: [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js#L782)
- `direct_post` state, nonce, and audience checks: [routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js#L1371)

## Wallet Checks Needed To Interoperate

A wallet unit interacting with these verifier flows should implement:

1. Resolve `request_uri` and process an `openid4vp://` deep link.
2. Support verifier identifiers based on `x509`, `did:web`, and `did:jwk`.
3. Support request objects that use DCQL.
4. Support `direct_post` response mode.
5. Support `direct_post.jwt` response mode.
6. Support encrypted `direct_post.jwt` and `dc_api.jwt` responses when verifier metadata includes encryption keys.
7. Preserve and return `state` for `direct_post`.
8. Preserve and satisfy verifier `nonce`.
9. For SD-JWT presentations, include a key-binding JWT with correct `nonce`.
10. For SD-JWT presentations, set key-binding `aud` to the verifier `client_id`.
11. For SD-JWT presentations, include correct `sd_hash`.
12. For DCQL responses, return `vp_token` as an object keyed by credential query ids, not a bare string.
13. For mdoc responses, return a verifiable mdoc token in the structure expected by the DCQL or mdoc branches.
14. Handle `wallet_metadata` driven encryption and request customization if interacting through request URI endpoints that accept it.

## Important Gaps Between Supported and Enforced

These are the main repo-specific gaps and inconsistencies:

- The standardized endpoint in [routes/verify/vpStandardRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/vpStandardRoutes.js#L75) still tries to load `presentation_definition` files for some profiles, but the actual JWT builder rejects `presentation_definition` and says to use DCQL only ([utils/cryptoUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/cryptoUtils.js#L325)).
- DCQL object keys are only warned about when expected credential ids are missing; that condition is not currently fatal ([routes/verify/verifierRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/verify/verifierRoutes.js#L373)).
- For `direct_post.jwt`, the code decodes payloads and decrypts JWE, but it does not appear to perform full cryptographic verification of the outer response JWT signature before extracting claims.
- The verifier supports wallet metadata driven encryption, but whether it is used depends on the wallet supplying `wallet_metadata.jwks` at the request URI step.
- Legacy verifier route families and verifier attestation routes coexist with the standardized endpoint, so “supported” is broader than the standardized V1.0 path alone.

## Practical Test Matrix

If you want to turn verifier behavior into a wallet interoperability matrix, the minimum rows should cover:

| Dimension | Test Rows |
|---|---|
| Client ID Scheme | `x509`, `did:web`, `did:jwk` |
| Query Model | DCQL PID, DCQL mdoc, transaction-data DCQL |
| Response Mode | `direct_post`, `direct_post.jwt`, `dc_api.jwt` |
| Request URI Method | GET, POST |
| Credential Format | `dc+sd-jwt`, `jwt_vc_json`, `mso_mdoc` |
| Response Protection | plaintext JWT, encrypted JWE |
| SD-JWT Binding | with valid KB-JWT, missing nonce, wrong `aud`, wrong `sd_hash` |
| Correlation | correct `state`, missing `state`, wrong `state`, wrong `nonce` |

## Recommended Single-Line Description

OpenID4VP verifier supporting X.509 and DID client identification, DCQL-based request objects, `direct_post` and JWT-based response modes, SD-JWT key-binding checks, mdoc verification, transaction-data requests, and encrypted wallet responses, with strict nonce/state validation and partial gaps between legacy request-generation code and V1.0-only DCQL enforcement.
