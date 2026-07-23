# WE BUILD CS-02 Profile vs FCAF MessageStructure Coverage

This report cross-references the FCAFS MessageStructure analysis in `/home/ni/code/fcafs/message-structure-analysis` with the WE BUILD CS-02 constrained presentation profile in `docs/core/cs-02-credential-presentation (1).md`.

The source FCAFS report is broad: it evaluates verifier and wallet behavior against 236 EC FCAF MessageStructure specs. CS-02 is narrower. It makes OpenID4VP, signed JAR, DCQL, `openid4vp://present`, SD-JWT-VC selective disclosure, ES256/P-256, nonce/audience binding, and Presentation Response validation the relevant target. ISO mdoc remains supported in this repo for practical compatibility. CWT, JSON serialization, OpenID Federation, and broader client identifier variants remain useful interoperability work, but they are not the first WE BUILD CS-02 alignment target.

## WE BUILD CS-02 Target Profile

| Area | CS-02 requirement | Current implementation status |
|---|---|---|
| Request protection | All authorization requests must be signed JARs. | Mostly covered by `wallet-client/src/lib/cs02RequestValidation.js` and `utils/cs02VerifierRequest.js`. |
| Credential query | DCQL must be used. | Covered for strict CS-02 paths by `wallet-client/src/lib/cs02DcqlValidation.js`; verifier generation also validates DCQL. |
| Invocation | Wallet invocation uses `openid4vp://present?request_uri=<URL>`. | Covered; legacy invocation can be gated by compatibility flags. |
| Wallet validation | Wallet validates request signature, nonce freshness, audience, expiry, credential types, disclosure constraints, and integrity. | Much improved; `did:web` exact `kid` enforcement and strict `client_metadata_uri` wiring are covered. Remaining gaps are narrower disclosure/request-integrity edge cases and future remote-metadata fetch hardening. |
| Credential format | SD-JWT-VC selective disclosure is mandatory. | Covered/partial for `dc+sd-jwt` and `vc+sd-jwt`; `mso_mdoc` remains allowed; other formats are compatibility-mode only. |
| Holder binding | KB-JWT is mandatory for SD-JWT VCs and must bind proof to nonce and audience. | Covered for generated wallet responses and verifier checks. |
| Verifier response validation | Verifier validates presentation proof signature, credential authenticity, WUA validity, disclosure integrity, holder binding, nonce/audience binding, and request constraints. | Much improved; verifier now validates response mode, DCQL shape, outer response JWT, KB-JWT claims, `sd_hash`, issuer signatures when local/test key material exists, requested claims after disclosure reconstruction, and status/trust placeholders. Configured issuer trust and future trust-framework enforcement remain incomplete. |
| Verifier metadata | Verifier metadata must be published and match runtime enforcement. | Mostly covered/partial; strict CS-02 metadata is now published through a filtered profile-specific route, while broad deployment metadata remains intentionally available for CS-03/compatibility routes. |

## Updated End-to-End Flow Coverage

```text
Verifier -> Wallet (OpenID4VP / CS-02)
  Verifier creates ES256 signed JAR with DCQL, nonce, state, exp, client_id, response_uri
  -> Wallet is invoked through openid4vp://present?request_uri=...
  -> Wallet fetches request object by GET or POST
  -> Wallet validates JAR header/payload/signature and DCQL before selection
  -> Wallet selects one or more matching credentials, filters SD-JWT disclosures, and creates KB-JWT
  -> Wallet posts vp_token or response JWT/JWE to Presentation Response Endpoint
  -> Verifier validates response mode, state, DCQL response shape, KB-JWT nonce/aud/sd_hash/cnf binding
  -> Verifier invokes issuer-trust and status-list placeholders before success
```

## Current Implementation Improvements

| Capability | Status | Evidence |
|---|---|---|
| `openid4vp://present` invocation | Covered | `parseOpenId4VpDeepLink` is used before request fetch in `wallet-client/src/lib/presentation.js`; strict options come from `resolveCs02ValidationOptions`. |
| Signed request requirement | Mostly covered | `validateCs02JarHeader`, `validateCs02JarPayload`, and `verifyCs02JarSignature` enforce signed JAR behavior in `wallet-client/src/lib/cs02RequestValidation.js`. |
| JAR `typ` and `alg` | Covered for strict CS-02 | `CS02_JAR_TYP` and `CS02_ALLOWED_ALGS` enforce `oauth-authz-req+jwt` and `ES256`. |
| Request URI GET/POST | Covered | `fetchCs02AuthorizationRequestJwt` supports allowed request URI methods and strict content-type policy. |
| HTTPS `request_uri` | Covered with dev override | Strict mode requires HTTPS unless `CS02_ALLOW_HTTP` is enabled. |
| DCQL-only request validation | Covered | `validateCs02PresentationQuery` rejects `presentation_definition`, scope-only queries, combined `scope` + `dcql_query`, and missing `dcql_query` in strict mode. |
| DCQL structural validation | Mostly covered | `validateCs02DcqlQuery` checks non-empty credentials, ids, duplicate ids, formats, `meta`, claim paths, `claim_sets`, `credential_sets`, `multiple`, and holder-binding policy. |
| `trusted_authorities` | Placeholder/advisory | `validateCs02TrustedAuthoritiesPolicy` logs and ignores constraints until a trust registry is configured, matching the current project policy. |
| Multiple credential responses | Covered | `selectWalletCredentialsForDcql` honors `multiple=true`, and `buildCs02VpTokenObject` emits arrays for multi-credential entries. |
| SD-JWT selective disclosure | Covered/partial | Wallet filters disclosures by requested DCQL claim paths; full disclosure integrity is still stronger on holder-binding than on all requested/unsolicited claim edge cases. |
| KB-JWT generation | Covered | Wallet generates KB-JWT with nonce, audience, `iat`, and `sd_hash`; verifier validates those claims. |
| Verifier response mode validation | Covered | `validateCs02ResponseSubmission` rejects bare `vp_token` for `direct_post.jwt`, wrong-mode submissions, missing response, and missing state. |
| DCQL response object validation | Covered | `validateCs02DcqlVpTokenResponse` rejects non-object tokens, unknown ids, missing required ids, wrong credential-set satisfaction, bad arrays, and multiple values unless `multiple=true`. |
| `direct_post.jwt` outer JWT validation | Mostly covered | `verifyCs02OuterResponseJwt` validates signature when a verification key is resolvable and checks `iss`, `aud`, `iat`, `exp`, and `state`. The remaining qualifier is intentional: configured verification-key/trust policy is still profile-dependent. |
| JWE response header validation and decryption-key selection | Covered | `validateCs02JweResponseHeader` checks `alg`, `enc`, and `kid` against metadata, and the verifier decrypts with the advertised response-encryption private key rather than the verifier signing key. `tests/verifierEncryptionKeys.test.js` covers the positive path and wrong-key regression. |
| Status-list validation | Placeholder covered | `validateCs02CredentialStatusList` decodes SD-JWT issuer payload and validates `status.status_list.idx` plus HTTPS absolute `uri`; missing status is allowed unless strict status validation is enabled. |
| Trust policy | Placeholder covered | `utils/cs02TrustPolicy.js` centralizes x509, verifier-attestation, DID, metadata, issuer-trust, and status policy placeholders. |
| Metadata filtering | Mostly covered/partial | `filterClientMetadataForCs02Enforcement` filters CS-02 request-time metadata, and `routes/metadataroutes.js` now publishes explicit strict `/client-metadata/cs02` and broad `/client-metadata` or `/client-metadata/cs03` views from the same deployment config. The remaining risk is route-by-route audit pressure so strict flows never accidentally consume the broad projection. |

## Coverage Table: FCAF Specs Filtered By CS-02

Legend:

| Mark | Meaning |
|---|---|
| Yes | Covered for the WE BUILD CS-02 profile |
| Partial | Some CS-02 behavior exists, but validation is incomplete, placeholder-only, or route-dependent |
| Missing | Required by CS-02 but not implemented |
| Out of scope | FCAF coverage target is broader than current CS-02 |

### ProtocolMessages: Authorization Request / JAR (PM 002-011)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| Plain unsigned request (PM 002) | CS-02 forbids unsigned requests | Yes | Strict wallet validation rejects unsigned/malformed JARs and `alg=none`. |
| `typ=oauth-authz-req+jwt` handling (PM 004, 006-007) | Required in practice | Yes | `validateCs02JarHeader` requires the CS-02 JAR typ. |
| Request object by reference (PM 005) | Required | Yes | `openid4vp://present?request_uri=...` and GET/POST retrieval are supported. |
| `client_id` present and request/JAR consistency (PM 008-010) | Required | Yes | Payload requires `client_id`; deep-link `client_id`, when present, must match the signed JAR. |
| `request_uri_method=post` (PM 011) | Useful and supported | Yes | Wallet sends form-encoded POST and rejects unsupported methods in strict mode. |

### ProtocolMessages: DCQL Top-Level (PM 012-021)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| DCQL used instead of PEX/scope | Required | Yes | Strict mode rejects `presentation_definition`, scope-only requests, and combined `dcql_query` + `scope`. |
| One or more matching credentials | Required | Yes/partial | Wallet can select one or multiple matching credentials; optional credential-set semantics are implemented for current cases. |
| No credential satisfies query | Required | Yes | Wallet fails with access-denied style behavior instead of falling back to unrelated credentials. |
| Malformed DCQL rejected | Required | Mostly yes | Structural validation covers ids, formats, claims, `claim_sets`, `credential_sets`, `multiple`, and holder-binding policy. |
| Unknown params ignored | Required by broader OpenID4VP | Partial | The CS-02 subset validates required structure but does not implement a full unknown-parameter negative matrix. |
| `transaction_data` support | Optional/profile-specific | Partial | Existing checks cover encoded `credential_ids` in generation and wallet fatal errors for malformed transaction data; full FCAF matrix remains incomplete. |
| Mutual exclusivity of `dcql_query` and `scope` | Required by FCAF | Yes | `validateCs02PresentationQuery` rejects both being present. |

### ProtocolMessages: Request URI / Retrieval / Request Object (PM 022-051)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| GET/POST `request_uri` | Required | Yes | Wallet supports both allowed methods. |
| HTTPS-only `request_uri` | Required for production security | Yes | Strict mode requires HTTPS unless local dev override is configured. |
| Request URI response content type | FCAF negative tests | Yes/partial | Strict fetch checks for `application/oauth-authz-req+jwt`; compatibility behavior may still differ outside CS-02 mode. |
| UTF-8/form POST | Required for POST method | Yes | Wallet sends form content for POST retrieval. |
| Nonce and expiry in request object | Required | Yes | Payload validation requires `nonce`, `iat`, `exp`, and request lifetime limits. |
| Audience matches wallet policy | Required by CS-02 WU validation | Yes/partial | Default wallet audience policy accepts `https://self-issued.me/v2` until a wallet-specific audience is configured. |
| `client_id` query/JWT mismatch | Required | Yes | Deep-link and signed JAR `client_id` contradictions are rejected. |
| Query vs signed JAR precedence | Required | Partial | `validateCs02RequestUriQueryPrecedence` catches contradictions for mapped fields; not every possible query parameter is modeled. |

### ProtocolMessages: DCQL credentials / credential_sets / claims (PM 052-123)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| `credentials` array exists and is non-empty | Required | Yes | Strict validator rejects missing or empty credentials. |
| Credential query `id` validation | Required | Yes | Non-empty id, allowed charset, and duplicate-id checks are enforced. |
| `format` validation | Required | Yes | Strict mode allows `dc+sd-jwt`, `vc+sd-jwt`, and project-scoped `mso_mdoc`; other formats are compatibility-mode only. |
| `multiple` | Required when requested | Yes | Wallet can return arrays for `multiple=true`; verifier validates array shape and rejects extra multiples otherwise. |
| `meta` matching | Required for credential selection | Mostly yes | SD-JWT `vct_values` and mdoc `doctype_value` are validated. More format-specific meta constraints may still be future work. |
| `trusted_authorities` | Relevant to high assurance | Partial / placeholder | Accepted as advisory and logged until a trust registry is configured. |
| `require_cryptographic_holder_binding` | Relevant to CS-02 | Yes | Strict mode rejects `false` for SD-JWT-VC because KB-JWT is mandatory. |
| Claim paths and claim_sets | Required for disclosure constraints | Partial | The validator enforces non-empty string path segments, duplicate claim ids, and `claim_sets` references. Enforced runtime support now covers SD-JWT claim-path presence for current string-segment paths, including nested object paths and dotted disclosure-key matches, plus SD-JWT `claim_sets` and exact string `values` for that subset. Nested mdoc claim paths, `claim_sets`, and exact string `values` are also enforced. Broader DCQL path grammar remains incomplete. |
| `credential_sets` | Relevant when used | Mostly yes | Non-empty options and unknown id references are rejected; verifier validates satisfied required sets. |

### ProtocolMessages: Authorization Response (PM 124-159)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| direct_post response | Required | Yes | Verifier requires `vp_token` and `state` for direct_post. |
| direct_post.jwt / encrypted response | Useful, profile-adjacent | Yes for the implemented strict path | Verifier requires `response`, validates JWE headers, selects the metadata-advertised response-encryption key, decrypts the compact JWE, and verifies signed response JWT claims/signature when key material is resolvable. Broader trust-policy variants remain profile-dependent. |
| `vp_token` DCQL object shape | Required with DCQL | Yes | Verifier rejects non-object, unknown ids, missing required ids, and invalid value cardinality. |
| `transaction_data` reference in credential presentation | Optional/profile-specific | Partial | Some validation exists, but full FCAF error matrix is not covered. |
| Wallet error response handling | Required robustness | Yes/partial | Verifier stores failed session state and returns wallet-reported protocol errors for covered response paths. |
| Unsupported response modes / scopes / formats | Required negative tests | Mostly yes | Request generation and wallet validation reject unsupported CS-02 modes/formats; `dc_api` and `dc_api.jwt` remain supported for expected future CS-02 expansion. |

### Metadata: Status Claims (M 081-103) and CredentialFormats status (CF 029-031, 049)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| JOSE `status` / `status_list` validation | Important for credential authenticity/revocation | Partial / placeholder | `utils/cs02StatusList.js` validates malformed references (`idx`, HTTPS absolute `uri`) and is invoked by verifier SD-JWT checks. Fetch, signature validation, bitstring decoding, and revoked/suspended decisions are TODOs until trust framework exists. |
| Missing status behavior | Local policy | Yes / placeholder | Missing status is allowed by default and rejected only when `CS02_STRICT_STATUS_VALIDATION` is enabled. |
| COSE status claims | Out of core CS-02 SD-JWT target | Out of scope / partial for mdoc | mdoc remains supported, but COSE status-list validation is not part of the current CS-02 SD-JWT alignment work. |

### Metadata: client_metadata and Client Identifier Schemes (M 104-141)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| Verifier metadata publication | Required | Mostly yes / partial | The deployment now publishes a strict CS-02 verifier metadata view at `/client-metadata/cs02` and preserves explicit broad or CS-03 views at `/client-metadata` and `/client-metadata/cs03`. `data/verifier-config.json` remains the broad capability source by design, so the remaining work is ensuring every strict CS-02 route consumes the filtered projection rather than the broad source directly. |
| `client_metadata` parsing and precedence | Required | Yes / partial | Inline and remote metadata are validated in strict mode, HTTPS `client_metadata_uri` is enforced, and inline metadata takes precedence. Remaining follow-up is fetch timeout/max-size hardening. |
| `x509_san_dns` | Required/recommended in CS-02 | Partial / intentional placeholder | Wallet verifies with x5c leaf key. Chain trust and SAN DNS match are intentionally skipped until trust anchors are configured, with placeholder methods left in place. |
| `verifier_attestation` | Recommended/allowed in CS-02 | Partial / intentional placeholder | JOSE header `jwt` is required in the wallet path, but issuer trust, `sub`, expiry, and signing-key binding are placeholders until trusted issuers are configured. |
| `did:web` / `did:jwk` | Recommended by CS-02 | Yes | `did:jwk` enforces P-256/ES256 key material through the shared trust policy. `did:web` resolves over HTTPS, requires an exact `kid`, and rejects fallback to unrelated verification methods. |
| `openid_federation`, `x509_hash`, `origin:` | Broader FCAF | Out of scope / partial | Not core CS-02; useful for broader FCAF but lower WE BUILD priority. |
| Wallet metadata encryption | Useful | Mostly yes | Request/response encryption exists, strict metadata distinguishes `direct_post` from `direct_post.jwt`, and the direct-post path now uses the same selected response-encryption-key model as `dc_api.jwt`. Remaining work is broader route-surface audit coverage. |

### CredentialFormats (CF 029-049)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| SD-JWT-VC compact with KB-JWT | Required | Mostly yes | Wallet appends KB-JWT; verifier checks `typ`, nonce, audience, `iat`, `sd_hash`, `cnf.jwk` signature binding, issuer signature when local/test key material exists, requested claims, and unsolicited disclosure rejection in strict mode. Configured issuer trust remains placeholder-level. |
| SD-JWT-VC compact without KB-JWT | Negative case for CS-02 | Yes | Verifier strict SD-JWT presentation validation rejects missing KB-JWT. |
| JWT VC / JWT VP | Not primary CS-02 | Compatibility only | These are not allowed in strict CS-02 DCQL format validation. |
| ISO mdoc | Practical project scope | Partial | `mso_mdoc` remains allowed and supported; broader mdoc/COSE/FCAF coverage is not complete. |
| CWT, JSON serialization, multiple mdocs | Broader FCAF | Out of scope | These remain FCAF gaps but are not WE BUILD CS-02 blockers. |

## Remaining CS-02-Critical Gaps

| Priority | Gap | Why it matters for WE BUILD CS-02 |
|---|---|---|
| High | Full credential authenticity remains incomplete. | The verifier now validates issuer signatures when local/test key material exists, but configured issuer trust and trust-framework-backed authenticity are still intentionally placeholder-only. |
| High | Metadata consistency is incomplete. | Strict request-time metadata filtering is in place and strict CS-02 metadata is now published on a dedicated route, but continued auditing is still needed so compatibility metadata cannot leak into strict CS-02 request generation or other strict surfaces. |
| Major | Status/revocation is placeholder-only. | Malformed status-list references are rejected, but status-list token fetch, signature validation, bitstring decoding, and revoked/suspended decisions wait on the trust framework. |
| Major | Production trust policy is intentionally deferred. | x509 chain/SAN validation and verifier-attestation trusted issuer validation are intentionally skipped until trust anchors/trusted issuers exist. |
| Major | Full disclosure/request-constraint validation still needs hardening. | DCQL structure, requested-claim checks, nested supported-path enforcement, and unsolicited disclosure rejection are stronger now, but wallet-side minimization, broader DCQL path grammar beyond the supported subset, broader value semantics, and more FCAF negative cases are not complete. |
| Major | Consent is out of scope in runtime and must stay documented as such. | `wallet-client` is a headless test wallet. Production wrappers still need their own UI/API consent gate and safe consent logging. |

## FCAF Gaps That Are Lower Priority For WE BUILD CS-02

| FCAF area | Reason |
|---|---|
| Plain unsigned authorization request support | CS-02 requires signed requests and wallets must reject unsigned requests. |
| COSE status and multiple mdoc DeviceResponses | mdoc is supported for project compatibility, but CS-02 alignment is focused on SD-JWT-VC. |
| CWT referenced tokens | Not part of the CS-02 SD-JWT-VC target. |
| JSON serialization credentials | Not part of the CS-02 compact SD-JWT-VC target. |
| OpenID Federation | Useful for broader HAIP/FCAF, but current work uses x509/verifier_attestation placeholders and DID schemes. |
| `redirect_uri` unsigned/client-id scheme behavior | CS-02 emphasizes signed JAR and high-assurance schemes. Redirect URI scheme may remain compatibility behavior but should not drive WE BUILD conformance. |

## Profile-Adjusted Coverage Summary

| Layer | WE BUILD relevance | Coverage |
|---|---|---|
| Signed JAR request creation | Required | Mostly covered: ES256/P-256 request generation exists for CS-02 paths; trust-anchor-backed x509 policy is placeholder. |
| Wallet JAR validation | Required | Mostly covered: strict `typ`, `alg`, required fields, lifetime, audience policy, HTTPS request URI, signature verification, query precedence, exact `did:web` `kid` binding, and strict `client_metadata_uri` policy are in place. |
| `openid4vp://present` request URI invocation | Required | Covered. |
| DCQL query and response shape | Required | Mostly covered: structure, ids, formats, claim paths, claim_sets, credential_sets, multiple, and response object shape are validated. |
| SD-JWT-VC selective disclosure | Required | Partial/covered for the supported subsets; current SD-JWT string-segment claim-path presence, dotted disclosure-key matching, `claim_sets`, and exact string `values` constraints are now enforced, and nested mdoc claim-path / `claim_sets` / exact string `values` constraints are also enforced. Broader path/value semantics remain follow-up work. |
| KB-JWT holder binding | Required | Covered for generated wallet responses and verifier checks. |
| Verifier nonce/audience/request-constraint checks | Required | Mostly covered for response mode, state, nonce, audience, DCQL response shape, and KB-JWT; issuer trust and disclosure authenticity remain partial. |
| Credential authenticity and status | Required by verifier validation intent | Partial: KB-JWT/cnf binding and status reference placeholders exist; issuer signature/trust and revocation decisions remain TODO until trust framework exists. |
| Verifier metadata | Required | Mostly covered/partial: inline metadata filtering/validation exists, and strict/public metadata publication is now profile-separated. Remaining work is making sure every strict route consistently uses the strict projection. |
| Holder consent | Required | Out of scope in this repo | `wallet-client` is a headless test wallet; production wrappers must implement consent before calling the presentation flow. |

## Recommended Remediation Order

1. Finish the remaining strict metadata-consumption audit so compatibility/static metadata cannot leak unsupported formats or algorithms into strict CS-02 routes.
2. Extend SD-JWT-VC issuer authenticity from local/test key verification to configured issuer trust once the trust framework exists.
3. Keep status-list validation as placeholder until trust framework exists, then add fetch/cache/timeout/max-size policy, token signature validation, bitstring decoding, and revoked/suspended decisions.
4. When trust anchors/trusted attestation issuers exist, implement x509 chain/SAN DNS enforcement and verifier-attestation issuer/sub/expiry/signing-key binding validation in the placeholder methods.
5. Harden remaining disclosure/request-constraint checks: wallet-side minimization, broader DCQL path grammar beyond the supported subset, broader value semantics, credential-set strictness, and more negative tests.
6. Keep holder consent documented as external to this headless test wallet and require production wrappers to implement the consent gate.

## Bottom Line

Against the original broad FCAFS report, this repo still does not cover the full 236-spec MessageStructure surface. Against the narrower WE BUILD CS-02 profile, the implementation is now substantially closer than the original report indicated: strict wallet request validation, DCQL validation, multi-credential response generation, verifier response validation, KB-JWT checks, status-list placeholders, and shared trust/metadata policy are in place.

The auditable disposition register in
`FCAFs/we-build-cs02-disposition-overrides.json` currently contains 301
evidence-backed source-row mappings: 190 implemented, 0 partial, 38
structural-only, and 72 explicitly inapplicable to strict CS-02, plus one
out-of-scope datamodel row. The available
catalogues contain 301 explicit rows (222 MessageStructure and 79
SecurityMechanisms); no explicit catalogue rows remain unclassified. The
source MessageStructure heading claims 236 rows, but 14 of those rows are not
present as explicit table entries and remain a catalogue-reconciliation item.

The generated per-layer view is: MessageStructure 156 implemented, 0 partial,
14 structural-only, 47 inapplicable, and one datamodel-deferred row (222 explicit rows);
SecurityMechanisms 34 implemented, 22 structural-only, 23 inapplicable, and no unclassified rows
(79 explicit rows).

No applicable strict CS-02 FCAF row remains partial in the disposition register. The
remaining work is deliberately outside this increment: trust-anchor and issuer
trust decisions, status-list retrieval/evaluation, PID/data-model rules,
interactive consent/authentication UX, and broader compatibility profiles.
