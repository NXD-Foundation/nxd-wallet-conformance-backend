# WE BUILD CS-02 Profile vs FCAF MessageStructure Coverage

This report cross-references the FCAFS MessageStructure analysis in `/home/ni/code/fcafs/message-structure-analysis` with the WE BUILD CS-02 constrained presentation profile in `docs/core/cs-02-credential-presentation (1).md`.

The source FCAFS report is broad: it evaluates verifier and wallet behavior against 236 EC FCAF MessageStructure specs. CS-02 is narrower. It makes OpenID4VP, signed JAR, DCQL, `openid4vp://present`, SD-JWT-VC selective disclosure, ES256/P-256, nonce/audience binding, and Presentation Response validation the relevant target. ISO mdoc, CWT, JSON serialization, OpenID Federation, and some broader FCAF client identifier variants are useful interoperability capabilities, but they are not the core WE BUILD CS-02 target.

## WE BUILD CS-02 Target Profile

CS-02 requires:

| Area | CS-02 requirement | Local reference |
|---|---|---|
| Request protection | All authorization requests must be signed JARs. | `docs/core/cs-02-credential-presentation (1).md:99`, `:128`, `:136`, `:269` |
| Credential query | DCQL must be used. | `docs/core/cs-02-credential-presentation (1).md:102` |
| Invocation | Wallet invocation uses `openid4vp://present?request_uri=<URL>`. | `docs/core/cs-02-credential-presentation (1).md:140` |
| Wallet validation | Wallet validates request signature, nonce freshness, audience, expiry, credential types, disclosure constraints, and integrity. | `docs/core/cs-02-credential-presentation (1).md:150` |
| Credential format | SD-JWT-VC selective disclosure is mandatory. | `docs/core/cs-02-credential-presentation (1).md:177`, `:251` |
| Holder binding | KB-JWT is mandatory for SD-JWT VCs and must bind proof to nonce and audience. | `docs/core/cs-02-credential-presentation (1).md:105`, `:179`, `:254` |
| Verifier response validation | Verifier validates presentation proof signature, credential authenticity, WUA validity, disclosure integrity, holder binding, nonce/audience binding, and request constraints. | `docs/core/cs-02-credential-presentation (1).md:271` |
| Verifier metadata | Verifier metadata must be published. | `docs/core/cs-02-credential-presentation (1).md:282`, `:284` |

## Updated End-to-End Flow Coverage

```
Verifier -> Wallet (OpenID4VP / CS-02)
  Verifier creates signed JAR with DCQL, nonce, state, exp, client_id, response_uri
  -> Wallet is invoked through openid4vp://present?request_uri=...
  -> Wallet fetches request object by GET or POST
  -> Wallet verifies signed request object and selects credential using DCQL
  -> Wallet filters SD-JWT disclosures and creates KB-JWT
  -> Wallet posts vp_token to Presentation Response Endpoint
  -> Verifier checks state, nonce, audience, sd_hash, cnf-bound KB-JWT, and requested claims
```

The current repo has improved over the older merged FCAFS report in several CS-02-critical areas:

| Capability | Status | Evidence |
|---|---|---|
| `openid4vp://present` invocation | Covered | Wallet parser accepts `present` authority and rejects other non-empty authorities in `wallet-client/src/lib/presentation.js:104`. |
| Signed request requirement | Mostly covered | Wallet rejects `alg=none` and verifies JARs using x5c, metadata JWKS/JWKS URI, or DID material in `wallet-client/src/lib/presentation.js:244`. Verifier signs x509 and DID request objects in `utils/cryptoUtils.js:486` and `:572`. |
| DCQL-only request generation | Covered in builder | Builder rejects `presentation_definition` and emits `dcql_query` in `utils/cryptoUtils.js:418`. |
| Request URI GET/POST | Covered | Wallet fetches request object with GET or POST in `wallet-client/src/lib/presentation.js:126`. |
| Transaction data binding to DCQL ids | Covered/partial | Verifier validates encoded `credential_ids` when parseable in `utils/cryptoUtils.js:430`; wallet treats invalid transaction data as fatal in `wallet-client/src/lib/presentation.js:560`. |
| SD-JWT selective disclosure | Covered/partial | Wallet filters disclosures by DCQL claim paths in `wallet-client/src/lib/presentation.js:828` and `wallet-client/src/lib/sdJwtDisclosureSelection.js`. This is functional but not full DCQL structural validation. |
| KB-JWT generation | Covered | Wallet resolves holder key material and creates KB-JWT with nonce, audience, and `sd_hash` in `wallet-client/src/lib/presentation.js:840`. |
| DCQL response object | Covered for selected credential | Wallet returns `vp_token` as object keyed by DCQL credential id in `wallet-client/src/lib/presentation.js:1019`. |
| Verifier nonce/audience/key-binding checks | Covered/partial | Verifier checks nonce, audience, `sd_hash`, and `cnf.jwk` signature binding in `routes/verify/verifierRoutes.js` and `utils/sdJwtKeyBinding.js`. |
| Verifier response JWT signature validation | Missing/partial | Existing docs still note that `direct_post.jwt` unencrypted responses are decoded before full outer response JWT signature verification. |

## Coverage Table: FCAF Specs Filtered By CS-02

Legend:

| Mark | Meaning |
|---|---|
| Yes | Covered for the WE BUILD CS-02 profile |
| Partial | Some CS-02 behavior exists, but validation is incomplete or route-dependent |
| Missing | Required by CS-02 but not fully implemented |
| Out of scope | FCAF coverage target is broader than current CS-02 |

### ProtocolMessages: Authorization Request / JAR (PM 002-011)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| Plain unsigned request (PM 002) | Not required; CS-02 forbids unsigned requests | Out of scope | CS-02 requires signed request objects. Wallet rejects `alg=none`. |
| `typ=oauth-authz-req+jwt` handling (PM 004, 006-007) | Required in practice | Partial | Verifier sets `typ`. Wallet verifies signatures, but no strict `typ` allowlist was found in the wallet verifier path. |
| Request object by reference (PM 005) | Required for CS-02 invocation | Yes | `openid4vp://present?request_uri=...` is supported. |
| `client_id` present and request/JAR consistency (PM 008-010) | Required | Partial | Wallet checks deep-link `client_id` mismatch if present, but the path does not clearly reject a request JWT missing `client_id`. |
| `request_uri_method=post` (PM 011) | Useful and supported | Yes | Wallet fetches via POST with form content type. |

### ProtocolMessages: DCQL Top-Level (PM 012-021)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| DCQL used instead of PEX/scope | Required | Yes | Request builder rejects `presentation_definition` and uses `dcql_query`. |
| One or more matching credentials | Required | Partial | Wallet selects a single matching credential. Multiple credential response is not complete. |
| No credential satisfies query | Required | Yes | Wallet fails when no stored credential matches format/meta constraints. |
| Malformed DCQL rejected | Required | Partial | Missing/empty `credentials` is rejected by selection failure; deeper structure validation is incomplete. |
| Unknown params ignored | Required by broader OpenID4VP | Partial | Not a strict schema parser; unknown params are effectively ignored in many paths. |
| `transaction_data` support | Optional/profile-specific | Partial | Implemented where present, but malformed base64 transaction data is not always rejected by the verifier builder. |
| Mutual exclusivity of `dcql_query` and `scope` | Required by FCAF | Missing | No clear wallet rejection for both being present. CS-02 uses DCQL, so this matters mostly for negative tests. |

### ProtocolMessages: Request URI / Retrieval / Request Object (PM 022-051)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| GET/POST `request_uri` | Required | Yes | Wallet supports both. |
| HTTPS-only `request_uri` | Required for production security | Missing/partial | Wallet fetch path does not visibly enforce HTTPS before `fetch`. |
| Request URI response content type | FCAF negative tests | Missing | Wallet reads body text and does not enforce `application/oauth-authz-req+jwt`. |
| UTF-8/form POST | Required for POST method | Yes | Wallet sends `application/x-www-form-urlencoded`. |
| Nonce and expiry in request object | Required | Partial | Verifier includes `nonce`, `iat`, `exp`; wallet requires `nonce` but relies on JWT library clock checks and does not separately model nonce freshness. |
| Audience matches wallet | Required by CS-02 WU validation | Missing/unclear | Request JWT `aud` is hard-coded to `https://self-issued.me/v2` in builder; wallet does not visibly validate that audience matches a wallet identifier. |
| `client_id` query/JWT mismatch | Required | Yes when deep link contains client_id | Wallet rejects mismatch between deep-link `client_id` and request JWT `client_id`. |

### ProtocolMessages: DCQL credentials / credential_sets / claims (PM 052-123)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| `credentials` array exists and is non-empty | Required | Partial | Wallet requires an array to select; structural errors become selection failures rather than precise protocol validation. |
| Credential query `id` validation | Required for DCQL response shape | Partial | Wallet uses `id` when present; it does not fully enforce type, charset, uniqueness, or missing-id rejection. |
| `format` validation | Required | Partial | Wallet supports `dc+sd-jwt`, `vc+sd-jwt`, `mso_mdoc`, `jwt_vc_json`; unsupported formats fail matching. No full OID4VP Appendix B validation. |
| `multiple` | FCAF broader behavior | Partial | Response builder treats `multiple=true` and false the same for the selected credential. |
| `meta` matching | Required for credential selection | Partial | Supports SD-JWT `vct_values` and mdoc `doctype_value`; no full format-specific `meta` schema validation. |
| `trusted_authorities` | Relevant to high assurance | Missing | No evidence of wallet-side trusted authority constraint validation. |
| `require_cryptographic_holder_binding` | Relevant to CS-02 | Partial | Holder binding is generated for SD-JWT presentations, but request-side flag validation is not complete. |
| Claim paths and claim_sets | Required for disclosure constraints | Partial | Wallet filters SD-JWT disclosures by first path segment; full DCQL path grammar, `claim_sets`, duplicate claim ids, value matching, and negative validation remain incomplete. |
| `credential_sets` | Relevant when used | Partial | Wallet validates non-empty options and unknown ids, but only supports single selected credential behavior. |

### ProtocolMessages: Authorization Response (PM 124-159)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| direct_post response | Required | Yes | Wallet posts form-encoded response; verifier checks state and nonce. |
| direct_post.jwt / encrypted response | Useful, profile-adjacent | Partial | Wallet can create JWE/JWT response; verifier decrypts JWE branch. Full outer response JWT signature verification is still not clearly enforced for unencrypted direct_post.jwt. |
| `vp_token` DCQL object shape | Required with DCQL | Partial | Wallet emits correct object shape for selected credential. Verifier validates object shape but missing expected credential ids may be warning-level in current docs. |
| `transaction_data` reference in credential presentation | Optional/profile-specific | Partial | Some validation exists, but full FCAF error matrix is not covered. |
| Wallet error response handling | Required robustness | Partial | Verifier surfaces wallet-reported errors for direct_post. Coverage of all FCAF error flows is incomplete. |
| Unsupported response modes / scopes / formats | Required negative tests | Partial | Request builder rejects unsupported response modes; wallet negative handling is not complete. |

### Metadata: Status Claims (M 081-103) and CredentialFormats status (CF 029-031, 049)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| JOSE `status` / `status_list` validation | Important for credential authenticity/revocation | Missing | The FCAFS report identified this as uncovered. CS-02 verifier validation includes credential authenticity; status checking should be treated as a CS-02 gap even if not spelled out in detail. |
| COSE status claims | Out of core CS-02 because mdoc is deferred | Out of scope / Missing for mdoc | CS-02 note says ISO18013-5/7 support comes in subsequent versions. |

### Metadata: client_metadata and Client Identifier Schemes (M 104-141)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| Verifier metadata publication | Required | Partial | Local metadata/config exists, but this report did not prove full `.well-known` publication and schema coverage. |
| `client_metadata` parsing and precedence | Required for interoperability | Partial | Wallet accepts inline metadata and metadata URI/JWKS for verification. Full precedence and negative validation are incomplete. |
| `x509_san_dns` | Required/recommended in CS-02 | Partial | Verifier can build x509_san_dns requests, but wallet verifies x5c leaf signature without visible SAN/trust-chain validation. |
| `verifier_attestation` | Recommended/allowed in CS-02 | Partial | Verifier can generate a development VA-JWT, but comments indicate the self-signed variant is not production-compliant; wallet-side attestation validation is not evident. |
| `did:web` / `did:jwk` | Recommended by CS-02 | Yes/partial | Verifier and wallet support DID-based request signing and verification. Trust policy for DID resolution remains limited. |
| `openid_federation`, `x509_hash`, `origin:` | Broader FCAF | Out of scope / partial | Not core CS-02; useful for broader FCAF but lower WE BUILD priority. |
| Wallet metadata encryption | Useful | Partial | Verifier can encrypt request objects to wallet metadata JWKS; wallet direct support depends on flow and metadata. |

### CredentialFormats (CF 029-049)

| FCAF spec area | CS-02 relevance | Coverage | Notes |
|---|---:|---|---|
| SD-JWT-VC compact with KB-JWT | Required | Yes/partial | Wallet appends KB-JWT; verifier checks nonce, audience, `sd_hash`, and `cnf.jwk` signature binding. Credential issuer signature/status validation still needs hardening. |
| SD-JWT-VC compact without KB-JWT | Negative case for CS-02 | Partial | CS-02 requires KB-JWT; verifier rejects missing nonce/key-binding in key-bound paths, but full negative test matrix should be added. |
| JWT VC / JWT VP | Not primary CS-02 | Partial | Supported for compatibility. |
| ISO mdoc | Deferred by CS-02 note | Out of scope for CS-02 v1.1 | Repo has mdoc support, but CS-02 says ISO18013-5/7 come later. |
| CWT, JSON serialization, multiple mdocs | Broader FCAF | Out of scope | These remain FCAF gaps but are not WE BUILD CS-02 blockers. |

## CS-02-Critical Gaps

| Priority | Gap | Why it matters for WE BUILD CS-02 |
|---|---|---|
| Critical | Full request object validation is incomplete on wallet side. | CS-02 requires signature, nonce freshness, audience match, expiry, credential constraints, and request integrity. Current wallet verifies signatures and requires nonce, but `typ`, HTTPS/content-type, audience-to-wallet, strict `client_id`, and full DCQL schema checks are incomplete. |
| Critical | Verifier response validation is still partial. | CS-02 requires validation of presentation proof signature, credential authenticity, disclosure integrity, holder binding, nonce/audience binding, and request constraints. Holder binding is much improved, but outer response JWT signature verification and credential authenticity/status validation remain incomplete. |
| Critical | Status/revocation validation is missing. | The FCAFS report shows JOSE/COSE status specs uncovered. For CS-02 SD-JWT-VC, JOSE status/status_list validation should be implemented as part of credential authenticity. |
| Major | Client identifier trust policy is incomplete. | CS-02 names `x509_san_dns`, `verifier_attestation`, and DIDs. The implementation signs/verifies with x5c and DID material, but production-grade SAN matching, certificate chain anchoring, verifier attestation issuer trust, and metadata precedence are not complete. |
| Major | DCQL structural validation is incomplete. | CS-02 mandates DCQL. The wallet matches practical `format` and `meta` constraints but does not fully validate IDs, duplicate IDs, claim path grammar, claim_sets, `trusted_authorities`, `multiple`, or invalid formats. |
| Major | Consent is not evidenced as a protocol gate. | CS-02 requires transparent holder consent and forbids auto-consent. The wallet presentation function can execute a presentation flow directly; this report did not find a clear mandatory consent step in the core library path. |
| Major | ES256/P-256 is not uniformly enforced. | CS-02 requires strict P-256 with ES256. The code supports ES256 paths, but x509 and verifier_attestation branches still have RS256 fallbacks/defaults. |

## FCAF Gaps That Are Lower Priority For WE BUILD CS-02

These remain FCAF MessageStructure gaps, but they should not be treated as first-order CS-02 blockers:

| FCAF area | Reason |
|---|---|
| Plain unsigned authorization request support | CS-02 requires signed requests and wallets must reject unsigned requests. |
| ISO mdoc, multiple DeviceResponses, COSE status | CS-02 v1.1 explicitly defers ISO18013-5/7 support to subsequent versions. |
| CWT referenced tokens | Not part of the CS-02 SD-JWT-VC target. |
| JSON serialization credentials | Not part of the CS-02 compact SD-JWT-VC target. |
| OpenID Federation | Useful for broader HAIP/FCAF, but CS-02 highlights x509/verifier_attestation and recommends DIDs. |
| `redirect_uri` unsigned/client-id scheme behavior | CS-02 emphasizes signed JAR and high-assurance schemes. Redirect URI scheme may be useful for compatibility but should not drive WE BUILD conformance. |

## Profile-Adjusted Coverage Summary

This is not a recount of all 236 FCAF cases. It is the practical CS-02 subset view:

| Layer | WE BUILD relevance | Coverage |
|---|---|---|
| Signed JAR request creation | Required | Partial: signed request objects exist; ES256 is not uniform. |
| Wallet JAR validation | Required | Partial: signature verification exists; strict `typ`, HTTPS, content type, audience, and trust policy are incomplete. |
| `openid4vp://present` request URI invocation | Required | Covered. |
| DCQL query and response shape | Required | Partial: practical selection/response exists; full DCQL schema validation missing. |
| SD-JWT-VC selective disclosure | Required | Partial/covered for simple claim paths. |
| KB-JWT holder binding | Required | Covered for generated wallet responses; verifier-side checks are now materially improved. |
| Verifier nonce/audience/request-constraint checks | Required | Partial: nonce/audience and claim constraints exist; expected DCQL id enforcement and outer response proof validation remain incomplete. |
| Credential authenticity and status | Required by verifier validation intent | Missing/partial: key binding is checked, but issuer signature/trust and status_list validation need hardening. |
| Verifier metadata | Required | Partial: config exists; publication/schema proof incomplete. |
| Holder consent | Required | Missing/unclear in core automated presentation path. |

## Recommended Remediation Order

1. Add a CS-02 wallet request validator that explicitly checks JAR `typ`, `alg=ES256`, `client_id`, `nonce`, `exp`, `aud`, HTTPS `request_uri`, response content type, and `dcql_query` presence.
2. Add full DCQL schema validation for the CS-02 subset: credential query `id`, uniqueness, format allowlist, `meta.vct_values`, claims path grammar, claim ids, `claim_sets`, and `trusted_authorities` policy.
3. Enforce ES256/P-256 consistently in verifier request generation. Remove or isolate RS256-only branches from CS-02 flows.
4. Harden verifier response validation: verify outer direct_post.jwt signatures when unencrypted, require expected DCQL credential ids as fatal, and add tests for missing/wrong KB-JWT nonce, audience, `sd_hash`, and `cnf.jwk`.
5. Implement JOSE `status` / `status_list` validation for SD-JWT-VC credentials and define the local policy for missing status.
6. Define production trust policy for `x509_san_dns`, `verifier_attestation`, and DIDs: SAN matching, trust anchors, verifier attestation issuer validation, metadata precedence, and certificate chain handling.
7. Make holder consent an explicit mandatory step in the wallet UI/API path, or document that the library is lower-level and must be wrapped by a consent gate.

## Bottom Line

Against the original broad FCAFS report, this repo still does not cover the full 236-spec MessageStructure surface. Against the narrower WE BUILD CS-02 profile, the implementation is much closer: the core happy path for signed OpenID4VP, `openid4vp://present`, DCQL, SD-JWT-VC disclosure, KB-JWT, and nonce/audience binding is present.

The remaining CS-02 blockers are not broad format support. They are stricter validation and trust: full wallet-side request validation, full DCQL schema validation, uniform ES256/P-256 enforcement, production-grade client identifier trust, credential status validation, explicit consent gating, and complete verifier-side response proof validation.
