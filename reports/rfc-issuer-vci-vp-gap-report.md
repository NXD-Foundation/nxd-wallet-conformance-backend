# RFC Issuer / Verifier Gap Report Against OIDF Conformance Suite

## Scope

This report compares:

- The OIDF conformance-suite codebase in `/home/ni/code/conformance-suite-release-v5.1.40`
- The issuer/verifier implementation in `/home/ni/code/js/rfc-issuer-v1`

The focus is limited to:

- OpenID4VCI issuer-side coverage
- OpenID4VP verifier-side coverage
- Tests/checks that exist in the OIDF suite but are not covered, or only partially covered, in `rfc-issuer-v1`

This is a semantic/specification-oriented comparison, not just a route inventory.

## Main Sources Reviewed

### OIDF conformance suite

- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerTestPlan.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerMetadataTest.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerMetadataSignedTest.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerHappyFlow.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerHappyFlowAdditionalRequests.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerHappyFlowMultipleClients.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerHappyFlowWithSkipNotification.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerFailOnInvalidNonce.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerFailOnReplayNonce.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerFailOnInvalidJwtProofSignature.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerFailOnInvalidKeyAttestationSignature.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerFailOnInvalidClientAttestationSignature.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerFailOnInvalidClientAttestationPopSignature.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerFailOnMismatchedClientAttestationPopKey.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerFailOnMissingProof.java`
- `src/main/java/net/openid/conformance/vp1finalverifier/VP1FinalVerifierTestPlan.java`
- `src/main/java/net/openid/conformance/vp1finalverifier/AbstractVP1FinalVerifierTest.java`
- `src/main/java/net/openid/conformance/vp1finalverifier/VP1FinalVerifierHappyFlow.java`
- `src/main/java/net/openid/conformance/vpid3verifier/VPID3VerifierTestPlan.java`
- `src/main/java/net/openid/conformance/vpid3verifier/AbstractVPID3VerifierTest.java`
- `src/main/java/net/openid/conformance/vpid3verifier/VPID3VerifierHappyFlow.java`

### RFC issuer/verifier

- `testCaseCoverage.yml`
- `testCaseRequests.yml`
- `README.md`
- `docs/vci-authorization-code-wallet-matrix.md`
- `docs/vp-verification-wallet-matrix.md`
- `routes/metadataroutes.js`
- `routes/issue/sharedIssuanceFlows.js`
- `routes/verify/verifierRoutes.js`
- `routes/verify/vpStandardRoutes.js`
- `utils/cryptoUtils.js`
- `utils/credentialResponseEncryption.js`
- `tests/metadataDiscovery.test.js`
- `tests/sharedIssuanceFlows.test.js`
- `tests/credentialResponseEncryption.test.js`
- `tests/oauthClientAttestation.test.js`
- `tests/keyAttestationProof.test.js`
- `tests/directPostJwt.test.js`
- `tests/verifierRoutesDirectPostJwt.test.js`
- `tests/stateParameterSpec.test.js`

## Executive Summary

### VCI

`rfc-issuer-v1` already covers a substantial amount of issuer-side OID4VCI behavior, especially:

- metadata discovery basics
- nonce issuance and nonce replay protection
- proof validation
- key attestation validation
- client attestation validation
- credential response encryption validation
- unknown credential identifier/configuration errors

The main remaining gaps against the OIDF suite are:

- no signed metadata response support
- no explicit rejection of access tokens sent in query parameters
- no explicit end-to-end test for compressed encrypted credential responses (`zip=DEF`)
- notification behavior only partially tested
- no explicit multi-client conformance regression
- no operational/TLS-style additional request coverage

### VP

The OIDF VP verifier plans are much thinner than the VCI issuer plans. They are mostly happy-flow tests, but they still enforce important request-object semantics.

`rfc-issuer-v1` is already stronger than the published OIDF plan in some response-validation areas, especially:

- state correlation
- nonce correlation
- SD-JWT key-binding `aud` and `sd_hash` handling

The main VP-side gaps are:

- inconsistent coexistence of Final/DCQL logic with legacy `presentation_definition` flows
- incomplete strictness around DCQL request hygiene
- likely missing full outer JWT verification for `direct_post.jwt`
- client metadata and emitted JWK hygiene not as explicitly validated as in OIDF

## Detailed Comparison

### VCI issuer-side comparison

| Area | OIDF suite behavior | RFC issuer status | Notes |
|---|---|---|---|
| Issuer metadata baseline | Validates required metadata fields, HTTPS URLs, issuer URI, schema, authorization server metadata, `authorization_details_types_supported`, HAIP nonce endpoint behavior | Covered / Partial | `tests/metadataDiscovery.test.js` is extensive and `routes/metadataroutes.js` implements the baseline. Coverage is spread across many repo-local tests rather than a single strict conformance validator. |
| Signed issuer metadata | Tests signed metadata response using `application/jwt` when exposed | Missing | `routes/metadataroutes.js` only serves JSON. No signed metadata response path found. |
| Standard happy flow | End-to-end issuer flow via metadata, PAR, token, nonce, proof, credential issuance | Covered | Strongly represented in `tests/sharedIssuanceFlows.test.js`, `tests/codeFlowSdJwtRoutes.test.js`, and the VCI matrix docs. |
| Invalid nonce | Reject with `invalid_nonce` | Covered | Explicit tests exist in `tests/sharedIssuanceFlows.test.js`. |
| Replay nonce | Reject nonce reuse with `invalid_nonce` | Covered | Explicit tests exist in `tests/sharedIssuanceFlows.test.js`. |
| Missing proof | Reject missing `proofs` when proof is required | Covered | Covered by proof-structure and proof-requirement tests, especially in `tests/metadataDiscovery.test.js`. |
| Invalid JWT proof signature | Reject invalid JWT proof with `invalid_proof` | Covered | Covered by issuance and proof validation tests. |
| Invalid key attestation signature | Reject invalid key-attestation proof | Covered | Covered by `tests/keyAttestationProof.test.js`. |
| Invalid client attestation signature | Reject invalid client-attestation signature | Covered | Covered by `tests/oauthClientAttestation.test.js`. |
| Invalid client-attestation PoP signature | Reject invalid PoP signature | Covered | Covered by `tests/oauthClientAttestation.test.js`. |
| Mismatched client-attestation PoP key | Reject cryptographically valid PoP signed with wrong key | Covered | Covered by `tests/oauthClientAttestation.test.js`. |
| Unknown `credential_configuration_id` | Reject with `unknown_credential_configuration` | Covered | Explicitly covered in `tests/sharedIssuanceFlows.test.js`. |
| Unknown `credential_identifier` | Reject with `unknown_credential_identifier` | Covered | Explicitly covered in `tests/sharedIssuanceFlows.test.js`. |
| Unsupported encryption algorithm | Reject with `invalid_encryption_parameters` | Covered | Covered in `tests/credentialResponseEncryption.test.js` and `tests/sharedIssuanceFlows.test.js`. |
| Encrypted response with compression | Happy flow probes support for encrypted response compression (`zip=DEF`) | Partial | Implementation support exists in `utils/credentialResponseEncryption.js`, but no explicit test was found. |
| Access token in query | Reject request if access token is supplied as query parameter | Missing | No explicit route handling or test found for access-token-in-query rejection. |
| Notification skipped by wallet | Issuer must tolerate never receiving notification | Partial | Behavior is likely fine, but no explicit regression test was found for “wallet never calls notification”. |
| Notification request shape | Wallet-side suite validates notification fields and unknown fields | Partial | `/notification` exists, but stronger semantic tests for malformed/unknown-field requests were not found. |
| Multiple clients | Happy flow repeated with multiple clients | Partial | Multiple client-id schemes are supported, but not a clear sequential two-client conformance regression. |
| Additional HTTP/TLS checks | Additional requests exercise TLS and header permissiveness | Missing | Not represented in RFC repo tests. More operational than pure spec semantics, but still in OIDF scope. |

### VP verifier-side comparison

| Area | OIDF suite behavior | RFC verifier status | Notes |
|---|---|---|---|
| Valid request-object shape | Checks `response_type=vp_token`, response mode validity, client ID consistency, request URI HTTPS/no fragment, typ, signature | Partial | Covered in pieces across `tests/directPostJwt.test.js`, `tests/x509Routes.test.js`, `tests/didRoutes.test.js`, `tests/didJwkRoutes.test.js`. |
| No `client_id_scheme` parameter in final request | Explicitly checked by OIDF | Covered / Partial | Newer builder tests enforce omission, but legacy helpers still include `client_id_scheme`. |
| DCQL extraction and validation | Final/ID3 flows extract and validate DCQL; final flow also checks no `scope` when DCQL is present | Partial | Core builder is Final-oriented and rejects `presentation_definition`, but the standardized route layer still carries legacy PEX behavior. |
| Unknown DCQL properties | OIDF warns on unknown properties after schema validation | Partial | Your repo supports DCQL but does not always make unknown or missing keys fatal. |
| `response_uri` validity | OIDF validates `response_uri` | Covered / Partial | Request-building tests cover presence and routing; more centralized conformance-style validation would still help. |
| Nonce quality | OIDF checks invalid chars and nonce length warnings | Partial | Nonce usage is strong; explicit nonce syntax/length checks are less centralized in repo tests. |
| `direct_post` state handling | OIDF expects strict response validation | Covered | Strong coverage in `tests/stateParameterSpec.test.js` and `tests/verifierRoutesDirectPostJwt.test.js`. |
| `direct_post.jwt` response processing | OIDF happy flow expects verifier to process JWT/JWE response correctly | Partial | Repo processes and decrypts responses, but your own docs note likely missing full outer signature verification. |
| SD-JWT key binding | OIDF happy flow uses valid presentations; repo additionally validates nonce, aud, and `sd_hash` | Covered | RFC repo is stronger than published OIDF plan here. |
| Client metadata hygiene | ID3 verifier base test validates client metadata/JWK quality and public-only JWKs | Partial | Request generation is tested, but strong validation of emitted metadata/JWK hygiene is less explicit. |
| `x509_hash` client ID semantics | Final verifier validates `x509_hash` variant when selected | Covered | Covered in `tests/directPostJwt.test.js`. |
| Legacy PEX coexistence | OIDF Final flow is DCQL-centric | Missing / Inconsistent | `utils/cryptoUtils.js` rejects `presentation_definition` for Final behavior, but `routes/verify/vpStandardRoutes.js` still loads PEX definitions. |

## Important Gaps With Highest Practical Value

These are the gaps most worth fixing if the objective is to improve `rfc-issuer-v1` against the OIDF suite and tighten spec behavior:

1. Signed metadata responses are not implemented.
2. Access tokens in query parameters are not explicitly rejected on issuance endpoints.
3. Compressed encrypted credential responses are implemented but not explicitly tested.
4. Notification endpoint validation is not covered as strongly as the suite implies.
5. VP standardized flow still mixes legacy `presentation_definition` behavior with Final/DCQL-only behavior.
6. `direct_post.jwt` likely lacks complete outer JWT cryptographic verification.
7. Client metadata / client JWK hygiene checks are not as explicitly tested as in OIDF.

## Suggested Interpretation Of Coverage Labels

- Covered: behavior exists and there is meaningful automated test coverage
- Partial: behavior exists or is implied, but coverage is indirect, fragmented, or less strict than OIDF
- Missing: I did not find equivalent implementation or meaningful automated coverage

## Recommended Next Step

Use this report together with the backlog document `reports/rfc-issuer-implementation-backlog.md`, which turns these gaps into concrete implementation and test tasks.
