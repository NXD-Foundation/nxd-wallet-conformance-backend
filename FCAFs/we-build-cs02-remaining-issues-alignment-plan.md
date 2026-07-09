# WE BUILD CS-02 Remaining Issues Alignment Plan

## Source Baseline

This plan starts from the updated status in `FCAFs/we-build-cs02-fcaf-message-structure-coverage.md`. The initial Phase 1-5 alignment work already added strict wallet request validation, strict DCQL validation, multi-credential response support, verifier response validation, KB-JWT checks, status-list placeholders, and shared trust/metadata policy.

The remaining work is narrower. It is mostly about making the active runtime paths use the new policy helpers consistently, aligning metadata with actual enforcement, and completing the trust/authenticity surfaces that were intentionally left as placeholders until configuration exists.

The remaining CS-02-critical issues are:

- exact `did:web` `kid` binding in the wallet JAR verification path
- strict `client_metadata_uri` validation and remote metadata policy
- verifier metadata consistency for strict CS-02 mode
- SD-JWT-VC issuer signature and configured issuer trust validation
- future status-list enforcement once trust framework inputs exist
- production `x509_san_dns` and `verifier_attestation` trust checks once trust anchors/trusted issuers exist
- disclosure/request-constraint hardening beyond the current DCQL subset
- explicit holder consent gating or documented integration boundary
- tests that lock the above behavior into strict CS-02 mode

## Phase A: DID Trust Policy Wiring

Goal: make active wallet-side DID verification follow the shared CS-02 trust policy instead of duplicating weaker local matching behavior.

Required wallet changes:

- Update `wallet-client/src/lib/cs02RequestValidation.js` so the `did:web` JAR verification path requires a JOSE `kid`.
- Resolve `did:web` documents only over HTTPS. Keep the existing HTTPS-only resolver behavior, but make the trust policy receive enough context to prove HTTPS resolution occurred.
- Call `validateDidWebKidResolution` from `utils/cs02TrustPolicy.js` before importing a verification key.
- Remove fallback behavior that verifies against every DID document verification method when `kid` is missing or mismatched.
- Require the resolved verification method to contain `publicKeyJwk`.
- Require the resolved `publicKeyJwk` to be EC/P-256 and compatible with ES256.
- Verify the JAR signature only with the exact key selected by the matched `kid`.
- Preserve the existing `did:jwk` strict behavior, but route it through `validateDidJwkTrustRules` so DID trust policy lives in one place.
- Convert `Cs02TrustPolicyError` failures into wallet `Cs02ValidationError` with `invalid_client`.

Required trust-policy changes:

- Extend `validateDidWebKidResolution` to accept an optional `resolutionUrl` or `resolvedOverHttps` parameter.
- If a resolution URL is provided, require `https:`.
- If no URL is available, require the caller to pass `resolvedOverHttps: true`.
- Reject missing `kid` with a stable `invalid_client` error.
- Reject `kid` values that do not exactly match the DID document verification method id or the canonical fragment form for that DID.
- Keep support for existing local DID document id shapes only when they cannot widen matching beyond the requested fragment.

Required tests:

- Add wallet request validation tests for missing `did:web` `kid`.
- Add tests for `did:web` `kid` pointing to a different verification method than the signing key.
- Add tests proving no fallback-to-any-verification-method is accepted.
- Add tests for successful `did:web` verification with exact `kid`.
- Add tests for `did:jwk` rejecting non-P-256 and non-ES256 keys through the shared policy.

Acceptance criteria:

- A `did:web` JAR cannot verify unless its `kid` resolves to the exact P-256 public key used for the signature.
- All DID trust failures are logged without credential or private key material.
- DID validation behavior is covered by unit tests and, where practical, one wallet presentation integration test.

## Phase B: `client_metadata_uri` Policy And Metadata Precedence

Goal: make strict wallet validation treat remote verifier metadata with the same policy as inline metadata.

Required wallet request validation changes:

- Import and call `validateCs02ClientMetadataUri` from `utils/cs02TrustPolicy.js` when `payload.client_metadata_uri` is present.
- Reject non-string, empty, relative, malformed, or non-HTTPS `client_metadata_uri` in strict CS-02 mode.
- Fetch remote metadata only after the HTTPS placeholder validation passes.
- Validate fetched remote metadata with `validateCs02ClientMetadata`.
- Apply the same format, alg, JWK schema, and response-mode policy to remote metadata as inline `client_metadata`.
- Define the effective metadata precedence:
  - signed JAR payload values remain authoritative for `client_id`, `response_mode`, `response_uri`, `nonce`, `state`, and `dcql_query`
  - inline `client_metadata` is preferred over `client_metadata_uri` when both are present
  - `client_metadata_uri` is used only to resolve verifier keys or encryption metadata not supplied inline
  - metadata must not contradict signed JAR response-mode constraints
- Fail closed when remote metadata cannot be fetched or parsed in strict CS-02 mode.
- Keep compatibility behavior outside strict mode if legacy flows currently depend on best-effort metadata fetch.

Required metadata fetch hardening:

- Add fetch timeout and maximum response-size policy for `client_metadata_uri`.
- Require JSON content type for remote metadata when the server provides a content type.
- Reject arrays, strings, or non-object metadata documents.
- Do not follow redirects to non-HTTPS URLs.
- Do not log full metadata documents; log only field presence and validation errors.

Required tests:

- Reject `http://` `client_metadata_uri` in strict mode.
- Reject relative `client_metadata_uri`.
- Reject remote metadata containing unsupported strict CS-02 formats.
- Reject remote metadata with unsupported KB-JWT algs.
- Reject remote metadata advertising direct_post encryption settings when response mode is `direct_post`.
- Accept valid HTTPS remote metadata with supported JWKs.
- Verify inline metadata takes precedence when both inline metadata and URI metadata are present.

Acceptance criteria:

- Strict CS-02 wallet validation rejects invalid or unsupported metadata before credential selection.
- Remote and inline metadata cannot weaken signed JAR request parameters.
- Tests cover both positive and negative metadata URI behavior.

## Phase C: Verifier Metadata Consistency

Goal: ensure verifier metadata and request-time metadata advertise only what strict CS-02 runtime enforcement actually supports.

Required verifier metadata changes:

- Audit every place that loads or publishes `data/verifier-config.json`.
- Decide whether `data/verifier-config.json` should be strict CS-02 by default or whether strict metadata should be produced through a filtered view.
- In strict CS-02 mode, advertise only:
  - `dc+sd-jwt`
  - `vc+sd-jwt`
  - `mso_mdoc`
  - SD-JWT issuer algs that are actually accepted
  - KB-JWT algs that are actually enforced, currently ES256
  - response modes that the verifier validates
  - JWE algorithms and enc values that are actually accepted by `validateCs02JweResponseHeader`
- Remove `jwt_vc_json` from strict CS-02 metadata.
- Remove `https://cloudsignatureconsortium.org/2025/x509` from strict CS-02 metadata unless it is part of a distinct compatibility or CS-03 route.
- Remove `ES384` from `kb-jwt_alg_values` in strict CS-02 metadata unless verifier-side KB-JWT validation is expanded to accept and verify ES384.
- For `direct_post`, remove all encrypted-response metadata:
  - `encrypted_response_alg_values_supported`
  - `encrypted_response_enc_values_supported`
  - `authorization_encrypted_response_alg`
  - `authorization_encrypted_response_enc`
- Keep encrypted-response metadata only for `direct_post.jwt`.
- Ensure `filterClientMetadataForCs02Enforcement` deletes both encrypted alg and enc fields for `direct_post`.
- Ensure `utils/cryptoUtils.js` does not reintroduce direct_post encryption metadata after filtering.

Required publication policy:

- If public verifier metadata endpoints exist or are added, expose a strict CS-02 filtered metadata document for CS-02 routes.
- Keep compatibility metadata separate and clearly named.
- Do not let a compatibility route silently feed unsupported metadata into strict CS-02 JAR generation.
- Document the difference between strict CS-02 metadata and legacy/compatibility metadata.

Required tests:

- Unit test `filterClientMetadataForCs02Enforcement` for `direct_post` deleting encrypted alg and enc metadata.
- Unit test strict metadata filtering removes `jwt_vc_json`.
- Unit test strict metadata filtering keeps `mso_mdoc`.
- Unit test KB-JWT alg filtering keeps only ES256.
- Add a route or builder test proving generated strict CS-02 request objects do not contain unsupported metadata.
- Add a metadata fixture test that fails if `data/verifier-config.json` is used directly in strict CS-02 without filtering.

Acceptance criteria:

- Strict CS-02 request metadata matches runtime enforcement.
- Compatibility metadata cannot leak unsupported formats/algorithms into strict CS-02 request objects.
- Metadata tests fail if unsupported strict-mode formats or algs are reintroduced.

## Phase D: SD-JWT-VC Issuer Authenticity And Trust

Goal: move from holder-binding-only validation to real SD-JWT-VC issuer authenticity validation.

Required verifier changes:

- Add an SD-JWT issuer signature validation module, or extend the existing SD-JWT validation utility if one already exists.
- Decode the issuer-signed JWT segment of the SD-JWT.
- Require a protected header with a supported issuer signing algorithm.
- Reject `alg=none` and unsupported issuer signing algorithms.
- Resolve issuer verification keys from configured trusted issuer metadata.
- Support at least one configured trust source:
  - explicit issuer allowlist with JWKS/JWKS URI
  - local trusted issuer configuration file
  - existing issuer metadata if already validated through a trusted path
- Verify the issuer-signed JWT signature before accepting any disclosed claims.
- Require expected issuer claims:
  - `iss`
  - `iat` when present to be sane
  - `exp` when present to be unexpired
  - `vct` or equivalent credential type when requested by DCQL
  - `cnf.jwk` when holder binding is required
- Validate that presented disclosures reconstruct against the issuer-signed SD-JWT payload.
- Verify that requested DCQL claim paths are present after disclosure reconstruction.
- Reject unsolicited disclosed claims in strict CS-02 mode unless explicitly allowed by the request.
- Run issuer trust validation before status-list trust decisions.

Required trust-policy changes:

- Extend `validateCs02IssuerTrust` to read configured trusted issuers.
- Keep default behavior as placeholder only if no trusted issuer config exists, but return a visible marker that issuer trust was not enforced.
- Add an environment/config flag for strict issuer trust once configuration exists.
- Define a stable error code for untrusted issuer, for example `invalid_credential`.
- Keep logs concise: issuer identifier, key id, configured trust source, and reason for failure.

Required tests:

- Reject SD-JWT with invalid issuer signature.
- Reject SD-JWT with unsupported issuer alg.
- Reject SD-JWT missing `cnf.jwk` when holder binding is required.
- Reject SD-JWT from untrusted issuer when trust config is present.
- Accept SD-JWT from trusted issuer with valid signature and matching `cnf.jwk`.
- Reject presented disclosures that do not reconstruct.
- Reject missing requested claims.
- Reject unsolicited disclosures in strict mode if policy is enabled.

Acceptance criteria:

- Verifier does not mark a CS-02 SD-JWT presentation successful based only on KB-JWT holder binding.
- Issuer signature and configured issuer trust are verified when trust configuration exists.
- Placeholder/no-trust-framework behavior is explicit and test-covered.

## Phase E: Status-List Enforcement Readiness

Goal: keep the current placeholder behavior safe, while making the future trust-framework implementation straightforward.

Current policy:

- Missing SD-JWT-VC status is allowed by default.
- Malformed `status.status_list` references are rejected when present.
- Missing status is rejected only when `CS02_STRICT_STATUS_VALIDATION=true`.
- Fetch, token signature verification, bitstring decoding, and revoked/suspended decisions remain TODO until trusted status-list issuers exist.

Required near-term changes:

- Keep `validateCs02CredentialStatusList` invoked from the verifier SD-JWT strict path.
- Ensure status-list validation receives the same trust-policy options used for issuer trust.
- Add an explicit return field showing whether status was:
  - absent
  - structurally valid placeholder
  - structurally invalid
  - fully enforced
- Log placeholder status decisions at debug level without treating them as success proof.
- Add TODO comments naming the exact future inputs required:
  - trusted status-list issuers
  - allowed status-list JWT algorithms
  - cache lifetime
  - fetch timeout
  - maximum response size
  - revoked/suspended bit interpretation

Future enforcement changes once trust exists:

- Fetch `status.status_list.uri` over HTTPS only.
- Enforce timeout and maximum response size.
- Require status-list token content type to be JWT or JSON/JWT-compatible if specified.
- Verify status-list token signature against trusted status-list issuer keys.
- Require status-list token issuer to be trusted or linked to the credential issuer according to local policy.
- Decode the compressed bitstring according to the selected status-list specification.
- Evaluate `idx` and reject revoked or suspended credentials.
- Cache status-list tokens safely by URI, issuer, and token expiry.
- Fail closed on malformed fetched status-list tokens in strict mode.

Required tests:

- Existing malformed local status-list tests remain.
- Add test proving verifier invokes status-list placeholder for SD-JWT presentations.
- Add test proving missing status is allowed by default.
- Add test proving missing status is rejected with `CS02_STRICT_STATUS_VALIDATION=true`.
- Add TODO/skipped tests for future revoked and suspended decisions.
- Add TODO/skipped tests for fetch timeout and max-size behavior.

Acceptance criteria:

- Current placeholder status behavior is explicit and covered.
- Future trust-framework status behavior has stable integration points and tests ready to unskip.

## Phase F: Production x509 And Verifier-Attestation Trust

Goal: leave current no-anchor behavior intact, but define exactly how production trust checks will be enabled once trust configuration exists.

Current policy:

- x509 SAN DNS chain/SAN validation is intentionally skipped because no trust anchors are configured.
- verifier_attestation trusted issuer validation is intentionally skipped because trusted verifier-attestation issuers are not configured.
- Placeholder methods must remain in place so runtime integration points do not change later.

Required x509 production changes when trust anchors exist:

- Add trust-anchor configuration, for example `CS02_X509_TRUST_ANCHORS_PATH`.
- Parse `x5c` certificate chains from JAR headers.
- Verify the JAR signature with the x5c leaf key.
- Validate the certificate chain against configured trust anchors.
- Require certificate validity period to include current time.
- Require the leaf certificate key to be P-256 and compatible with ES256.
- Extract the SAN DNS names from the leaf certificate.
- Require the SAN DNS name to match the host part of the non-prefixed `x509_san_dns` `client_id`.
- Reject wildcard SANs unless an explicit policy says they are allowed.
- Reject missing SAN DNS.
- Log certificate subject, issuer, SAN DNS names, and trust anchor id, not full certificate chains.

Required verifier-attestation production changes when trusted issuers exist:

- Add trusted verifier-attestation issuer configuration, for example `CS02_VERIFIER_ATTESTATION_ISSUERS_PATH`.
- Require JOSE header `jwt` for `verifier_attestation` requests.
- Decode and verify the verifier-attestation JWT signature.
- Require `iss` to match a configured trusted attestation issuer.
- Require `sub` to match the non-prefixed verifier identifier.
- Require `exp` to be present and unexpired.
- Require `iat` to be sane.
- Require attestation claims to bind the JAR signing key.
- Verify the JAR signature with the attested key.
- Reject self-signed/development attestation when production trust config is enabled.

Required tests now:

- Tests should assert current placeholder behavior returns `enforced: false`.
- Tests should assert x509 placeholder is called from both verifier request generation and wallet request validation.
- Tests should assert verifier-attestation placeholder is called when header `jwt` is present.
- Add skipped/TODO tests for configured trust anchors and trusted verifier-attestation issuers.

Acceptance criteria:

- Current behavior remains non-blocking without trust config.
- Enabling trust config flips behavior from placeholder to enforced validation without changing callers.
- Production trust failures return stable `invalid_client` errors.

## Phase G: Disclosure And Request-Constraint Hardening

Goal: close the remaining validation gap between structurally valid DCQL and fully verified disclosed credential content.

Required wallet changes:

- Extend supported DCQL claim path grammar beyond current string-only path segments only when required by the project profile.
- For unsupported path grammar, fail explicitly in strict CS-02 mode.
- Ensure every requested SD-JWT disclosure exists in the stored credential.
- Fail when a requested disclosure cannot be found.
- Do not include unsolicited disclosures in strict CS-02 mode.
- When `claim_sets` is present, disclose only the claims belonging to the satisfied claim set option.
- For `credential_sets`, only present credentials belonging to the satisfied option.
- Preserve existing multi-credential behavior for `multiple=true`.

Required verifier changes:

- Reconstruct disclosed SD-JWT claims before accepting the presentation.
- Verify every requested DCQL claim path is present in the reconstructed claims.
- Reject unsolicited disclosed claims when strict policy is enabled.
- Validate `vct` in reconstructed/issuer-signed credential against `meta.vct_values`.
- Validate `mso_mdoc` doctype against `meta.doctype_value` for mdoc responses.
- Ensure a response satisfying one `credential_sets` option does not include unrelated credential query ids.
- Preserve current behavior that optional credential sets do not require every known id.

Required tests:

- Reject missing requested disclosure.
- Reject unsolicited disclosure.
- Accept only the selected `claim_sets` option.
- Reject wrong `vct`.
- Reject wrong mdoc doctype when `mso_mdoc` is requested.
- Reject unrelated credential ids when a required credential-set option is satisfied.
- Accept valid multi-credential response when `multiple=true`.

Acceptance criteria:

- The wallet only discloses what the strict DCQL request allows.
- The verifier validates that the received presentation satisfies the original request constraints, not just the holder-binding proof.

## Phase H: Holder Consent Gate

Goal: ensure CS-02 flows cannot silently present credentials without a holder consent decision.

Required design decision:

- Decide whether `wallet-client/src/lib/presentation.js` is a low-level automation library or an end-user wallet flow.
- If it is a low-level library, document that callers must provide a consent gate before invoking presentation generation.
- If it is an end-user wallet flow, add an explicit consent step before presentation generation.

Required implementation if consent is enforced in this repo:

- Add a consent callback or approval object to the presentation flow.
- Present the verifier identity, requested credential query ids, requested claim paths, response mode, and transaction data summary to the consent layer.
- Require a positive consent decision before credential selection or before presentation generation.
- Return a protocol error such as `access_denied` when the holder declines.
- Do not store raw credentials in consent logs.
- Record only consent decision metadata:
  - session id
  - verifier client id
  - requested credential ids
  - requested claim paths
  - decision timestamp
  - accepted/declined

Required tests:

- Presentation generation is blocked when no consent callback/decision is provided in strict end-user mode.
- Declined consent returns `access_denied`.
- Accepted consent allows the happy path to continue.
- Consent logs do not include raw credentials or private key material.

Acceptance criteria:

- CS-02 strict presentation cannot silently auto-present in the end-user wallet path.
- If consent is external to this repo, the boundary is documented and tested through an explicit adapter contract.

## Phase I: Tests, Fixtures, And Regression Gates

Goal: make the remaining CS-02 behavior hard to regress.

Add or update tests in these areas:

- `wallet-client/test/cs02RequestValidation.test.js`
  - `did:web` missing/mismatched `kid`
  - HTTPS-only `client_metadata_uri`
  - remote metadata schema errors
  - inline metadata precedence
- `wallet-client/test/cs02DcqlValidation.test.js`
  - remaining claim path grammar cases
  - `claim_sets` satisfaction and rejection
  - `trusted_authorities` advisory logging
- `wallet-client/test/presentationKeyBinding.test.js`
  - no unsolicited disclosures
  - missing requested disclosures
  - consent behavior if implemented in wallet flow
- `tests/cs02TrustPolicy.test.js`
  - direct_post deletes encrypted alg and enc metadata
  - `did:web` HTTPS and exact `kid` matching
  - placeholder trust behavior when no anchors are configured
- `tests/cs02StatusList.test.js`
  - strict missing status
  - verifier invocation of status-list placeholder
  - TODO/skipped revoked/suspended tests
- `tests/cs02VerifierResponse.test.js`
  - issuer signature/trust failures
  - unsolicited disclosures
  - wrong `vct`
  - credential-set strict response behavior
- route-level verifier tests
  - direct_post/direct_post.jwt failure updates session status to failed
  - invalid CS-02 response never stores validated claims

Recommended commands:

```bash
npm test
cd wallet-client && npm test
npx mocha tests/cs02TrustPolicy.test.js tests/cs02StatusList.test.js tests/cs02VerifierResponse.test.js --exit
cd wallet-client && npx mocha test/cs02RequestValidation.test.js test/cs02DcqlValidation.test.js --exit
```

Regression gate:

- The focused CS-02 suites should run quickly and be suitable for pre-merge validation.
- Any future compatibility-mode expansion must add tests proving strict CS-02 mode remains unchanged.

## Acceptance Criteria

The remaining alignment work is complete when:

- `did:web` JAR verification requires exact `kid` resolution and cannot fall back to unrelated DID document keys.
- `did:jwk` and `did:web` validation both use the shared CS-02 trust policy.
- Strict wallet validation rejects invalid `client_metadata_uri` and validates fetched metadata before use.
- Strict verifier metadata advertises only the formats, algorithms, response modes, and encryption options enforced at runtime.
- `direct_post` metadata does not advertise encrypted response settings.
- SD-JWT-VC issuer signatures are verified and issuer trust is enforced when trust configuration exists.
- Status-list validation remains explicitly placeholder-only without trust config and becomes enforceable without changing callers when trust config is added.
- x509 and verifier-attestation placeholder methods remain callable now and become enforcing when anchors/trusted issuers are configured.
- The wallet and verifier enforce request/disclosure constraints beyond holder-binding proof.
- Holder consent is either enforced in the wallet flow or documented as an explicit caller responsibility with a tested adapter boundary.
- Focused CS-02 tests cover all high-priority remaining gaps.

## Assumptions And Defaults

- CS-02 strict mode remains the default.
- `mso_mdoc` remains allowed in this repo even though the current CS-02 text primarily targets SD-JWT-VC.
- `dc_api` and `dc_api.jwt` remain supported compatibility/future-CS-02 modes and should not be rejected solely because the current CS-02 profile does not emphasize them.
- `trusted_authorities` remains advisory until a trust registry is configured.
- Missing SD-JWT-VC status remains allowed by default until status-list issuer trust exists.
- x509 chain/SAN and verifier-attestation trusted issuer enforcement remain intentionally skipped until trust anchors/trusted issuers are configured.
- Compatibility behavior must be explicit and must not silently weaken strict CS-02 routes.
