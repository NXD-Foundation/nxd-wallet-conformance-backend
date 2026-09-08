# WE BUILD CS-02 / FCAF Implementation Alignment Plan

## Source Baseline

This plan turns the findings in `FCAFs/we-build-cs02-fcaf-message-structure-coverage.md` into implementation work for this repo.

The CS-02-critical target is narrower than the full FCAF MessageStructure catalog. The implementation should prioritize:

- signed OpenID4VP authorization requests using JAR
- DCQL-only credential queries
- `openid4vp://?request_uri=...` wallet invocation
- SD-JWT-VC selective disclosure
- mandatory KB-JWT holder binding
- nonce and audience binding
- verifier metadata consistency
- strict Presentation Response validation

Broader FCAF areas such as ISO mdoc, CWT, JSON serialization credentials, multiple mdoc DeviceResponses, and OpenID Federation remain useful future interoperability work, but they are not the first alignment target for WE BUILD CS-02.

## Phase 1: Wallet Request Validation

Add a dedicated CS-02 request validation layer around the wallet presentation flow, centered on `wallet-client/src/lib/presentation.js`. The validator should run after parsing the deep link and fetching the request object, but before credential selection or presentation generation.

Required wallet checks:

- Treat `openid4vp://?request_uri=...` as the canonical CS-02 invocation form. Keep `openid4vp://present?...` only as explicit compatibility behavior.
- Require `request_uri` to be present and absolute.
- Require HTTPS `request_uri` in CS-02 mode. Allow HTTP only through an explicit local-development override.
- Allow only `request_uri_method=get` and `request_uri_method=post`; reject any other method before network fetch.
- For POST request-uri retrieval, send `Content-Type: application/x-www-form-urlencoded` and `Accept: application/oauth-authz-req+jwt`.
- Require request-uri responses to use `Content-Type: application/oauth-authz-req+jwt` in CS-02 mode.
- Require the request object to be a signed JWT/JAR.
- Reject `alg=none`, missing `alg`, RS256, ES256K, EdDSA, and any non-ES256 algorithm in CS-02 mode.
- Require the JAR protected header to contain `typ: oauth-authz-req+jwt`.
- Require the JAR signing key to be P-256 when `alg=ES256`.
- Require payload fields: `client_id`, `nonce`, `response_uri`, `response_type`, `response_mode`, `iat`, `exp`, and `dcql_query`.
- Require `response_type` to be exactly `vp_token`.
- Require `exp` to be in the future and within the accepted request lifetime.
- Require `iat` to be within accepted clock skew.
- Require `aud` to satisfy wallet audience policy. Default policy: accept `https://self-issued.me/v2` until a wallet-specific audience identifier is configured.
- If the deep link contains `client_id`, require it to equal the JAR `client_id`.
- Allow only CS-02 client identifier schemes: `x509_san_dns`, `verifier_attestation`, `did:web`, and `did:jwk`.
- Reject unsigned, unverifiable, expired, incomplete, or scheme-invalid requests before any credential lookup.

Client identifier trust checks:

- For `x509_san_dns`, verify the JAR signature with the x5c leaf key now. Certificate-chain validation against trust anchors and SAN DNS enforcement are intentionally skipped until trust anchors are configured; leave a clearly named placeholder validation method so the future trust-framework implementation has a stable integration point.
- For `did:web`, resolve the DID document over HTTPS, select the verification method from `kid`, and verify the JAR signature with the resolved P-256 public key.
- For `did:jwk`, decode the embedded JWK, require a P-256 public key, and verify the JAR signature.
- For `verifier_attestation`, parse and require the JOSE `jwt` header where present, but do not enforce trusted-issuer validation until trusted verifier-attestation issuers are configured. Leave a placeholder method for future validation of issuer trust, `sub` match, expiry, and JAR signing-key binding.

Expected wallet error behavior:

- Return or surface protocol-specific errors consistently: `invalid_request`, `invalid_request_uri`, `invalid_request_uri_method`, `invalid_client`, or `vp_formats_not_supported` where applicable.
- Log the failing check and received value shape without logging full credentials or private key material.

## Phase 2: Wallet DCQL And Presentation Generation Validation

Make wallet DCQL handling strict before `selectWalletCredentialTypeForDcql` is allowed to select credentials.

Required DCQL checks:

- Require `dcql_query` in CS-02 mode.
- Reject `presentation_definition` in CS-02 mode.
- Reject scope-only credential queries in CS-02 mode.
- Reject requests containing both `dcql_query` and `scope`.
- Require `dcql_query.credentials` to be a non-empty array.
- Require every credential query to have an `id`.
- Require each credential query `id` to be a non-empty string containing only `[A-Za-z0-9_-]`.
- Reject duplicate credential query ids.
- Require `format` to be present.
- Allow `dc+sd-jwt`, `vc+sd-jwt`, and `mso_mdoc` in the current implementation. `mso_mdoc` remains in practical project scope even though CS-02 does not explicitly require it yet.
- Treat `jwt_vc_json` and other formats as compatibility-mode only unless CS-02 scope is expanded.
- For SD-JWT-VC queries, validate `meta.vct_values` when present and use it for credential matching.
- If the verifier constrains credential type, require a satisfiable `meta.vct_values` match before selecting a stored credential.
- Validate `claims` as an array when present.
- Require every claim `path` to be a non-empty array using only supported JSON object-key path segments for the first implementation.
- Reject boolean, negative integer, empty, or malformed path segments.
- Require claim ids when `claim_sets` is present.
- Reject duplicate claim ids.
- Validate that every `claim_sets` reference points to an existing claim id.
- Validate `credential_sets` as non-empty options arrays when present.
- Reject `credential_sets` options that reference unknown credential query ids.
- Implement `multiple=false` as the default.
- For `multiple=true`, implement multi-credential response generation instead of rejecting. Return all matching credentials for that credential query id, preserving the DCQL response object shape.
- Treat `trusted_authorities` as advisory until a trust registry is configured. Ignore it for matching/enforcement for now, log that it was ignored, and leave a placeholder method for future trust-registry validation.
- Reject `require_cryptographic_holder_binding=false` for SD-JWT-VC in CS-02 mode because KB-JWT is mandatory.

Required presentation-generation checks:

- Select credentials only after format, `vct`, claim, holder-binding, and credential-set constraints are satisfied.
- Do not add unsolicited SD-JWT disclosures beyond requested claims.
- Fail when a requested disclosure cannot be found in the stored SD-JWT.
- Generate a KB-JWT for every SD-JWT-VC presentation.
- KB-JWT must include `typ: kb+jwt`, `nonce`, `aud`, `iat`, and `sd_hash`.
- KB-JWT must be signed with the private key corresponding to the credential `cnf.jwk`.
- The `aud` value must be the verifier `client_id`.
- The `sd_hash` must be computed over the presented SD-JWT without the KB-JWT.
- `vp_token` for DCQL must be an object keyed by credential query id.
- Each `vp_token` member value must be a string or array of strings according to the `multiple` policy.
- If no credential satisfies the query, return an `access_denied` or equivalent protocol error rather than falling back to an unrelated credential.

## Phase 3: Verifier Request Generation Hardening

Harden CS-02 request generation around `utils/cryptoUtils.js` and the standardized VP request route.

Required verifier request checks:

- CS-02 request generation must always produce signed JARs.
- CS-02 JAR signing must use ES256 with a P-256 key.
- RS256 request signing must be removed from CS-02 routes or isolated behind a non-CS-02 compatibility flag.
- Request JWT header must include `typ: oauth-authz-req+jwt`.
- Request JWT payload must include `client_id`, `nonce`, `state`, `response_uri`, `response_type: vp_token`, `response_mode`, `iat`, `exp`, and `dcql_query`.
- Request JWT payload must not include `presentation_definition` in CS-02 mode.
- Default request lifetime should remain short, with `exp` no more than five minutes after `iat`.
- `response_mode` must be one of the modes the verifier actually validates. Default CS-02 mode should be `direct_post`; `direct_post.jwt` is allowed only when response JWT/JWE validation is enforced.
- Continue supporting `dc_api` and `dc_api.jwt`. Do not reject these modes solely because CS-02 does not currently emphasize them; they are expected to be added to CS-02 later. Track any stricter validation needed for those modes as follow-up work.
- Generated `dcql_query` must satisfy the same structural rules expected from external requests.
- Verifier metadata must advertise only the algorithms, credential formats, response modes, and encryption algorithms that are actually enforced.

Transaction data checks:

- If `transaction_data` is present, each entry must be base64url-encoded JSON.
- Decoding failures must be fatal in CS-02 mode.
- `type` must be a non-empty string from the supported transaction-data type allowlist.
- `credential_ids`, when present, must be a non-empty string array.
- Every `credential_ids` entry must match a DCQL credential query id.
- If `credential_ids` is omitted, document and implement the policy that the transaction data applies to all DCQL credential queries.

Client identifier generation checks:

- `x509_san_dns` CS-02 requests should use ES256/P-256 signing. SAN DNS and certificate-chain trust-anchor validation should remain placeholder/TODO work until trust anchors are configured.
- `did:web` CS-02 requests must use a resolvable DID document and a `kid` that resolves to the signing key.
- `did:jwk` CS-02 requests must embed a P-256 public JWK in the DID.
- `verifier_attestation` CS-02 requests may continue using the current development attestation path until trusted verifier-attestation issuers are configured. Keep a placeholder production validation method and clearly mark self-signed attestation as non-production.

## Phase 4: Verifier Response Validation Hardening

Harden response processing around `routes/verify/verifierRoutes.js`.

Required response-mode checks:

- For `direct_post`, require form-encoded `vp_token` and matching `state`.
- For `direct_post.jwt`, require a `response` parameter.
- Reject bare `vp_token` submissions when the stored session expects `direct_post.jwt`.
- Reject response modes that do not match the stored verifier session.
- Surface wallet-reported `error` and `error_description`, store them on the session, and return stable protocol errors.

Required `direct_post.jwt` checks:

- If `response` is JWE, decrypt with the configured verifier key.
- Require JWE `alg`, `enc`, and `kid` to match allowed verifier metadata.
- If `response` is an unencrypted JWT, verify the outer JWT signature before reading payload claims.
- Validate outer response JWT `iss`, `aud`, `iat`, `exp`, and `state`.
- Require `aud` to match the verifier `client_id`.
- Require `state` to match the stored session state.
- Reject expired response JWTs and response JWTs issued outside accepted clock skew.

Required DCQL response checks:

- If the request used DCQL, require `vp_token` to be a JSON object.
- Require the object to contain exactly the expected credential query ids unless the request explicitly allowed optional credential sets.
- Missing expected credential ids must be fatal, not warning-only.
- Unknown credential ids must be rejected.
- Each credential value must be a string or array of strings according to the request `multiple` policy.
- Empty arrays must be rejected.
- Multiple returned credentials must be rejected unless `multiple=true` was requested and implemented.

Required SD-JWT-VC checks:

- Require a KB-JWT for every SD-JWT-VC in CS-02 mode.
- Require KB-JWT `typ: kb+jwt`.
- Require KB-JWT `nonce` to match the stored session nonce.
- Require KB-JWT `aud` to match the verifier `client_id`.
- Require KB-JWT `iat` to be within accepted clock skew.
- Require KB-JWT `sd_hash`.
- Recompute `sd_hash` from the presented SD-JWT and compare it.
- Verify KB-JWT signature using the public key from the credential `cnf.jwk`.
- Verify the SD-JWT-VC issuer signature and issuer trust chain or configured issuer key.
- Verify the presented disclosures resolve correctly against the issuer-signed SD-JWT.
- Verify requested claims are present and no unsolicited claims are accepted in CS-02 strict mode.
- Reject credentials missing `cnf.jwk` when holder binding is required.

Session and result checks:

- On any validation failure, set the session status to failed and store a precise error code.
- On success, store validated claims only after all response, holder-binding, and credential checks pass. Invoke status/trust placeholder checks, but do not require trust-framework-dependent status enforcement until that framework exists.
- Avoid persisting raw credentials, private keys, or full status-list tokens in session logs.

## Phase 5: Trust, Status, And Metadata Policy

Prepare shared trust and status policy used by both wallet and verifier. Because this repo does not currently have configured trust anchors or trusted verifier-attestation issuers, Phase 5 implementation should add stubs, TODOs, and integration points rather than enforcing trust-anchor-backed validation immediately.

Status-list validation:

- Add a placeholder JOSE `status.status_list` validation module for SD-JWT-VC credentials.
- Stub checks for `status.status_list.idx` as a non-negative integer and `status.status_list.uri` as an absolute HTTPS URI.
- Leave status-list token fetch, signature validation, bitstring decoding, and revoked/suspended decisions as TODOs until trusted status-list issuers are configured.
- Do not fail presentations solely for missing status in the current implementation unless a CS-02 strict status-validation flag is explicitly enabled.
- Document the intended future behavior: in full CS-02 conformance mode, reject missing, malformed, suspended, or revoked status once the trust framework exists.
- Leave cache/timeout/maximum response-size behavior as TODOs attached to the placeholder status-list validator.

Trust policy:

- Add placeholder methods for configured trust anchors for `x509_san_dns`.
- Add placeholder methods for x5c chain validation and SAN DNS match to `client_id` host.
- Do not enforce x5c trust-chain or SAN DNS validation until trust anchors are configured.
- Add placeholder methods for trusted verifier-attestation issuers.
- Add placeholder methods for verifier attestation `iss`, `sub`, `exp`, `iat`, and key-binding claims.
- Do not enforce verifier-attestation trusted-issuer validation until trusted issuers are configured.
- Define DID trust rules for `did:web` and `did:jwk`.
- For `did:web`, require HTTPS resolution and reject unresolved or mismatched `kid`.
- For `did:jwk`, require allowed key type, curve, and algorithm.

Metadata policy:

- Publish verifier metadata that matches actual runtime enforcement.
- Ensure metadata does not advertise unsupported signing algorithms, response modes, credential formats, or encryption algorithms.
- Define precedence rules:
  - signed request object values override request URI query values
  - request URI query values must not contradict signed request object values
  - inline `client_metadata` must be schema-valid
  - `client_metadata_uri`, if supported, must be HTTPS and must resolve to schema-valid metadata
- Document any compatibility exceptions separately from CS-02 conformance mode.

## Test Plan

Add or expand tests in root verifier suites and wallet-client suites.

Wallet tests:

- Add wallet request validation tests under `wallet-client/test/`.
- Extend `wallet-client/test/dcqlCredentialSelection.test.js` for strict DCQL validation.
- Extend `wallet-client/test/sdJwtDisclosureSelection.test.js` for unsolicited and missing disclosure behavior.
- Extend `wallet-client/test/presentationKeyBinding.test.js` for KB-JWT key-source and `cnf.jwk` binding behavior.
- Keep `wallet-client/test/openid4vpUri.test.js` as the canonical invocation test suite.

Verifier tests:

- Extend `tests/directPostJwt.test.js` and `tests/verifierRoutesDirectPostJwt.test.js` for response JWT/JWE validation.
- Extend `tests/sdJwtKeyBinding.test.js` for KB-JWT negative cases.
- Add tests around `utils/cryptoUtils.js` request generation for CS-02 JAR constraints.
- Add placeholder status-list validation tests for SD-JWT-VC credentials. Mark network fetch, issuer trust, and revoked/suspended status decisions as TODO until the trust framework exists.

Required negative scenarios:

- Reject missing JAR `typ`.
- Reject wrong JAR `typ`.
- Reject `alg=none`.
- Reject RS256 in CS-02 mode.
- Reject expired JAR.
- Reject missing `client_id`.
- Reject missing `nonce`.
- Reject missing `dcql_query`.
- Reject HTTP `request_uri` in CS-02 mode.
- Reject wrong request-uri content type.
- Reject unsupported `request_uri_method`.
- Reject both `dcql_query` and `scope`.
- Reject duplicate DCQL credential ids.
- Reject invalid DCQL id characters.
- Reject missing DCQL format.
- Reject unsupported DCQL format.
- Reject invalid claim paths.
- Reject invalid `credential_sets` references.
- Reject SD-JWT-VC without KB-JWT.
- Reject KB-JWT wrong nonce.
- Reject KB-JWT wrong audience.
- Reject KB-JWT wrong `sd_hash`.
- Reject KB-JWT signed by a key other than credential `cnf.jwk`.
- Reject `direct_post.jwt` with invalid outer JWT signature.
- Reject `direct_post.jwt` with wrong `aud`.
- Reject DCQL response missing an expected credential id.
- Reject unknown DCQL response credential ids.
- Stub malformed status-list claim handling and document the intended future rejection behavior.
- Stub revoked or suspended credential handling and document the intended future rejection behavior.

Required positive scenario:

- Accept a CS-02 happy path with:
  - `openid4vp://?request_uri=...`
  - HTTPS request-uri retrieval
  - ES256/P-256 signed JAR
  - `typ: oauth-authz-req+jwt`
  - valid DCQL SD-JWT-VC query
  - valid SD-JWT-VC disclosure set
  - valid KB-JWT with nonce, audience, `sd_hash`, and `cnf.jwk` binding
  - status-list validation stub invoked without enforcing trust-framework-dependent decisions
  - successful verifier response

Commands:

```bash
npm test
cd wallet-client && npm test
npx mocha tests/sdJwtKeyBinding.test.js tests/verifierRoutesDirectPostJwt.test.js
cd wallet-client && npx mocha test/dcqlCredentialSelection.test.js
```

## Acceptance Criteria

The implementation is aligned with this plan when:

- Every CS-02-critical gap in `FCAFs/we-build-cs02-fcaf-message-structure-coverage.md` maps to an implemented wallet-client check, verifier check, shared trust/status policy, or documented compatibility exception.
- CS-02 strict mode rejects unsigned, weakly signed, expired, incomplete, or unverifiable authorization requests.
- CS-02 strict mode requires DCQL and rejects malformed DCQL before credential selection.
- Wallet-generated SD-JWT-VC presentations include a valid KB-JWT bound to nonce, audience, `sd_hash`, and credential `cnf.jwk`.
- Verifier validates response mode, state, nonce, audience, DCQL response shape, KB-JWT, SD-JWT issuer authenticity, and disclosure integrity before marking a session successful. Status-list and trust-anchor-backed checks have callable placeholders/TODOs until the trust framework exists.
- Verifier metadata accurately reflects the runtime-supported CS-02 algorithms, formats, response modes, and encryption options.
- Tests cover the required positive and negative scenarios listed above.
- Legacy compatibility behavior is isolated behind explicit flags or routes and is not silently accepted in CS-02 conformance mode.

## Assumptions And Defaults

- CS-02 conformance mode is strict by default.
- Legacy compatibility exceptions must be explicitly named and must not weaken CS-02 routes.
- Allowed current credential formats are `dc+sd-jwt`, `vc+sd-jwt`, and `mso_mdoc`.
- Allowed CS-02 signing algorithm is ES256.
- Required signing curve is P-256.
- Allowed CS-02 client identifier schemes are `x509_san_dns`, `verifier_attestation`, `did:web`, and `did:jwk`.
- Default wallet audience policy accepts `https://self-issued.me/v2` until a wallet-specific audience identifier is configured.
- Missing SD-JWT-VC status is not rejected by default until the status/trust framework exists. The plan keeps placeholder validators and documents future strict behavior.
- CWT, JSON serialization credentials, multiple mdoc DeviceResponses, and OpenID Federation remain lower-priority broader FCAF work unless the project scope is expanded. Single `mso_mdoc` presentation remains in current practical scope.
