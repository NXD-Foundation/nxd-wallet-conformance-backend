# Expanded RFC Issuer / Verifier Gap Report Against OIDF Conformance Suite

Date: 2026-04-10

## Scope

This is a supplement to `reports/rfc-issuer-vci-vp-gap-report.md`. It keeps the original issuer/verifier comparison intact and adds gaps found by widening the scan to:

- OIDF VCI issuer happy-flow internals and response validators.
- OIDF VCI wallet test plan and emulated issuer checks.
- OIDF OpenID4VP Final and ID3 wallet test plans.
- Existing implementation notes and tests in `/home/ni/code/js/rfc-issuer-v1`.

The additional wallet-plan findings are role-specific. They only apply if `rfc-issuer-v1` is expected to behave as, or regression-test, a wallet/client. They should not be counted as issuer/verifier server gaps unless that role is in scope.

## Additional Sources Reviewed

OIDF conformance suite:

- `src/main/java/net/openid/conformance/vci10wallet/VCIWalletTestPlan.java`
- `src/main/java/net/openid/conformance/vci10wallet/AbstractVCIWalletTest.java`
- `src/main/java/net/openid/conformance/vci10wallet/VCIWalletTestCredentialIssuance.java`
- `src/main/java/net/openid/conformance/vci10wallet/VCIWalletTestCredentialIssuanceWithNotification.java`
- `src/main/java/net/openid/conformance/vci10wallet/VCIWalletTestCredentialIssuanceUsingScopesWithoutAuthorizationDetailsInTokenResponse.java`
- `src/main/java/net/openid/conformance/vp1finalwallet/VP1FinalWalletTestPlan.java`
- `src/main/java/net/openid/conformance/vp1finalwallet/AbstractVP1FinalWalletTest.java`
- `src/main/java/net/openid/conformance/vpid3wallet/VPID3WalletTestPlan.java`
- `src/main/java/net/openid/conformance/vpid3wallet/AbstractVPID3WalletTest.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerHappyFlow.java`
- `src/main/java/net/openid/conformance/vci10issuer/VCIIssuerHappyFlowAdditionalRequests.java`
- `src/main/java/net/openid/conformance/vci10issuer/condition/statuslist/VCIValidateCredentialValidityByStatusListIfPresent.java`

RFC issuer/verifier:

- `/home/ni/code/js/rfc-issuer-v1/docs/vci-preauth-pid-x509-wallet-matrix.md`
- `/home/ni/code/js/rfc-issuer-v1/docs/vci-authorization-code-wallet-matrix.md`
- `/home/ni/code/js/rfc-issuer-v1/docs/vp-verification-wallet-matrix.md`
- `/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js`
- `/home/ni/code/js/rfc-issuer-v1/routes/issue/preAuthSDjwRoutes.js`
- `/home/ni/code/js/rfc-issuer-v1/routes/verify/vpStandardRoutes.js`
- `/home/ni/code/js/rfc-issuer-v1/utils/credentialResponseEncryption.js`
- `/home/ni/code/js/rfc-issuer-v1/utils/credGenerationUtils.js`
- `/home/ni/code/js/rfc-issuer-v1/tests/sharedIssuanceFlows.test.js`
- `/home/ni/code/js/rfc-issuer-v1/tests/metadataDiscovery.test.js`
- `/home/ni/code/js/rfc-issuer-v1/tests/issuerSigningAlignment.test.js`
- `/home/ni/code/js/rfc-issuer-v1/wallet-client`

## New Or Sharpened Gaps


| Area                                                   | OIDF behavior                                                                                                                                                              | RFC issuer status | Notes                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pre-authorized flow `tx_code` validation               | VCI wallet test emulated issuer validates submitted `tx_code` against the expected value.                                                                                  | Missing           | The repo docs explicitly say `tx_code` is advertised but not validated at `/token_endpoint`. Tests cover offer shape, not rejection of missing/wrong `tx_code`.                                                                                                                  |
| Signed issuer metadata                                 | OIDF issuer test requests `Accept: application/jwt`, verifies `application/jwt`, and decodes signed issuer metadata if present.                                            | Missing           | Confirmed again in `routes/metadataroutes.js`: metadata endpoints return JSON and do not branch on `Accept: application/jwt`.                                                                                                                                                    |
| Access token in query parameters                       | OIDF issuer negative test fails a request containing `access_token` in the query.                                                                                          | Missing           | Still no equivalent explicit route guard or regression found for `/credential?access_token=...` or `/credential_deferred?access_token=...`.                                                                                                                                      |
| Encrypted credential response with `zip=DEF`           | OIDF happy flow makes a second encrypted credential request with DEFLATE compression and checks the credential response compression.                                       | Partial           | `utils/credentialResponseEncryption.js` implements `zip === "DEF"`, but explicit end-to-end test coverage was not found.                                                                                                                                                         |
| Deferred credential response strictness                | OIDF treats `transaction_id` responses as deferred issuance, expects HTTP 202 warning/compatibility, and requires numeric `interval`. It then polls the deferred endpoint. | Partial           | `rfc-issuer-v1` has deferred routes and tests for `transaction_id`/`interval`, but some API-backed tests accept `200/400/500` while sessions are not fully wired. Tighten this into deterministic 202 then 200 polling tests.                                                    |
| Unknown keys in credential response/error response     | OIDF warns on credential response fields outside `credentials`, `transaction_id`, `notification_id`, `interval`, and similarly checks credential error responses.          | Partial           | Repo tests assert some response shapes, but no centralized unknown-field rejection/warning-equivalent coverage was found.                                                                                                                                                        |
| HAIP credential validity checks                        | OIDF validates HAIP SD-JWT VC validity via `exp` or `status`, checks `exp`, fetches `status_list.uri`, decodes status list, and requires valid status.                     | Partial / Missing | Repo can embed `status_reference` and has some WUA/status examples, but I did not find full status-list token retrieval/decoding validation or HAIP validity regression coverage.                                                                                                |
| HAIP SD-JWT issuer `x5c` header                        | OIDF requires `x5c` in HAIP SD-JWT credential headers.                                                                                                                     | Partial           | `issuerSigningAlignment.test.js` verifies x509 issuance signs with the key matching `x5c`, but there is no broader HAIP-profile assertion that all required SD-JWT VC credentials include `x5c`.                                                                                 |
| Credential signing certificate must not be self-signed | OIDF VCI wallet setup rejects a self-signed credential signing certificate.                                                                                                | Partial / Missing | Repo has x509 signing alignment tests, but `utils/cryptoUtils.js` also contains comments indicating a self-signed verifier-attestation JWT path. Clarify whether credential issuer signing certificates are expected to be non-self-signed in HAIP mode and add a specific test. |
| Nonce endpoint cache headers                           | OIDF issuer-side nonce endpoint validation checks HTTP 200 JSON, `Cache-Control: no-store`, and nonce response schema.                                                     | Partial           | `/nonce` route tests assert `c_nonce`/`c_nonce_expires_in`, but I did not find a strict `Cache-Control: no-store` assertion.                                                                                                                                                     |
| FAPI interaction and resource headers                  | OIDF additional request tests send IPv6 `x-fapi-customer-ip-address`, UTF-8 JSON `Accept`, permissive `Accept`, and expect successful credential endpoint handling.        | Missing           | This is operational/conformance hardening rather than core VCI semantics. Not covered in repo tests.                                                                                                                                                                             |
| mso_mdoc issuer response validation                    | OIDF parses VCI mdoc credential as `IssuerSigned` and validates the mdoc issuer signature.                                                                                 | Partial           | Repo has mdoc generation and route tests, but several metadata tests still allow `400/500` for mdoc proof-type migration. Add a deterministic OIDF-style happy path for `mso_mdoc` if that profile is in scope.                                                                  |


## Wallet-Role Gaps

These are only gaps if `rfc-issuer-v1/wallet-client` or the service’s tests are intended to cover wallet/client behavior.

### VCI Wallet

OIDF’s VCI wallet plan uses an emulated issuer and authorization server. It expects the wallet to:

- Resolve issuer metadata and OAuth authorization server metadata from correct well-known URLs.
- Support wallet-initiated and issuer-initiated authorization-code flows.
- Use PAR before authorization in authorization-code flow.
- Preserve `issuer_state` from credential offer to authorization request.
- Support pre-authorized code flow, including `tx_code` submission when required.
- Call the nonce endpoint before the credential endpoint.
- Send VCI 1.0 `proofs` rather than legacy singular `proof`.
- Support immediate and deferred credential issuance.
- Support encrypted and plain credential responses.
- Handle token responses with and without `authorization_details`, falling back to scope-driven behavior where configured.
- Support notification endpoint calls when `notification_id` is returned.
- Support `mtls`, `private_key_jwt`, and `attest_jwt_client_auth` client-auth variants, plus DPoP and mTLS sender-constrained tokens.

`rfc-issuer-v1` covers many server-side counterparts, but I did not find a full wallet-client conformance regression for this matrix. The largest concrete wallet-role gaps are `tx_code` handling, deterministic deferred polling, and strict encrypted response handling from the wallet side.

### OpenID4VP Wallet

OIDF’s VP wallet plans include more negative checks than the verifier plans:

- Happy flow without `state`.
- Happy flow with `state`, longer nonce, longer state, and redirect returned from `response_uri`.
- Negative test where `response_uri` is not valid for the client identifier.
- Negative test where the request object signature is invalid.
- For Final/DCQL flows: validate DCQL, warn on unknown DCQL properties, reject `presentation_submission`, and expect `vp_token` keyed by DCQL query IDs.
- For ID3/presentation-exchange variants: validate `presentation_submission`.
- For encrypted response modes: check JWE header `cty`, `alg`, `enc`, `kid`, and body restrictions such as no `iss`/`exp`/`aud`.
- For SD-JWT presentations: verify KB-JWT signature, `typ`, `iat`, `aud`, `nonce`, `sd_hash`, and warn on unexpected binding-JWT header parameters/claims.
- For mdoc direct_post.jwt in ID3: validate JWE `apu`/`apv` nonce behavior.
- For callback redirects: require GET, empty query, and fragment containing `code_verifier`.

`rfc-issuer-v1` has stronger verifier-side state/nonce/SD-JWT checks than the OIDF verifier happy-flow plan, but I did not find wallet-client coverage for the negative wallet scenarios above.

## Highest-Value Additions Beyond The First Report

1. Enforce `tx_code` / `user_pin` for pre-authorized-code offers that advertise `tx_code`.
2. Add deterministic deferred issuance tests: `/credential` returns 202 with `transaction_id` and numeric `interval`, `/credential_deferred` polls and returns the credential.
3. Add nonce endpoint header assertions, especially `Cache-Control: no-store`.
4. Add compressed encrypted credential-response end-to-end test for `zip=DEF`.
5. Add response-shape strictness checks for unknown fields in credential success and error responses.
6. Add HAIP SD-JWT VC validity/status-list and `x5c` profile tests if HAIP certification parity matters.
7. Add wallet-client conformance tests only if the wallet role is in scope: invalid VP request object signature, invalid `response_uri`, VP redirect callback behavior, encrypted response JWE header/body hygiene, and VCI `tx_code`/deferred/encrypted-response handling.

## Relationship To The First Report

The first report remains accurate for the issuer/verifier server roles. This expanded report adds:

- concrete pre-authorized `tx_code` enforcement as a new high-value issuer gap;
- stricter deferred, nonce, status-list, and response-shape gaps;
- wallet-role gaps that were outside the first report’s stated scope.

