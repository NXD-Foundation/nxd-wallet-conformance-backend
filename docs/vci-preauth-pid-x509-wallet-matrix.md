# VCI 1.0 Wallet Matrix for Pre-Auth PID SD-JWT X.509 Flow

This note is grounded in the current issuer implementation, starting from the pre-authorized offer route at [routes/issue/preAuthSDjwRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/preAuthSDjwRoutes.js#L107) and the shared token and credential handlers in [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L224).

## Baseline Test Case

The specific route under review returns a credential offer for:

- `grant_type = urn:ietf:params:oauth:grant-type:pre-authorized_code`
- `tx_code = present in offer metadata`
- `credential_configuration_id = urn:eu.europa.ec.eudi:pid:1`
- `format = dc+sd-jwt`
- issuer signature profile carried in session as `x509`
- proof type expected at `/credential` = `proofs.jwt`

The offer config is built here:

- [routes/issue/preAuthSDjwRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/preAuthSDjwRoutes.js#L107)
- [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js#L522)

The PID configuration is advertised here:

- [data/issuer-config.json](/home/ni/code/js/rfc-issuer-v1/data/issuer-config.json#L994)

## Summary Matrix

| Dimension | Value for This Test Case | Other Values Advertised or Implemented Here |
|---|---|---|
| Grant Type | `pre-authorized_code` | `authorization_code` via standardized and code-flow routes ([routes/issue/vciStandardRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/vciStandardRoutes.js#L38), [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L583)) |
| PAR | Not applicable to this pre-authorized flow | PAR is only relevant to the authorization-code flow in this repo |
| tx_code in Offer | `Yes` | `No` via `/offer-no-code` and `tx_code_required=false` |
| tx_code Enforcement | `Advertised, but not actually validated at /token_endpoint in current code` | Same current behavior for pre-auth flow; wallet should still support sending it per VCI |
| Wallet Invocation Scheme | `openid-credential-offer://` | `haip://` for HAIP routes and standardized `url_scheme=haip` |
| Credential Configuration | `urn:eu.europa.ec.eudi:pid:1` | Multiple other IDs in issuer metadata, including `jwt_vc_json` and `mso_mdoc` entries |
| Credential Format | `dc+sd-jwt` | `jwt_vc_json`, `mso_mdoc` |
| Binding Method | `jwk` | `cose_key` for `urn:eu.europa.ec.eudi:pid:1:mso_mdoc` |
| Proof Container | `proofs` object, VCI 1.0 style | Legacy `proof` is rejected |
| Proof Type for This Case | `jwt` | Code and tests indicate `cose_key` handling is expected for `mso_mdoc`, plus optional attestation proof paths in broader wallet-attestation logic |
| Proof Signing Alg | `ES256` | `ES256` only for the advertised PID SD-JWT config |
| Credential Signing Alg | `ES256` | `ES256` for JWT-based credentials, `-7` and `-9` for advertised `mso_mdoc` signing |
| Issuer Signature Reference in Credential | `x5c` JOSE header | `jwk`, `kid`, `did:web` are also implemented for issuer-side signing |
| Access Token Type | `bearer` by default | `DPoP` if wallet sends a valid DPoP proof at `/token_endpoint` |
| Client Authentication at Token Endpoint | `public` works | Metadata also advertises `attest_jwt_client_auth`, but current code treats WIA as optional and does not enforce it |
| Issuance Mode | `Immediate` by default | `Deferred` supported when session is marked deferred; wallet must poll `/credential_deferred` with `transaction_id` |
| Nonce Model | `c_nonce` from `/token_endpoint`, proof must echo it | `/nonce` endpoint also exists for fresh nonce retrieval |
| Selective Disclosure Model | SD-JWT VC | Wallet must process SD disclosures for the PID claim set advertised in metadata |

## Wallet Checks Required for This Test Case

For a wallet unit to pass this flow end-to-end, it should implement these checks and behaviors:

1. Parse the deep link and resolve `credential_offer_uri`.
2. Read `credential_configuration_ids` and confirm `urn:eu.europa.ec.eudi:pid:1` is supported.
3. Detect that the offer uses pre-authorized code and extract `pre-authorized_code`.
4. Detect `tx_code` metadata and be able to collect a numeric 4-digit code from the user.
5. Call `/token_endpoint` with the pre-authorized code.
6. Be able to send either bearer-style token requests or DPoP-bound token requests.
7. Capture `c_nonce` from the token response and use it in the proof JWT.
8. Build the credential request using `credential_configuration_id` or `credential_identifier`, but never both.
9. Use `proofs` and not legacy `proof`.
10. Send exactly one proof type in the `proofs` object.
11. For this case, send `proofs.jwt` as a string or non-empty array.
12. Sign the proof with `ES256`.
13. Put a holder public key in the proof header as either embedded `jwk` or a resolvable `kid` (`did:key`, `did:jwk`, `did:web`).
14. Set proof `aud` to the issuer base URL.
15. Include the `nonce` claim and keep it fresh.
16. For this repo’s authorization-code flow, include `iss`; for this pre-auth case it is not enforced.
17. Handle `invalid_proof` with refreshed `c_nonce` and retry.
18. Consume the issued credential as `dc+sd-jwt` and validate the issuer signature chain or key reference according to the JOSE header.

These checks are directly enforced in:

- request shape validation: [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L224)
- pre-auth token issuance and `c_nonce` creation: [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L518)
- proof validation and nonce replay handling: [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L1200)

## Issuer-Enforced Checks

The issuer currently enforces these at runtime:

- `credential_configuration_id` xor `credential_identifier`
- `proofs` must exist
- `proof` singular is rejected
- `proofs` must be a JSON object
- exactly one proof type key is allowed
- `proofs.jwt` must be a string or a non-empty array
- proof JWT header must contain `alg`
- proof JWT `alg` must match metadata for the requested credential config
- proof JWT must contain or resolve a usable holder public key
- proof JWT signature must verify
- proof JWT `aud` must match issuer URL
- proof JWT must contain a valid, unused `nonce`
- if WUA is present and valid, proof key must match one of `attested_keys`
- unknown or expired pre-authorized code is rejected
- DPoP, when present, is syntactically and cryptographically validated before issuing a DPoP-bound token

## Important Gaps Between Offer and Enforcement

These are the main places where a wallet implementer should distinguish spec intent from current repo behavior:

- PAR is not part of this pre-authorized flow; it applies only to the authorization-code endpoints.
- `tx_code` is advertised in the offer config, but the token endpoint code does not currently validate a submitted `tx_code` or `user_pin`.
- `attest_jwt_client_auth` is advertised in OAuth metadata, but WIA is currently optional and validation failure does not block issuance.
- For pre-authorized flow, DPoP is optional. If no DPoP header is sent, the issuer falls back to bearer tokens.
- The broader codebase supports multiple issuer signing references (`x5c`, embedded `jwk`, `kid`, `did:web`), but the exact test case here sets the session to `x509`.

## Practical Wallet Conformance Matrix

If you want to treat this test case as one row in a wallet test suite, the full wallet matrix for this issuer should at least cover:

| Dimension | Wallet Must Implement for Full Coverage |
|---|---|
| Offer Transport | `openid-credential-offer://`, `haip://`, raw `credential_offer_uri` retrieval |
| Grant Handling | `pre-authorized_code`, `authorization_code` |
| User Secret Step | no `tx_code`, `tx_code` prompt and submission |
| Token Binding | bearer, DPoP |
| Client Authentication | public, optional wallet attestation paths |
| Credential Formats | `dc+sd-jwt`, `jwt_vc_json`, `mso_mdoc` |
| Proof Types | `jwt` for SD-JWT and JWT VC, `cose_key` path for mdoc-class requests |
| Binding Methods | `jwk`, `cose_key` |
| Issuer Signature Reference | `x5c`, embedded `jwk`, `kid`, `did:web` |
| Issuance Timing | immediate, deferred polling |
| Error Recovery | `invalid_grant`, `invalid_proof`, nonce refresh, `authorization_pending`, `slow_down`, `invalid_transaction_id` |

## Recommended Single-Line Test Case Description

Pre-authorized VCI 1.0 issuance, `tx_code` offer variant, PID `dc+sd-jwt`, holder-bound with `proofs.jwt` (`ES256`), issuer-signed with `x5c`, immediate issuance, bearer-or-DPoP token binding, with nonce-based proof validation and optional wallet attestation checks.
