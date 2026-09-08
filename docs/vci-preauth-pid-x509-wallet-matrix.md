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

| Dimension | Value for This Test Case | `WALLET_PROFILE=webuild-cs01` (CS-01) | Other Values Advertised or Implemented Here |
|---|---|---|---|
| Grant Type | `pre-authorized_code` | Supported by default; dual-grant offers prefer `authorization_code` | `authorization_code` via standardized and code-flow routes ([routes/issue/vciStandardRoutes.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/vciStandardRoutes.js#L38), [routes/issue/sharedIssuanceFlows.js](/home/ni/code/js/rfc-issuer-v1/routes/issue/sharedIssuanceFlows.js#L583)) |
| PAR | Not applicable to this pre-authorized flow | Not used on pre-auth path; mandatory only for auth-code in CS-01 | PAR is only relevant to the authorization-code flow in this repo |
| tx_code in Offer | `Yes` | Wallet must collect PIN when `tx_code` is advertised; issuer validates at `/token_endpoint` | `No` via `/offer-no-code`, `/cs01-offer`, and `tx_code_required=false` |
| tx_code Enforcement | Validated when session advertises `txCodeRequired` | Wallet sends `tx_code` (or `pin` in `/issue` body); issuer rejects missing/wrong codes | CS-01 tx-code offer route: `GET /cs01-offer-tx-code` |
| Wallet Invocation Scheme | `openid-credential-offer://` | Same | `haip://` for HAIP routes and standardized `url_scheme=haip` |
| Credential Configuration | `urn:eu.europa.ec.eudi:pid:1` | Selected via top-level `credential_configuration_ids`; no grant `scope` | Multiple other IDs in issuer metadata, including `jwt_vc_json` and `mso_mdoc` entries |
| Credential Format | `dc+sd-jwt` | Same | `jwt_vc_json`, `mso_mdoc` |
| Binding Method | `jwk` | Wallet Unit subject key in proof JWT + `key_attestation` header | `cose_key` for `urn:eu.europa.ec.eudi:pid:1:mso_mdoc` |
| Proof Container | `proofs` object, VCI 1.0 style | Required | Legacy `proof` is rejected |
| Proof Type for This Case | `jwt` | Required with WUA key attestation binding | `cose_key` for `mso_mdoc`, plus optional attestation proof paths |
| Proof Signing Alg | `ES256` | `ES256` (negotiated from metadata) | `ES256` only for the advertised PID SD-JWT config |
| Credential Signing Alg | `ES256` | Same | `ES256` for JWT-based credentials, `-7` and `-9` for advertised `mso_mdoc` signing |
| Issuer Signature Reference in Credential | `x5c` JOSE header | Same validation expectations | `jwk`, `kid`, `did:web` also implemented for issuer-side signing |
| Access Token Type | `bearer` by default in compatibility mode | **DPoP only** — sender-constrained; DPoP generation failure is fatal | `DPoP` when wallet sends valid DPoP at `/token_endpoint` |
| Client Authentication at Token Endpoint | `public` works | **WUA headers required** (`OAuth-Client-Attestation` + PoP); no body `client_assertion` | WUA-required pre-auth fails closed; compatibility logs `[CS01_NON_COMPLIANCE]` |
| Token-request `authorization_details` | Often sent in compatibility flows | Omitted for single-config offers; required when offer lists multiple `credential_configuration_ids` | VCI v1.0 pre-auth grant does not carry `scope` |
| Issuance Mode | `Immediate` by default | Same; deferred polls honor issuer `interval` from 202 responses | `Deferred` via `/credential_deferred` with Bearer + DPoP |
| Nonce Model | `c_nonce` from `/token_endpoint`, proof must echo it | Same | `/nonce` endpoint also exists for fresh nonce retrieval |
| Selective Disclosure Model | SD-JWT VC | Same | Wallet must process SD disclosures for the PID claim set advertised in metadata |
| Pre-auth opt-out | N/A | Set `CS01_DISABLE_PRE_AUTHORIZED=true` to block pre-auth only; auth-code still works | See [cs01-pre-authorized-flow-relaxation-plan.md](./cs01-pre-authorized-flow-relaxation-plan.md) |

## Wallet Checks Required for This Test Case

For a wallet unit to pass this flow end-to-end, it should implement these checks and behaviors:

1. Parse the deep link and resolve `credential_offer_uri`.
2. Read `credential_configuration_ids` and confirm `urn:eu.europa.ec.eudi:pid:1` is supported.
3. Detect that the offer uses pre-authorized code and extract `pre-authorized_code`.
4. Detect `tx_code` metadata and be able to collect a numeric 4-digit code from the user.
5. Call `/token_endpoint` with the pre-authorized code.
6. Be able to send either bearer-style token requests or DPoP-bound token requests.
7. Capture `c_nonce` from the token response and use it in the proof JWT.
8. Build the credential request using returned `credential_identifier` values
   when Token Response authorization details contain them; otherwise use
   `credential_configuration_id`, but never both.
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
- In **compatibility** mode (`WALLET_PROFILE` unset), DPoP and WUA remain optional at the issuer; bearer tokens are still issued without DPoP.
- In **CS-01** mode (`WALLET_PROFILE=webuild-cs01`), the wallet always sends DPoP + WUA on pre-auth; bearer fallback is unreachable client-side.
- Issuer WUA validation on WUA-required pre-auth sessions is fail-closed (WIA headers, DPoP binding, and WIA/KA Token Status List bits). Compatibility-mode pre-auth still logs `[CS01_NON_COMPLIANCE]` without hard-failing optional/missing WUA.
- When `HAIP_PROFILE_REQUIRE_DPOP_FOR_TOKEN=true`, the issuer rejects pre-auth token requests without DPoP.
- `tx_code` is validated when the pre-auth session was created with `txCodeRequired` (see `createPreAuthSessionData()` in [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js)).
- The broader codebase supports multiple issuer signing references (`x5c`, embedded `jwk`, `kid`, `did:web`), but the exact test case here sets the session to `x509`.

## Practical Wallet Conformance Matrix

If you want to treat this test case as one row in a wallet test suite, the full wallet matrix for this issuer should at least cover:

| Dimension | Compatibility Mode | CS-01 (`webuild-cs01`) |
|---|---|---|
| Offer Transport | `openid-credential-offer://`, `haip://`, raw `credential_offer_uri` retrieval | Same |
| Grant Handling | `pre-authorized_code`, `authorization_code` | Both supported; dual-grant prefers auth-code |
| User Secret Step | no `tx_code`, `tx_code` prompt and submission | PIN required when offer advertises `tx_code` |
| Token Binding | bearer or DPoP | DPoP mandatory; fatal if generation fails |
| Client Authentication | public, optional wallet attestation | WUA headers only; no body `client_assertion` |
| Credential Selection | `authorization_details` common | Pre-auth: `credential_configuration_ids`; `authorization_details` only for multi-config |
| Credential Formats | `dc+sd-jwt`, `jwt_vc_json`, `mso_mdoc` | Same (per metadata) |
| Proof Types | `jwt` for SD-JWT/JWT VC; `cose_key` for mdoc | `jwt` + WUA `key_attestation` in proof header |
| Binding Methods | `jwk`, `cose_key` | Wallet Unit subject key |
| Issuer Signature Reference | `x5c`, embedded `jwk`, `kid`, `did:web` | Same |
| Issuance Timing | immediate, deferred polling | Deferred: honor issuer `interval`; stop on `invalid_transaction_id` / `credential_request_denied` |
| Error Recovery | `invalid_grant`, `invalid_proof`, nonce refresh | Same + explicit opt-out error when `CS01_DISABLE_PRE_AUTHORIZED=true` |
| Test Suite | `npm test` in `wallet-client/` | `npm run test:cs01` |

## CS-01 Deployment Quick Reference

For ITB+ or remote interop with Spherity-style pre-auth offers:

```bash
# wallet-client/docker-compose.yml or environment
WALLET_PROFILE=webuild-cs01
WALLET_CLIENT_ID=wallet-client
WALLET_ATTESTATION_SOURCE=local-key

# Optional: restore legacy auth-code-only CS-01 behavior
# CS01_DISABLE_PRE_AUTHORIZED=true
```

Issuer CS-01 pre-auth offer endpoints:

- `GET /cs01-offer` — pre-auth without `tx_code`
- `GET /cs01-offer-tx-code` — pre-auth with `tx_code`

Verify wallet grant policy: `GET http://localhost:4000/health` → `grantPolicy.preAuthorizedEnabled` should be `true`.

## Recommended Single-Line Test Case Description

**Compatibility:** Pre-authorized VCI 1.0 issuance, `tx_code` offer variant, PID `dc+sd-jwt`, holder-bound with `proofs.jwt` (`ES256`), issuer-signed with `x5c`, immediate issuance, bearer-or-DPoP token binding, with nonce-based proof validation and optional wallet attestation checks.

**CS-01:** Pre-authorized VCI 1.0 issuance with WUA + DPoP at token and credential endpoints, route-aware credential selection via `credential_configuration_ids`, optional `tx_code`, JWT proof with Wallet Unit key attestation, deferred polling with issuer `interval`, no bearer fallback.
