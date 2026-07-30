# Project Knowledge Base

## Purpose

This is the implementation-oriented entry point for the project. It maps the
profile-specific requirements in [RFC001](./core/RFC001.md),
[RFC002](./core/RFC002.md), and [RFC004](./core/RFC004.md) to the current
issuer, verifier, wallet client, configuration, and automated tests. The
APTITUDE RFCs are deltas/profiles, not replacements for their base standards.

It is not a claim that every requirement is implemented. For interoperability
or conformance decisions, read the linked specification first, then confirm
the current code and tests. Keep this document current when changing a
protocol boundary, security control, or declared support level.

## System At A Glance

The repository contains a Node.js/Express service with three cooperating
roles:

| Role | Primary implementation | Purpose |
| --- | --- | --- |
| Credential issuer | `routes/issue/`, `utils/credGenerationUtils.js` | OpenID4VCI 1.0 issuance using authorization-code and pre-authorized-code grants |
| Verifier / relying party | `routes/verify/`, `utils/mdlVerification.js` | OpenID4VP 1.0 request creation and presentation processing |
| Wallet test client | `wallet-client/src/` | Exercises discovery, issuance, proofs, presentation, and notifications |

The public protocol model is configuration-driven:

- [issuer-config.json](../data/issuer-config.json) publishes credential
  configurations, formats, endpoints, and credential-response encryption.
- [oauth-config.json](../data/oauth-config.json) publishes OAuth/PAR/PKCE,
  client-attestation, DPoP, and grant capabilities.
- [verifier-config.json](../data/verifier-config.json) publishes verifier
  identity, supported presentation formats, encryption keys, and algorithms.

`server.js` mounts every route module at the service root, except the mdoc
request helpers mounted under `/mdl`. Redis-backed state in
`services/cacheServiceRedis.js` correlates issuance, authorization-code,
presentation, deferred-issuance, and logging sessions. Tests may run without
Redis when `NODE_ENV=test` or `ALLOW_NO_REDIS=true`.

### Test-service Docker signing material

This repository is used as an interoperability **test service**. Its Docker
image deliberately includes the local `private-key.pem`, `public-key.pem`,
`x509EC/`, and `certs/` signing material through `Dockerfile`'s `COPY . .`.
Those paths must therefore remain absent from `.dockerignore`, so a locally
built image can be pushed and deployed without separately copying test keys to
the server. `docker-compose.yml` may also mount the same files read-only for
local development. This is an intentional test-only convenience and must not
be copied into a production issuer image or registry workflow.

## Authority And Profile Boundaries

For every flow, first identify its base specification (for example OpenID4VCI,
OpenID4VP, OAuth, HAIP, SD-JWT VC, or ISO mdoc). That base specification and
its errata define the protocol by default. An APTITUDE RFC defines only the
requirements, constraints, or extensions it explicitly states for the
APTITUDE profile; it does not silently redefine, duplicate, or replace the
base specification.

Use the following interpretation order:

1. Apply the relevant base standard and its errata.
2. Apply an APTITUDE RFC requirement only where that RFC explicitly adds a
   constraint, selects an option, or states a profile-specific extension.
3. Where an explicit APTITUDE requirement conflicts with an optional or
   variable base-specification choice, the APTITUDE requirement governs the
   selected profile. Otherwise, retain the base-specification rule.
4. Current configuration, implementation, and automated tests describe what
   this deployment does; they do not create a normative APTITUDE requirement.
5. This page and focused project documents are navigation and design aids,
   not normative sources.

Do not infer an APTITUDE requirement from a route, test fixture, historical
compatibility path, or metadata value. Likewise, do not omit a base-spec
requirement merely because it is not repeated in an APTITUDE RFC.

The local reference inventory is maintained in
[references/README.md](./references/README.md). It contains the OpenID4VCI,
OpenID4VP, HAIP, ARF, IETF, and APTITUDE trust copies used by the core RFCs.
The valid ETSI PDF copies are present alongside earlier firewall-response
captures; the inventory identifies both. ISO 18013 material is referenced but
not mirrored as full text.

## FCAF Alignment

The Aptitude branch’s FCAF assessment is recorded in
[FCAFs/aptitude-fcaf-alignment-status.md](./FCAFs/aptitude-fcaf-alignment-status.md)
with its machine-readable companion
[FCAFs/aptitude-fcaf-applicability.json](./FCAFs/aptitude-fcaf-applicability.json).
It intentionally does not inherit main’s per-ID CS-02 coverage counts until
the supporting implementation and tests are ported and revalidated.

| APTITUDE profile delta | Base specifications that remain authoritative | Main implementation area |
| --- | --- | --- |
| [RFC001 issuance](./core/RFC001.md) | [OpenID4VCI](./references/openid/openid-4-verifiable-credential-issuance-1_0.html), [HAIP](./references/openid/openid4vc-high-assurance-interoperability-profile-1_0.html), [ARF](./references/eu/arf-v1.0.0.pdf) | `routes/issue/`, issuer metadata, wallet issuance libraries |
| [RFC002 presentation](./core/RFC002.md) | [OpenID4VP](./references/openid/openid-4-verifiable-presentations-1_0.html), [HAIP](./references/openid/openid4vc-high-assurance-interoperability-profile-1_0.html), [ARF](./references/eu/arf-v1.0.0.pdf) | `routes/verify/`, VP crypto/helpers, wallet presentation libraries |
| [RFC004 status and revocation](./core/RFC004.md) | [APTITUDE trust](./references/aptitude/deliverable-2.1-trust.html), [OAuth Status List draft](./references/ietf/draft-ietf-oauth-status-list.html), [RFC 5280](./references/ietf/rfc5280.txt), [RFC 6960](./references/ietf/rfc6960.txt) | WIA/WUA status hooks and credential status references; no CRL/OCSP/TSL provider routes |

## RFC001: Credential Issuance Profile

RFC001 adds APTITUDE issuance-profile requirements to OpenID4VCI and its
selected base specifications. Read OpenID4VCI/HAIP/ARF first for behavior not
explicitly profiled by RFC001. The standard shared endpoint implementation is
`routes/issue/sharedIssuanceFlows.js`; legacy and scenario-specific offer
routes are kept alongside it for interoperability coverage.

| RFC001 concern | Implementation mapping | Verification |
| --- | --- | --- |
| Discovery and issuer metadata | `routes/metadataroutes.js`; `data/issuer-config.json`; `data/oauth-config.json` | `tests/metadataDiscovery.test.js` |
| Credential offers and wallet invocation | `routes/issue/preAuthSDjwRoutes.js`, `routes/issue/codeFlowSdJwtRoutes.js`, `routes/issue/vciStandardRoutes.js`, `routes/multiCredentialOfferRoutes.js` | `tests/preAuthSDjwRoutes.test.js`, `tests/sharedIssuanceFlows.test.js` |
| Authorization-code grant | `POST /par` or `/authorize/par`, `GET /authorize`, then `POST /token_endpoint` | `tests/codeFlowSdJwtRoutes.test.js` |
| PAR and PKCE S256 | `routes/issue/codeFlowSdJwtRoutes.js` stores immutable PAR payloads, requires `request_uri` when configuration requires PAR, and validates S256; `validatePKCE` verifies the token request | `tests/codeFlowSdJwtRoutes.test.js` |
| Pre-authorized-code grant | offer routes above and `handlePreAuthorizedCodeFlow` in `sharedIssuanceFlows.js`. For multi-credential offers, each access token stores its own authorized configuration subset and issuance progress; a later exchange of the same test-service pre-authorized code cannot alter an earlier token's authorization. | `tests/preAuthSDjwRoutes.test.js`, `tests/sharedIssuanceFlows.test.js` |
| DPoP sender constraint | DPoP-bound token creation in `utils/tokenUtils.js`; resource proof verification in `validateDpopProofForResourceRequest` | issuance-flow tests and wallet `credentialNotification.js` |
| Credential proof and holder binding | `validateCredentialRequest`, `validateProofJWT`, and `verifyProofJWT`; wallet proof construction in `wallet-client/src/lib/credentialRequestProofs.js` | `tests/credGenerationUtilsProofBinding.test.js`, `tests/proofJwtResolver.test.js` |
| WIA at PAR/token | `validateWIA` in `utils/routeUtils.js`; OAuth client-attestation and PoP validation in `utils/oauthClientAttestation.js` | `tests/oauthClientAttestation.test.js`, `tests/wuaValidation.test.js` |
| WUA/key attestation at credential request | `validateWUA` and `utils/keyAttestationProof.js`; proof supports `proofs.jwt` and `proofs.attestation` paths. **Normative target (OpenID4VCI / HAIP):** an attestation proof must verify before issuance; decoded, unverified `attested_keys` must not be used as credential holder binding. When metadata advertises `proof_types_supported.jwt.key_attestations_required`, the JWT proof must carry a valid protected-header `key_attestation` and its signing key must match the primary attested key. **Temporary test-service deviation (2026-07):** for EUDI Reference Wallet interop, see [Temporary test-service relaxations](#temporary-test-service-relaxations-eudi-wallet-interop) below — tighten on the next spec-alignment pass. | `tests/keyAttestationProof.test.js`, `tests/wuaValidation.test.js`, `tests/sharedIssuanceFlows.test.js` |
| Immediate and deferred credentials | `POST /credential`, `POST /credential_deferred`, `resolveDeferredIssuanceContext` | `tests/sharedIssuanceFlows.test.js` |
| Nonce and notification | `POST /nonce`, `POST /notification`; wallet client notification helper | shared issuance tests and `wallet-client/src/lib/credentialNotification.js` |
| Credential response encryption | `utils/credentialResponseEncryption.js`; issuer metadata and wallet `credentialResponseEncryption.js` | `tests/credentialResponseEncryption.test.js` |
| Credential formats | SD-JWT VC/JWT VC generation in `utils/credGenerationUtils.js`; X.509 attribute credential support in `utils/issueX509AttrCredential.js`; mdoc configuration and generation helpers | `tests/issuerSigningAlignment.test.js`, `tests/mdocIssuerLeafCertificate.test.js` |

### Issuance Route Guide

The implementation uses deployment-specific paths, while metadata remains the
interoperable discovery surface.

| Endpoint | Role |
| --- | --- |
| `GET /vci/offer` | Standardized offer helper for authorization-code or pre-authorized issuance |
| `POST /par`, `POST /authorize/par` | PAR endpoint for authorization-code issuance |
| `GET /authorize` | Authorization step consuming the PAR `request_uri` |
| `POST /token_endpoint` | Authorization-code and pre-authorized token grants |
| `POST /credential` | Immediate credential issuance or deferred initiation |
| `POST /credential_deferred` | Deferred credential polling by `transaction_id` |
| `POST /nonce` | Credential-proof nonce issuance |
| `POST /notification` | Credential lifecycle notification receiver |
| `GET /.well-known/openid-credential-issuer` | Credential issuer metadata |
| `GET /.well-known/oauth-authorization-server` | Authorization server metadata |

### Local hotel + airline PNR multi-credential offer

For a localhost interoperability test, create a by-reference offer with the
following request. The response's `deepLink` is the URI to open in the wallet;
the wallet then sends consecutive standard `POST /credential` requests, one
for the hotel credential and one for the airline PNR credential.

```bash
curl -X POST http://localhost:3000/offer-no-code-batch \
  -H 'Content-Type: application/json' \
  -d '{
    "signatureType": "x509",
    "credentials": [
      {
        "credential_configuration_id": "booking_reference_credential",
        "payload": {
          "booking_reference": "OTA-MS62DP17-VQPSKP",
          "hotel_id": "9213",
          "hotel_name": "Test Hotel Rhodes",
          "arrival_date": "2026-07-31",
          "departure_date": "2026-08-04",
          "booking_platform": "SEDIT-X OTA Booking Portal"
        }
      },
      {
        "credential_configuration_id": "airline_pnr_credential",
        "payload": { "pnr": "Q7X2LM" }
      }
    ]
  }'
```

Put `signatureType: "x509"` in the JSON body (preferred for this POST), or as
a query parameter like `/vci/offer` / `/offer-no-code`. Either way the pre-auth
session stores `signatureType: "x509"` and issued SD-JWTs include an `x5c`
header. The EUDI Reference Wallet requires that for presentation; `kid`-only
signatures are stored but not presentable.

`airline_pnr_credential` is intentionally minimal: its only selectively
disclosable claim is the customer-facing PNR/record locator. It does not use
the separate Amadeus Flight Order ID or expose itinerary/passenger data.

### Local airline boarding pass offer

Issue an SD-JWT boarding pass with configuration id `airline_boarding_pass`
and VCT `urn:eu.aptitude:airline.boardingpass:1`. Prefer `signatureType: "x509"`
for EUDI Reference Wallet presentation.

```bash
curl -X POST http://localhost:3000/offer-no-code-batch \
  -H 'Content-Type: application/json' \
  -d '{
    "signatureType": "x509",
    "credentials": [
      {
        "credential_configuration_id": "airline_boarding_pass",
        "payload": {
          "pnr": "ABC123",
          "given_name": "NIKOS",
          "family_name": "MATKALAINEN",
          "passenger_name": "NIKOS MATKALAINEN",
          "carrier_name": "AEGEAN Connect",
          "carrier_code": "AC",
          "flight_number": "A3 604",
          "from": "ATH",
          "to": "HER",
          "departure_datetime": "2026-08-01T08:15:00+03:00",
          "arrival_datetime": "2026-08-01T09:05:00+03:00",
          "terminal": "Main",
          "gate": "B12",
          "boarding_time": "07:35",
          "seat": "14A",
          "boarding_group": "2",
          "sequence_number": "042",
          "cabin_class": "Economy",
          "ticket_number": "3901234567890",
          "baggage_allowance": "1 cabin bag + 1 personal item"
        }
      }
    ]
  }'
```

Present with `credential_profile=boarding_pass` (DCQL requests `pnr`,
`flight_number`, `seat`, `given_name`, `family_name`).

### EUDI Reference Wallet proof-metadata compatibility

The deployed EUDI Reference Wallet requires every advertised JWT proof type,
including `airline_pnr_credential`, to contain
`key_attestations_required: {}`. Keep that explicit empty object even though it
does not impose a key-storage or user-authentication constraint. Its presence
causes the wallet to use the key-attested JWT proof path, so the issuer must
continue to validate that proof as it does for the hotel credential. Removing
the field made this wallet version reject issuer metadata during parsing.

### EUDI Reference Wallet requires X.509-signed SD-JWT credentials for presentation

The EUDI Reference Wallet will **store** SD-JWT VCs signed with `kid` / JWK
(no `x5c`), but it will **not present** them. During OpenID4VP / DCQL matching
the wallet extracts claims via Multipaz `SdJwtVcCredential.getClaims`, which
requires an `x5c` certificate chain on the issuer-signed JWT and throws
`Only X509-certified keys are supported in SD-JWT` otherwise. That failure is
swallowed when building presentation candidates, so the UI shows
“The requested document is not available in your EUDI Wallet” even when the
credential is registered and the DCQL `vct_values` / claim paths match.

Observed symptoms when issuing with `kid-jwk` (e.g. `aegean#authentication-key`):

- At issuance: `issuerTrustResult=null`, `No certificate chain found`,
  `verifier.verify() returned null`
- At presentation: JAR `Resolution.Success`, then `request_no_data` / document
  not available; no `direct_post`

For EUDI wallet presentation interop, issue SD-JWT credentials (PID, airline
PNR, booking reference, etc.) with **X.509 / `x5c` signing**, not `kid`-only
JWK signatures.

### Temporary test-service relaxations (EUDI wallet interop)

The following are **intentional, temporary** deviations for local interoperability
with the EUDI Reference Wallet. They are **not** normative APTITUDE or
OpenID4VCI behaviour and **must be removed or tightened** on the next
spec-alignment / hardening update (configure proper Wallet Provider trust and
verification keys instead of relying on these fallbacks).

| Area | Current behaviour | Normative target | Code |
| --- | --- | --- | --- |
| `proofs.attestation` verification | When neither `key_attestation_jwks`, `wallet_unit_attestation_jwks`, nor `header.jwk` is available, the issuer logs a warning and binds the credential from **unverified** `attested_keys` in the decoded JWT (`signatureVerified: false`). | Verify the key-attestation / WUA JWS before issuance; bind only from a **verified** payload. Prefer `key_attestation_jwks` or `wallet_unit_attestation_jwks`, else `header.jwk`. | `utils/keyAttestationProof.js` (`verifyKeyAttestationProofChain`), `routes/issue/sharedIssuanceFlows.js` |
| WUA `iss` claim | Missing `iss` logs a warning; validation continues if structure and signature checks pass. | Reject or apply Wallet Provider trust policy on `iss` (Trusted List / registry). | `utils/routeUtils.js` (`validateWUA`) |
| Pre-authorized token response | Scope-only pre-auth exchange does **not** synthesize `authorization_details` with `credential_identifiers` (avoids EUDI wallet credential-request mismatch). | When returning `credential_identifiers`, wallets must request with `credential_identifier`; metadata should advertise `credential_identifiers_supported: true`. | `routes/issue/sharedIssuanceFlows.js` (`handlePreAuthorizedCodeFlow`) |

**Next alignment pass (TODO):** remove the unverified `attested_keys` fallback;
require configured WP verification material; re-enforce strict WUA `iss` and
trust-list policy; restore token `authorization_details` / identifier flow once
wallet and issuer agree on the identifying-credential path (OpenID4VCI §3.3.4 /
§8.2).

### RFC001 Boundaries

- The code implements both RFC001 grant variants, but a route being available
  does not make every scenario equally high-assurance. Verify the selected
  credential configuration, WIA/WUA policy, and sender constraint.
- `client_attestation_trusted_jwks` is empty by default in
  `data/oauth-config.json`. The code can cryptographically validate against
  configured keys, but the development fallback must not be treated as a
  production Wallet Provider trust framework.
- `isWuaWalletProviderTrustedByPolicy` and
  `isKeyAttestationTrustedByIssuer` are explicit trust-policy hooks. They are
  not a configured trusted-list implementation today.
- The configuration advertises `A128GCM` and `A256GCM` credential response
  encryption; request validation and JWE creation enforce the advertised
  parameters. Confirm the selected key-management algorithm with the wallet.

## RFC002: Credential Presentation Profile

RFC002 adds APTITUDE presentation-profile requirements to OpenID4VP and its
selected base specifications. Read OpenID4VP/HAIP/ARF and applicable ISO
material first for behavior not explicitly profiled by RFC002. The preferred
shared entry point is `GET /vp/request`; the repository also retains DID, DID
JWK, X.509, verifier-attestation, mdoc, and pilot-specific route families for
interoperability scenarios.

| RFC002 concern | Implementation mapping | Verification |
| --- | --- | --- |
| Verifier metadata | `routes/metadataroutes.js`; `data/verifier-config.json` | `tests/openidVerifierMetadata.test.js` |
| RFC002 same-device entry point | `GET /vp/etsi/same-device` and `GET /vp/request` in `routes/verify/vpStandardRoutes.js` | `tests/vpStandardRoutes.test.js` |
| Request object/JAR construction | `utils/cryptoUtils.js`, `utils/routeUtils.js`, and the identity-specific request routes | route tests for DID, DID JWK, X.509, and standard VP requests |
| Verifier identification | `routes/verify/didRoutes.js`, `didJwkRoutes.js`, `x509Routes.js`, and `verifierAttestationRoutes.js` | `tests/didRoutes.test.js`, `tests/didJwkRoutes.test.js`, `tests/x509Routes.test.js` |
| DCQL and Presentation Exchange requests | standard VP route and identity-specific `*DCQL*` helpers; definitions in `data/presentation_definition*.json` | `tests/presentationDefinition.test.js`, `tests/vpStandardRoutes.test.js` |
| Response modes | `POST /direct_post/:id` in `routes/verify/verifierRoutes.js`; handles `direct_post`, `direct_post.jwt`, `dc_api`, and `dc_api.jwt` session modes | `tests/directPostJwt.test.js`, `tests/verifierRoutesDirectPostJwt.test.js` |
| State and session correlation | `utils/vpSessionCorrelation.js` and verifier response handling | `tests/vpSessionCorrelation.test.js`, `tests/stateParameterSpec.test.js` |
| SD-JWT KB-JWT | `utils/sdJwtKeyBinding.js`; verifier checks the issuer credential `cnf.jwk`, KB-JWT signature, audience, nonce, and `sd_hash` | `tests/sdJwtKeyBinding.test.js` |
| mdoc/PID presentation | `utils/mdlVerification.js`, `routes/verify/mdlRoutes.js`, and mdoc branches in `verifierRoutes.js` | `tests/mdlVerification.test.js`, `tests/mdlRoutes.test.js`, `tests/walletClientMdocPresentation.test.js` |
| Encrypted VP responses | JWE decryption paths in `verifierRoutes.js`; verifier encryption capabilities in `data/verifier-config.json` | `tests/directPostJwt.test.js` |
| Transaction data / remote signing | `utils/cs03Validation.js`, `utils/cryptoUtils.js`, and session construction in `utils/routeUtils.js` | `tests/cs03Validation.test.js`, `tests/cs03RemoteSigning.test.js`, `tests/paymentTransactionDataHash.test.js` |

### Presentation Route Guide

| Endpoint family | Use |
| --- | --- |
| `GET /vp/request` | Shared configured OpenID4VP request entry point |
| `GET /vp/etsi/same-device` | RFC002 same-device profile helper |
| `POST /direct_post/:id` | Correlated presentation response endpoint |
| `GET /generateVPRequest*` | DID and X.509 scenario helpers |
| `GET /va/generateVPRequest*` | Verifier-attestation scenario helpers |
| `GET /mdl/generateVPRequest` | mdoc/PID-focused request helper |

### RFC002 Boundaries

- The service supports several historical route families. New generic work
  should start with `vpStandardRoutes.js`, the standard verifier metadata, and
  DCQL where the wallet supports it; keep Presentation Exchange paths for
  existing pilot compatibility.
- `verifyMdlToken` parses and validates the received mdoc `DeviceResponse`
  structure and requested claims. ISO remote mdoc transport/session binding
  has stricter requirements than simple payload decoding; validate the
  particular route and wallet flow before making an ISO 18013-7 conformance
  claim.
- SD-JWT key binding is actively checked. mdoc does not carry an SD-JWT
  KB-JWT, so its response path uses mdoc validation and state correlation
  instead of applying SD-JWT nonce rules.

## RFC004: Status, Revocation, And Trust Profile

RFC004 adds APTITUDE profile material for Wallet-side consumption of CRL,
OCSP, and Token Status List (TSL) information and provider interfaces. RFC
5280, RFC 6960, and the applicable Status List specification remain
authoritative for rules not explicitly profiled by RFC004. This repository is
primarily an issuer/verifier/wallet interoperability service, not a Provider
of WRPAC or WRPRC. Its implementation status is therefore intentionally
partial.

| RFC004 requirement area | Current mapping | Status |
| --- | --- | --- |
| Status references in issued credentials | `utils/credGenerationUtils.js` can include an upstream-provided status-list reference | Partial: issuance embeds a reference; it does not host a status list |
| WUA status-list parsing | `utils/vpHeplers.js` fetches and decompresses a Token Status List reference | Partial: a helper exists; this is not end-to-end trust-framework enforcement |
| WIA/WUA validation | `validateWIA` and `validateWUA` in `utils/routeUtils.js` validate JWT structure, signature material, expiry, and selected bindings | Partial: Wallet Provider trust-list policy is a hook, and revocation checking remains TODO |
| CRL provider endpoint | No route under `routes/` | Not implemented |
| OCSP provider endpoint | No route under `routes/` | Not implemented |
| TSL provider endpoint | No route under `routes/` | Not implemented |

Do not describe the project as RFC004-conformant for CRL, OCSP, or TSL service
provision. A production trust implementation needs configured trust anchors,
signature validation under those anchors, freshness and revocation checks, and
the RFC004 interfaces where the service assumes a provider role.

## Cross-Cutting Security Model

| Control | Code location | Notes |
| --- | --- | --- |
| OAuth client attestation | `utils/oauthClientAttestation.js` | Enforces JWT type, asymmetric algorithms, `cnf` hygiene, PoP audience and freshness; trust depends on configured JWKS |
| WIA and WUA | `utils/routeUtils.js`, `utils/keyAttestationProof.js` | Validates format/signature/bindings and exposes trust-policy gates. **Temporary:** see [Temporary test-service relaxations](#temporary-test-service-relaxations-eudi-wallet-interop) for unverified attestation binding and relaxed WUA `iss` — tighten on next spec-alignment pass. |
| DPoP | `utils/tokenUtils.js`, `sharedIssuanceFlows.js` | Binds tokens and resource requests to an EC JWK thumbprint |
| PKCE | `codeFlowSdJwtRoutes.js`, `sharedIssuanceFlows.js` | S256 is required for the authorization-code path |
| Credential proof | `sharedIssuanceFlows.js`, `utils/proofJwtResolver.js` | Resolves proof verification keys and validates holder proof constraints |
| SD-JWT presentation binding | `utils/sdJwtKeyBinding.js` | Ties KB-JWT signature to the issued credential’s `cnf.jwk` |
| Payload confidentiality | `utils/credentialResponseEncryption.js`, `verifierRoutes.js` | JWE encrypts credential responses and decrypts supported VP response modes |
| Session lifetime | `services/cacheServiceRedis.js` | Defaults to 180 seconds for VCI/VP sessions; configurable with environment variables |

### Recent Profile Hardening

- DPoP-bound access tokens must use the `DPoP` authorization scheme at issuer
  protected-resource endpoints; `Bearer` remains available only for unbound
  tokens.
- The wallet accepts standard JSON issuer metadata, does not require `openid`
  in optional AS `scopes_supported`, and uses `authorization_details` for a
  scope-less configuration only when the AS advertises `openid_credential`.
- RFC002 routes use prefixed DID verifier identifiers and publish a strict
  metadata projection at `/client-metadata/rfc002`; broad metadata remains for
  compatibility routes.
- Nested DCQL paths and requested values are checked before accepting extracted
  SD-JWT or mdoc presentation claims; mdoc namespace paths are normalized to
  the issuer-signed elements extracted by `verifyMdlToken`. TS-12 payment-SCA
  remains out of scope here.

## How To Navigate A Change

| Change area | Read first | Then inspect |
| --- | --- | --- |
| Offer, grant, PAR, token, credential, nonce, or deferred behavior | RFC001 and local OpenID4VCI | `routes/issue/`, issuer/OAuth config, shared issuance tests |
| Wallet attestation, WIA, WUA, or trust | RFC001, HAIP, ARF, RFC004 | `utils/routeUtils.js`, `utils/oauthClientAttestation.js`, `utils/keyAttestationProof.js`, WUA tests |
| Verifier request, metadata, DCQL, or response mode | RFC002 and local OpenID4VP | `routes/verify/`, verifier config, VP tests |
| SD-JWT holder binding | RFC002 and OpenID4VP | `utils/sdJwtKeyBinding.js`, `tests/sdJwtKeyBinding.test.js` |
| mdoc/PID | RFC002, ARF, applicable ISO material | `utils/mdlVerification.js`, `routes/verify/mdlRoutes.js`, mdoc tests |
| Status, revocation, or certificate validation | RFC004 and APTITUDE trust material | `utils/vpHeplers.js`, `utils/routeUtils.js`, `utils/credGenerationUtils.js` |

## Maintenance Rules

- Update this document in the same change set as any materially changed
  protocol support claim, endpoint, security policy, or source location.
- Mark a requirement as partial or not implemented when enforcement is absent;
  do not infer conformance from metadata advertisement or a helper function.
- When documenting an APTITUDE RFC requirement, identify the base
  specification it profiles and state only the explicit APTITUDE delta. Keep
  base-specification requirements out of the APTITUDE profile unless the RFC
  changes or selects them.
- Link focused design notes and test matrices from here when they become the
  primary explanation for a non-obvious decision.
- Keep `docs/core/` and `docs/references/` as the local specification base;
  do not duplicate normative text into this wiki.

## Pending Alignment Work

- **Tighten temporary EUDI wallet interop relaxations** — remove unverified
  `proofs.attestation` / `attested_keys` binding; configure
  `wallet_unit_attestation_jwks` (or `key_attestation_jwks`); enforce WUA `iss`
  and Wallet Provider trust policy; reconcile pre-auth token
  `authorization_details` / `credential_identifiers` with wallet behaviour.
  See [Temporary test-service relaxations](#temporary-test-service-relaxations-eudi-wallet-interop).
- [Main → APTITUDE alignment plan](./main-to-aptitude-alignment-plan.md) —
  commit-by-commit analysis of local `main` changes since 2026-06-01 mapped
  to RFC001/002/004 constraints. **Port backlog complete** on branch
  `aptitude-alignment` (938 root + 183 wallet tests passing; Docker build verified).
  Changes are uncommitted — ready for review and PR into `aptitude`.
  Deferred follow-ups: Phase 6 `sessionContext`, dual-profile config overlays.
