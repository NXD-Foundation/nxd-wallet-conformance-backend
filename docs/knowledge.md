# Project Knowledge Base

## Purpose

This file is the maintained entry point for project knowledge. It records the
current architectural context, decisions, known constraints, and the document
to consult for detail. It is not a normative specification, API reference, or
replacement for the evidence in the linked source documents.

Use it to orient implementation, review, and investigation work quickly. For
behaviour that affects interoperability or conformance, follow the linked
source of truth and then verify the current code and tests.

Agents should load the [project-knowledge](../.cursor/skills/project-knowledge/SKILL.md)
skill at task start so work follows this file's authority order, ITB/ITB+
meaning, and Fast Lookup routing.

## Project At A Glance

This repository is a configuration-driven Node.js/Express service with three
related roles:

- An OpenID4VCI 1.0 credential issuer.
- An OpenID4VP 1.0 credential verifier.
- A companion wallet-holder service under `wallet-client/` for exercising the
supported issuance and presentation flows.

Together, these three components are the WE BUILD Interoperability Test Bed
Plus (ITB+) reference deployment maintained in this repository. For future
references and discussions, treat **this codebase** — its current routes,
configuration, wallet client, and tests — as what "ITB" or "ITB+" means here,
unless a document explicitly points at the upstream WP4 ITB specification or
a separately hosted instance. The WE BUILD CS profiles describe what the test
bed is meant to validate; this repository is the running implementation that
ITB+ scenarios exercise against.

The primary supported credential families are SD-JWT VC, JWT VC, and
`mso_mdoc` (mDL/PID). Redis provides session, state, nonce, and deferred
issuance storage. The public protocol shape is mostly configured through
`data/issuer-config.json`, `data/verifier-config.json`, and
`data/oauth-config.json`.

### Session And Log Context

Sessions remain Redis-only and retain their existing service-specific keys and
TTLs: pre-authorized issuance, authorization-code issuance, VP, and wallet
test sessions are separate lifecycles with distinct session IDs. Every newly
stored session also contains a versioned `sessionContext` envelope. It is the
canonical location for lifecycle, nonce/client/audience/transaction bindings,
trust policy and decisions, and correlation metadata; legacy flat fields stay
present while routes are migrated.

Session logs remain separate append-only Redis records, not mutable arrays in
the session object. Issuer/verifier logs use `session-logs:<sessionId>` and the
wallet uses `wallet:logs:<sessionId>`; existing `/logs` APIs and their current
retention (30 minutes and one hour respectively) are unchanged. Log correlation
is async-scoped with `AsyncLocalStorage`, so concurrent requests cannot assign
one session's console output to another session.

This repository is a test framework: `/logs` intentionally exposes captured
protocol diagnostics for interoperability analysis. It is not a production-safe
public logging interface and must not be exposed with real credentials or tokens.

The logging-context migration is complete: issuer, verifier, and wallet-client
entry points use the shared async context, and the former process-global
`setSessionContext`/`clearSessionContext` API has been removed. Flat session
fields remain intentionally as protocol compatibility fields; the versioned
`sessionContext` is the canonical internal representation.

## Authority And Reading Order

When documents disagree, use this order of authority:

1. Published normative specifications and RFCs.
2. The applicable WE BUILD conformance specification in `docs/core/`.
3. Current code, configuration, and automated tests, which establish what this
  deployment actually does.
4. Project decision, matrix, plan, and interop documents in `docs/`.

The four top-level `cs-0*.md` files duplicate the corresponding files in
`docs/core/`. Treat `docs/core/` as canonical and avoid updating both copies
unless retaining that duplication is intentional.

## Architectural Decisions And Constraints



### CS-01 High-Assurance Issuance

- The CS-01 reference target is SD-JWT-VC issuance through PAR, PKCE S256,
sender-constrained tokens (such as DPoP or mTLS), Wallet Unit Attestation
(WUA) client authentication, and a credential proof bound to the Wallet
Unit subject key.
- Deferred issuance uses `transaction_id`, not `acceptance_token`.
- General OpenID4VCI compatibility modes may be deliberately less strict. Do
not describe them as CS-01 conformant.
- As of the recorded CS-01 v1.0 text, the conformance route is authorization
code only. The planned relaxation would add issuer-initiated pre-authorized
code issuance without weakening the high-assurance requirements. It is not
an implemented or normative rule until the CS-01 wording and implementation
are updated.

Sources: [CS-01](./core/cs-01-credential-issuance%20%281%29.md),
[attestation options](./haip-etsi-wallet-attestation-options.md), and
[pre-authorized-flow plan](./cs01-pre-authorized-flow-relaxation-plan.md).

### CS-04 Key Attestation Interoperability

- CS-04 remains the governing WE BUILD structure for WIA/KA issuance:
`attested_keys`, `key_storage`, `user_authentication`, `certification`, and
`key_storage_status` are retained, with short-lived KA tokens and proof
binding to `attested_keys[0]`.
- The wallet-client Wallet Provider publishes IETF Token Status List
  JWTs for WIA (`client_status.status`) and KA (`key_storage_status.status`)
  at `GET /status-lists/wia/1` and `GET /status-lists/ka/1`. CS-04 pins
  [draft-ietf-oauth-status-list-20](./rfc/draft-ietf-oauth-status-list-20.txt)
  for that wire format (`typ: statuslist+jwt`, `bits: 1`, ZLIB/DEFLATE,
  LSB-first packing). CS-01 attestations advertise those URIs from
  `WALLET_PROVIDER_URL`, keep status maintenance at least 31 days ahead of
  presentation, and retain list entries until that `exp`. Issuer-side fetch
  and bit evaluation of those lists is still out of scope.
- When an issuer supplies `c_nonce`, the KA carried in a JWT proof includes the
same `nonce`; the proof JWT and KA nonce are checked together before dispatch.
- The CS-04 `certification` example is currently tracked as an open
interoperability clarification because OpenID4VCI 1.0 describes that field as
a URL string while the CS-04 example uses an object. The implementation does
not silently override CS-04 for a Keycloak-specific shape.
- The KA JOSE type is `key-attestation+jwt`, as cited by CS-04 Annex A.2 from
OpenID4VCI 1.0 Appendix D.1. Shared KA validation rejects the unhyphenated
`keyattestation+jwt` spelling.

Sources: [CS-04 WUA lifecycle](./core/cs-04-wua-lifecycle.md),
[Token Status List draft-20](./rfc/draft-ietf-oauth-status-list-20.txt),
and [CS-04 interoperability issue](./issues/cs04-key-attestation-interoperability.md).

### Credential Issuer Metadata Discovery

- OpenID4VCI 1.0 Section 12.2.2 defines Credential Issuer metadata discovery.
For an issuer identifier with a path, insert
`/.well-known/openid-credential-issuer` between the origin and that path.
For example, `https://issuer.example/tenant` resolves to
`https://issuer.example/.well-known/openid-credential-issuer/tenant`.
- A Wallet is recommended to send an `Accept` header identifying the metadata
media types it supports. Every conforming issuer MUST support unsigned
`application/json`; signed `application/jwt` metadata is optional.
- The wallet client must request `application/json` until it implements
signed-metadata verification. Do not decode or use a JWT metadata payload
without signature verification and an established trust policy for its
signer. Supporting signed metadata is a separate security feature, not a
parsing fallback.
- The EUDI Android Demo wallet configures issuer trust with signed metadata
  required. This deployment therefore returns `application/jwt` metadata when
  the client advertises that media type. The JWT uses
  `typ=openidvci-issuer-metadata+jwt`, includes the complete X.509 `x5c`
  chain, and has `sub` equal to `credential_issuer` plus `iat`.
- Signed metadata is produced with the same WE-BUILD verifier P12 and loading
  policy as VP-request signing. Set `WEBUILD_P12_PASSWORD` when the P12 does
  not use the existing `webuild` default and, when the file is not at
  `certs/WE-BUILD-Verifier.p12`, set
  `ISSUER_METADATA_SIGNING_P12_PATH`. The chain must be trusted by the wallet
  as a Wallet Relying Party Access certificate; a successful verifier
  registration alone is not sufficient evidence of that role.
- OpenID4VCI does not require an OAuth Authorization Server metadata
`scopes_supported` array to contain `openid` for credential issuance. Treat
credential issuer `credential_configurations_supported[*].scope` values as
the primary source for scope-based issuance.
- If an issuer configuration has no `scope`, the wallet may only rely on
`authorization_details` for that credential when the Authorization Server
metadata advertises `authorization_details_types_supported` including
`openid_credential`.
- After every successful Token Response, the wallet must inspect returned
`authorization_details`: when an `openid_credential` entry contains
`credential_identifiers`, subsequent Credential Requests use
`credential_identifier` and omit `credential_configuration_id`; otherwise the
wallet uses `credential_configuration_id`. This is response-driven and applies
even when the wallet did not send `authorization_details` in the Token Request.
- HAIP 1.0 draft 03 Section 4.5 adds the requirement to publish a credential
type-to-`scope` mapping; it does not change the OpenID4VCI discovery URL or
metadata content negotiation rules.

Sources: [OpenID4VCI 1.0](./rfc/openid-4-verifiable-credential-issuance-1_0.html)
Sections 12.2.2-12.2.3 and [HAIP 1.0 draft 03](./rfc/openid4vc-high-assurance-interoperability-profile-1_0-ID1.html)
Section 4.5.

### OpenID4VP Verification

- The current standard verifier path uses DCQL for OpenID4VP 1.0; legacy
Presentation Exchange paths still exist but are not the current baseline.
- Supported verifier identities include X.509 and DID-based identifiers using the OpenID4VP `decentralized_identifier` prefix with `did:web` or `did:jwk`.
Supported response modes include `direct_post`, `direct_post.jwt`,
`dc_api`, and `dc_api.jwt`.
- Verification must distinguish advertised capability from runtime enforcement.
In particular, state/nonce checks, DCQL response shape, transaction-data
bindings, mdoc claim matching, and SD-JWT key binding each have explicit
enforcement paths.
- For strict `direct_post.jwt`, OpenID4VP encrypted-response processing uses
an unsigned encrypted JWT whose plaintext is the top-level Authorization
Response JSON object. The Wallet selects an `EC`/`P-256`, `use=enc` JWK with
both `kid` and `alg`, uses that exact `alg`, prefers `A256GCM`, and returns a
  protocol error rather than downgrading a successful response if encryption
  cannot be created.
- The verifier's advertised encryption JWK and decrypting private key are one
  key pair selected by `kid`. Startup/request handling must fail closed when
  their EC P-256 coordinates do not match; DC API and legacy HAIP response
  decryption must use this same registry rather than a separate hard-coded key.
- Verifier metadata should use the OpenID4VP 1.0 verifier-metadata model, not
older `client_metadata` representations.

Sources: [CS-02](./core/cs-02-credential-presentation%20%281%29.md),
[verifier metadata model](./openid4vp-cs02-verifier-metadata-model.md), and
[VP verification matrix](./vp-verification-wallet-matrix.md).

### CS-07 Digital Credentials API (DC API) Presentation

- The CS-07 target is the W3C Digital Credentials Working Draft dated
15 July 2026 together with OpenID4VP 1.0 Appendix A; the exact W3C draft is
pinned locally and must not be replaced by the moving editor's draft.
- The verifier-side CS-07 API consists of `POST /vp/dc-api/request`,
`POST /vp/dc-api/response/:sessionId`, and the sanitized polling endpoint
`GET /vp/dc-api/session/:sessionId`. The verifier does not host the RP HTML
page or invoke the browser API on behalf of a client. A separate,
dependency-free RP ESM adapter is implemented under `clients/dc-api/`; it fetches
the signed request, invokes `navigator.credentials.get()` in the RP's own
user-activation handler, and forwards only `protocol` and `data`.
- The backend must authorize configured RP origins and profile identifiers,
bind `expected_origins` and proof audiences to the calling RP origin, and
keep DCQL queries in verifier-owned profile configuration. Its response path
validates the envelope, decrypts the JWE, checks DCQL shape, and dispatches
SD-JWT/mDoc and specialized workflows through shared validators.
Encrypted `dc_api.jwt` response parsing and shared SD-JWT/mDoc dispatch have
dedicated CS-07 success-flow coverage.
The browser flow must use
`openid4vp-v1-signed`, a compact signed request in `data.request`,
`response_mode=dc_api.jwt`, configured `expected_origins`, and an audience
of `origin:<verifier-origin>` for response proofs.
- Profile and RP authorization are configured in `data/dc-api-config.json`
(or `DC_API_CONFIG_PATH`); ephemeral RP origins can be merged at startup via
`DC_API_RP_ORIGINS` (and optional `DC_API_RP_PROFILES`). The checked-in file
intentionally has no relying parties enabled and must be populated for a deployment.
- DC API transport must remain a thin adapter over the CS-02 DCQL and
credential-verification core. It must distinguish wallet protocol errors in
fulfilled `DigitalCredential.data` values from browser promise rejection.

Sources: [CS-07](./core/cs-07-credential-presentation-dc-api-updated.md),
[pinned W3C DC API draft](./rfc/w3c-digital-credentials-WD-20260715.html), and
[verifier implementation plan](./cs07-dc-api-verifier-implementation-plan.md),
[verifier API integration guide](./cs07-dc-api-verifier-api.md).

### CS-03 Remote Qualified Signing Compatibility

- CS-03 request generation remains explicitly selected with `cs03=1` on the
`/x509/generateVPRequestDCQL` route (and `cs03_oob=1` for callback delivery).
- The CSC X.509 DCQL format is not part of the strict CS-02 credential-format
set. To enable the intentional CS-03 compatibility allowance, set
`CS03_COMPATIBILITY=true`. The verifier may use the scoped alias
`VERIFIER_CS03_COMPATIBILITY=true`; the wallet may use
`WALLET_CS03_COMPATIBILITY=true`.
- The flag only permits the CSC X.509 DCQL format through the existing CS-03
flow. It does not enable CS-03 by itself, relax all CS-02 checks, or make
trust evaluation effective. Keep it disabled for ordinary CS-02 sessions.

Source: [CS-03 verifier flow summary](./cs03-verifier-flow-summary.md).

### Credential And Presentation Binding

- SD-JWT key-binding JWTs must be signed by the holder key in the issued
credential's `cnf.jwk`. The verifier checks its signature, `nonce`, `aud`,
and `sd_hash`.
- For any OpenID4VP `transaction_data` binding, calculate each KB-JWT hash
over the exact base64url string received in the Authorization Request; do not
decode the value before hashing.
- In strict CS-02 presentation, the Wallet also checks that its stored
presentation key is the credential's `cnf.jwk` before producing a KB-JWT.
- For mdoc issuance, construct ISO/IEC 18013-5 `IssuerSigned` and return
`base64url(CBOR(IssuerSigned))` as the OID4VCI credential value.
- mdoc metadata claim paths must contain both namespace and element identifier;
the PID `doctype` is the document identifier, not a format-suffixed
configuration identifier. A presented mdoc must be a proper `DeviceResponse`
with `deviceSigned` material.

Sources: [SD-JWT key-binding fixes](./sd-jwt-key-binding-interop.md),
[mdoc generation](./mdoc-credential-generation.md), and
[mdoc interop fixes](./mdoc-interop-fixes.md).

### TS-12 / CS-12 Payment SCA

- CS-12 in `docs/core/` is the WE BUILD profile of TS-12. ITB+ issues and
  presents the three in-scope attestation types
  `https://webuildconsortium.eu/sca/sca-iban/1.0`,
  `https://webuildconsortium.eu/sca/sca-user/1.0`, and
  `https://webuildconsortium.eu/sca/sca-card-dpc/1.0`. The URN
  `urn:eudi:sca:payment:1` is only the payment `transaction_data.type` and
  payload schema id, not a credential `vct`.
- `/ts12/payment/request` asks for exactly one of those VCTs (default
  `sca-iban`) and always uses `request_uri_method=post`. The Request Object
  is encrypted with Wallet Unit `wallet_metadata` JWKs that advertise
  `use=enc`. GET on `/ts12/payment/x509VPrequest/:id` is always rejected.
  Optional TS12 payment payload fields (`purpose`, `amount_estimated`,
  `amount_earmarked`, `sct_inst`) are accepted. The CLI wallet does not
  render visualisation/`ui_labels`.
- CS-12 `urn:eudi:sca:payment:1` is a first-class verifier
  `transaction_data` type. `VERIFIER_TS12_COMPATIBILITY=true` remains
  accepted but is not required to generate or validate that type. The
  wallet also accepts this payment type in CS-02 request validation.
- The encoded OpenID4VP `transaction_data` contains its required
  `transaction_data_hashes_alg` algorithm list. For TS-12 dynamic linking, the
  KB-JWT separately contains `transaction_data_hashes` and the required
  `transaction_data_hashes_alg` string (`"sha-256"`). The verifier checks the
  hash against the exact encoded request entry (without base64url-decoding it),
  enforces the TS-12 `amr` factors, rejects reused KB-JWT `jti` values, and
  treats a validated `jti` as the PSD2 Authentication Code. `sca-user`
  presentations also require the credential `aud` to include the RP
  `client_id`.

Sources: [CS-12 SCA payments](./core/cs-12-sca-payments%20(1).md) and
[TS-12 SCA with wallet](./ts12/ts12-electronic-payments-SCA-implementation-with-wallet%20(1).md),
Section 3.6 and Section 4.2.

### Wallet Attestation And Trust

- Current WUA-required issuance rejects missing or expired core WIA and key
attestation status fields, but incomplete status-list detail is currently
warning-only. The wallet-client now hosts resolvable WIA/KA Token Status
Lists per [draft-ietf-oauth-status-list-20](./rfc/draft-ietf-oauth-status-list-20.txt);
issuers that fetch `status_list.uri` can retrieve a signed
`application/statuslist+jwt`. This repository's issuer still does not fetch
or evaluate those bits.
- WUA/key-attestation signature validation is shared by `proofs.jwt` protected
  header `key_attestation` and `proofs.attestation`. In compatibility mode,
  configured Wallet Provider keys are preferred, then a protected-header `jwk`
  or leaf `x5c` may be used when no configured key set exists. Set
  `ENFORCE_WUA_TRUST_FRAMEWORK=true` to require configured
  `wallet_unit_attestation_jwks` (or the compatibility alias
  `key_attestation_jwks`). This source-enforcement switch does not replace the
  opted-in `trustFramework=true` Trusted List decision, certificate-chain
  validation, issuer binding, or revocation checks.
- The Phase 0/1 WE BUILD trust-list consumer now exists under `trust/`, with
  the pilot profile in `data/trust/webuild-wp4-pilot.json`, synthetic signed
  JSON/XML fixtures, and the focused command `npm run test:trust`. Opted-in
  issuance and verification flows enforce it; sessions without
  `trustFramework=true` retain compatibility behavior. The live profile pins
  the current WP4 signer as documented pilot TOFU material; embedded-`x5c`
  bootstrap is available only through an explicit test-only override.
- WE BUILD’s published JAdES JSON is signed over WP4 canonical JSON: object
  keys are recursively sorted, JSON is compact, and non-ASCII characters are
  escaped. The verifier must reproduce those exact bytes after removing the
  `signature` member; ordinary `JSON.stringify` insertion order is not
  sufficient for live WP4 documents.
- Phase 2 adds the strict resolver contract, all eight WP4 role mappings, a
  loopback HTTP adapter, and CLI parity over injected authenticated snapshots.
  Existing issuer, verifier, and wallet flows still do not enforce these
  decisions. Future session-level opt-in uses
  `trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" }`.
- Phase 3 now accepts `trustFramework=true` on issuance offer/session creation,
  verifier request generation, and the wallet test session. It persists that
  normalized policy and makes opted-in WIA/KA issuance fail closed unless the
  Wallet Provider certificate and identity resolve through the WP4 trust
  resolver. Each result, including missing or invalid attestation, is persisted
  as `trustDecision` and written to the session log; sessions without the flag
  retain compatibility behavior. Verifier credential trust remains Phase 4
  work.
- Phase 4 uses a shared verifier trust adapter. It consumes
  only cryptographically verified SD-JWT issuer evidence, maps credential
  context (`vct`/`doctype`) to explicit WP4 provider roles, and composes trust
  results with the existing signature, key-binding, DCQL, and status checks.
  Both shared and legacy mdoc paths extract the COSE issuer-authentication
  `x5chain` leaf for trust evaluation.
  Enforcement is activated only by the session policy created with
  `trustFramework=true` at VP request generation. Non-opted-in sessions retain
  compatibility behavior. mdoc issuer-certificate extraction and WRPAC/WRPRC
  evaluation are split: mdoc issuer certificates and WRPAC evaluation are now
  implemented for opted-in sessions. WRPRC is supported when deployment
  configuration supplies the distinct certificate through
  `TRUST_WRPRC_CERT_PATH`; otherwise no WRPRC decision is attempted.
- Listed certificates are accepted as an exact service leaf or as a CA anchor
  for a presented chain. Validity, chain signatures, CA constraints, and
  digital-signature key usage are checked. If a certificate advertises CRL
  distribution points, invalid, stale, unavailable, or revoking CRLs fail an
  opted-in decision; certificates without endpoints are recorded as
  `not-advertised`.
- A trust role can have multiple compatible pointers in the WE BUILD LoTL. The
  resolver authenticates, validates, and freshness-checks each pointer
  independently, then trusts a provider only if its identity/certificate
  matches at least one eligible list. Invalid or unavailable unrelated lists
  are included as diagnostic evidence; if no list for the role authenticates,
  the opted-in result is indeterminate and fails closed. A profile may set
  `pointerUrl` to deliberately restrict a role to one LoTL publisher.
- Registrars are generic: registration data may describe approved attestation
  types, while LoTEs publish provider anchors and status. NXD's current EAA
  LoTE has provider services and anchors but no registrar reference or
  `vct`/`doctype` scope. Trusted registrar scope evidence is enforced when
  available; absent evidence is temporarily allowed as `scope-unverified` and
  must be revisited before production hardening.
- Wallet-side trust enforcement follows the same session opt-in model. With
  `trustFramework=true`, the wallet checks the credential issuer's role-specific
  LoTE anchor before storing an SD-JWT/JWT credential. A trust-enabled JWT VC
  must have its signature verified by the same presented `x5c` certificate
  used as LoTE evidence; JWKS/DID verification alone cannot bind an unrelated
  certificate. Compatibility-mode decode-only JWT VC fallback is never trust
  evidence. Conventional JWT VC
  `vc.type`/`credential_type` is carried into registrar scope evaluation. The
  wallet checks an X.509
  verifier's WRPAC plus WRPRC before disclosing a presentation. The WRPRC is
  read from `verifier_info.registration_cert` first, then from the configured
  TS5 Registrar URL (`WALLET_TRUST_REGISTRAR_URL`) using the WRPAC entity ID.
  DID verifier identities remain outside this pilot enforcement path and are
  logged as not applicable. Credential type-to-provider-role entries in
  `wallet-client/data/trust-role-map.json` are routing hints, not an
  authorization registry: when a VCT/doctype is not mapped, the wallet tries
  the issuer-provider LoTE roles and accepts a trusted listed issuer. Likewise,
  an authenticated WRPRC with no declared credential/claim scope is accepted.
  Both cases persist and session-log `TRUST_SCOPE_NOT_DECLARED`; an explicit
  registrar scope remains enforced. This is intentional for the pilot test
  infrastructure and must be replaced by signed TL/registrar scope before a
  production trust decision.
- Production/conformance hardening still needs trusted Wallet Provider material
and complete status-list validation; keep any self-contained-key fallback
development-only when that work lands.

Source: [future WUA enforcement](./futureWUAstricterEnforcements.md).

### Certificate Chains For X.509 JAR

The verifier's X.509 JAR flow supports an `x5c` chain, but the current plan
records a leaf-only verifier P12 as an interoperability gap. The proposed
remediation is to package the issuer CA PEM, append it only when needed, keep
the leaf at index zero, and cover the assembly with tests. Check implementation
status before relying on this plan.

Source: [JAR x5c chain plan](./jar-x5c-certificate-chain-plan.md).

### Key And Certificate Inventory

The canonical development key paths are recorded in
[`utils/keyMaterialPaths.js`](../utils/keyMaterialPaths.js). The key roles are
deliberately separate:

- `private-key.pem` and `public-key.pem` are the application/issuer signing
  pair. `private-key-pkcs8.pem` is retained only for consumers that require
  PKCS#8 input.
- `didjwks/did_private_pkcs8.key` and `didjwks/did_public.pem` are the DID
  signing pair used by DID-based verifier requests and DID documents.
- `x509EC/ec_private_pkcs8.key` is the verifier response-encryption private
  key. It must match the EC P-256 `use=enc` JWK in `data/verifier-config.json`
  and `x509EC/client_certificate.crt`.
- `certs/WE-BUILD-Verifier.p12` is the X.509 verifier/JAR and signed issuer
  metadata signing material. `certs/pidissuerca02_eu.pem` is the CA used to
  extend the JAR `x5c` chain.
- Wallet-client credentials remain protocol-specific fixtures. DID, X.509,
  EC, CS-03, X25519, wallet-provider, and device keys must not be merged
  unless their protocol role and public-key identity are identical.

Historical backup material is kept under `deprecated/` for this testing
repository and must not be referenced by runtime code. The inventory tests
enforce private/public/certificate alignment and prevent backup paths from
re-entering active protocol directories.

## Documentation Map



### Canonical Specifications


| Document                                                                                             | Use it for                                                                                                                  | Status                       |
| ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| [CS-01 credential issuance](./core/cs-01-credential-issuance%20%281%29.md)                           | WE BUILD issuance roles, flows, requirements, and interfaces                                                                | Normative profile            |
| [CS-02 credential presentation](./core/cs-02-credential-presentation%20%281%29.md)                   | WE BUILD presentation and verifier requirements                                                                             | Normative profile            |
| [CS-03 remote signing](./core/cs-03-remote-signing-with-wallet-units%20%283%29.md)                   | Wallet- and QTSP-centric remote signing                                                                                     | Normative profile            |
| [CS-04 WUA lifecycle](./core/cs-04-wua-lifecycle.md)                                                 | WUA lifecycle, binding, revocation, and key attestation                                                                     | Normative profile            |
| [Token Status List draft-20](./rfc/draft-ietf-oauth-status-list-20.txt)                              | CS-04-pinned WIA/KA revocation Status List Token wire format (JWT, bits, compression, HTTP)                                 | Pinned Internet-Draft        |
| [CS-07 DC API presentation and issuance](./core/cs-07-credential-presentation-dc-api-updated.md)     | Pre-flight browser-mediated credential presentation and issuance requirements                                               | Normative pre-flight profile |
| [CS-12 SCA payments](./core/cs-12-sca-payments%20(1).md)                                             | WE BUILD profile of TS-12 for `sca-iban`, `sca-user`, and `sca-card-dpc` payment presentations                              | Normative pre-flight profile |
| [TS-12 SCA with wallet](./ts12/ts12-electronic-payments-SCA-implementation-with-wallet%20(1).md)     | Wallet-based strong customer authentication and transaction data                                                            | External specification       |
| `[docs/rfc/](./rfc/)`                                                                                | Local copies of OpenID4VCI 1.0, OpenID4VP 1.0, the CS-07-pinned W3C DC API draft, HAIP 1.0 draft 03, RFC 7591, RFC 9449, and Token Status List draft-20 | Reference copies             |




### Current Design, Behaviour, And Interoperability


| Document                                                                         | Primary question answered                                                           |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| [Wallet attestation options](./haip-etsi-wallet-attestation-options.md)          | What is CS-01-conformant WUA, PAR, proof binding, and deferred issuance behaviour?  |
| [OpenID4VP CS-02 verifier metadata](./openid4vp-cs02-verifier-metadata-model.md) | Which verifier metadata model and endpoints should new work use?                    |
| [CS-03 verifier flow summary](./cs03-verifier-flow-summary.md)                   | How do inline and OOB signature flows work, including PAdES/CAdES payloads?         |
| [VP verification wallet matrix](./vp-verification-wallet-matrix.md)              | What does the verifier support versus actually enforce?                             |
| [VCI authorization-code matrix](./vci-authorization-code-wallet-matrix.md)       | What a wallet must send and what the issuer enforces in authorization-code issuance |
| [VCI pre-auth PID X.509 matrix](./vci-preauth-pid-x509-wallet-matrix.md)         | Compatibility-mode pre-authorized PID issuance requirements and gaps                |
| [mdoc credential generation](./mdoc-credential-generation.md)                    | How issuer-side ISO 18013-5 mdoc construction maps to OID4VCI                       |
| [mdoc interop fixes](./mdoc-interop-fixes.md)                                    | Fixed mdoc metadata and wallet-presentation defects, plus porting checks            |
| [SD-JWT key-binding fixes](./sd-jwt-key-binding-interop.md)                      | Required holder-key continuity between issuance and presentation                    |




### Plans And Deferred Decisions


| Document                                                                          | Decision or work that remains conditional/pending                                                                           |
| --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| [CS-01 pre-auth relaxation plan](./cs01-pre-authorized-flow-relaxation-plan.md)   | Add CS-01 pre-auth only after the specification permits it, preserving HA controls                                          |
| [Future WUA stricter enforcement](./futureWUAstricterEnforcements.md)             | Status-list completeness and configured Wallet Provider trust material                                                      |
| [JAR x5c certificate-chain plan](./jar-x5c-certificate-chain-plan.md)             | Supply an X.509 JAR chain for wallets that validate it                                                                      |
| [CS-07 DC API verifier plan](./cs07-dc-api-verifier-implementation-plan.md)       | Add browser-mediated `openid4vp-v1-signed` presentation without weakening the CS-02 verification core                       |
| [WE BUILD-constrained FCAF alignment](./fcaf-we-build-alignment-plan.md)          | Align non-data-model FCAF coverage without weakening WE BUILD profiles or enabling trust decisions                          |
| [WE BUILD FCAF applicability register](./FCAFs/we-build-fcaf-applicability.json) | Machine-readable scope, disposition, and evidence policy for the alignment work; 301 explicit catalogue rows are classified |




## Working Rules

- Start new issuer work with CS-01 and the relevant VCI matrix; start verifier
work with CS-02, the metadata model, and the VP matrix.
- Treat every matrix as an implementation snapshot. Confirm assertions against
current routes, configuration, and tests before changing security behaviour.
- Record a new non-obvious decision here only when it changes project-wide
direction. Put detailed reasoning, protocol examples, and implementation
steps in a focused companion document and link it from this file.
- When a plan is implemented, change its entry here from pending to current
behaviour and retain the plan as historical rationale.
- Update this file in the same change set as any change to a linked decision,
profile interpretation, protocol support claim, or documentation location.
- When a security concept is accepted through multiple transports, share its
  parsing, key resolution, cryptographic verification, claim validation, and
  trust-policy functions. Transport handlers may add only transport-specific
  nonce, proof-of-possession, or binding checks, and every accepted transport
  needs parity tests.



## Fast Lookup


| If you are changing...                                      | Read first                                                                |
| ----------------------------------------------------------- | ------------------------------------------------------------------------- |
| Credential offers, PAR, token, proofs, or deferred issuance | CS-01, attestation options, relevant VCI matrix                           |
| WUA/WIA/KA validation, trust, or status-list publication    | CS-04, Token Status List draft-20, wallet-client publisher, future WUA enforcement |
| VP requests, metadata, response modes, or DCQL              | CS-02, verifier metadata model, VP matrix                                 |
| Browser-mediated DC API presentation                        | CS-07, pinned W3C DC API draft, OpenID4VP Appendix A, CS-07 verifier plan |
| Remote qualified signing                                    | CS-03 and CS-03 verifier flow summary                                     |
| SD-JWT holder binding                                       | SD-JWT key-binding fixes                                                  |
| TS-12 / CS-12 payment SCA and transaction data              | CS-12 SCA payments, then TS-12 SCA with wallet                |
| mdoc metadata, issuance, or presentation                    | mdoc generation and mdoc interop fixes                                    |
| X.509 JAR signing certificates                              | JAR x5c certificate-chain plan                                            |
