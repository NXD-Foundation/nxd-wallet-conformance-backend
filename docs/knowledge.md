# Project Knowledge Base

## Purpose

This file is the maintained entry point for project knowledge. It records the
current architectural context, decisions, known constraints, and the document
to consult for detail. It is not a normative specification, API reference, or
replacement for the evidence in the linked source documents.

Use it to orient implementation, review, and investigation work quickly. For
behaviour that affects interoperability or conformance, follow the linked
source of truth and then verify the current code and tests.

## Project At A Glance

This repository is a configuration-driven Node.js/Express service with three
related roles:

- An OpenID4VCI 1.0 credential issuer.
- An OpenID4VP 1.0 credential verifier.
- A companion wallet-holder service under `wallet-client/` for exercising the
supported issuance and presentation flows.

The primary supported credential families are SD-JWT VC, JWT VC, and
`mso_mdoc` (mDL/PID). Redis provides session, state, nonce, and deferred
issuance storage. The public protocol shape is mostly configured through
`data/issuer-config.json`, `data/verifier-config.json`, and
`data/oauth-config.json`.

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
- OpenID4VCI does not require an OAuth Authorization Server metadata
`scopes_supported` array to contain `openid` for credential issuance. Treat
credential issuer `credential_configurations_supported[*].scope` values as
the primary source for scope-based issuance.
- If an issuer configuration has no `scope`, the wallet may only rely on
`authorization_details` for that credential when the Authorization Server
metadata advertises `authorization_details_types_supported` including
`openid_credential`.
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
(or `DC_API_CONFIG_PATH`); the checked-in file intentionally has no relying
parties enabled and must be populated for a deployment.
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

### TS-12 Payment SCA

- The implemented TS-12 scope is the `urn:eudi:sca:payment:1` SCA
attestation and payment transaction type, requested with DCQL and presented
as an SD-JWT-VC with a KB-JWT.
- `VERIFIER_TS12_COMPATIBILITY=true` is a narrow CS-02 strict-mode exception:
it permits that TS-12 `transaction_data.type`; it does not enable the other
CS-02 compatibility relaxations.
- The encoded OpenID4VP `transaction_data` contains its required
`transaction_data_hashes_alg` algorithm list. For TS-12 dynamic linking, the
KB-JWT separately contains `transaction_data_hashes` and the required
`transaction_data_hashes_alg` string (`"sha-256"`). The verifier checks the
hash against the exact encoded request entry, enforces the TS-12 `amr`
factors, and rejects reused KB-JWT `jti` values.

Source: [TS-12 SCA with wallet](./ts12/ts12-electronic-payments-SCA-implementation-with-wallet%20%281%29.md),
Section 3.6 and Section 4.2.

### Wallet Attestation And Trust

- Current WUA-required issuance rejects missing or expired core WIA and key
attestation status fields, but incomplete status-list detail is currently
warning-only.
- Trust-list enforcement is intentionally out of scope today. Header-carried
`x5c` or `jwk` material can be used as a transitional interoperability
fallback when no trusted JWKS is configured.
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

## Documentation Map



### Canonical Specifications


| Document                                                                                             | Use it for                                                                                                                  | Status                       |
| ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| [CS-01 credential issuance](./core/cs-01-credential-issuance%20%281%29.md)                           | WE BUILD issuance roles, flows, requirements, and interfaces                                                                | Normative profile            |
| [CS-02 credential presentation](./core/cs-02-credential-presentation%20%281%29.md)                   | WE BUILD presentation and verifier requirements                                                                             | Normative profile            |
| [CS-03 remote signing](./core/cs-03-remote-signing-with-wallet-units%20%283%29.md)                   | Wallet- and QTSP-centric remote signing                                                                                     | Normative profile            |
| [CS-04 WUA lifecycle](./core/cs-04-wua-lifecycle.md)                                                 | WUA lifecycle, binding, revocation, and key attestation                                                                     | Normative profile            |
| [CS-07 DC API presentation and issuance](./core/cs-07-credential-presentation-dc-api-updated.md)     | Pre-flight browser-mediated credential presentation and issuance requirements                                               | Normative pre-flight profile |
| [TS-12 SCA with wallet](./ts12/ts12-electronic-payments-SCA-implementation-with-wallet%20%281%29.md) | Wallet-based strong customer authentication and transaction data                                                            | External specification       |
| `[docs/rfc/](./rfc/)`                                                                                | Local copies of OpenID4VCI 1.0, OpenID4VP 1.0, the CS-07-pinned W3C DC API draft, HAIP 1.0 draft 03, RFC 7591, and RFC 9449 | Reference copies             |




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



## Fast Lookup


| If you are changing...                                      | Read first                                                                |
| ----------------------------------------------------------- | ------------------------------------------------------------------------- |
| Credential offers, PAR, token, proofs, or deferred issuance | CS-01, attestation options, relevant VCI matrix                           |
| WUA/WIA/KA validation or trust                              | CS-04 and future WUA enforcement                                          |
| VP requests, metadata, response modes, or DCQL              | CS-02, verifier metadata model, VP matrix                                 |
| Browser-mediated DC API presentation                        | CS-07, pinned W3C DC API draft, OpenID4VP Appendix A, CS-07 verifier plan |
| Remote qualified signing                                    | CS-03 and CS-03 verifier flow summary                                     |
| SD-JWT holder binding                                       | SD-JWT key-binding fixes                                                  |
| TS-12 payment SCA and transaction data                      | TS-12 SCA with wallet                                                     |
| mdoc metadata, issuance, or presentation                    | mdoc generation and mdoc interop fixes                                    |
| X.509 JAR signing certificates                              | JAR x5c certificate-chain plan                                            |
