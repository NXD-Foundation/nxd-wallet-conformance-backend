# WE BUILD Credential Issuance Profile: Wallet Attestation and Credential Binding Options

## Purpose

This note clarifies how wallet authentication and credential-binding proofs should be understood for the WE BUILD credential issuance conformance profile.

It is based on the WE BUILD CS-01 Credential Issuance specification, which profiles OpenID4VCI and HAIP for high-assurance issuance of SD-JWT-VC credentials within the WE BUILD ecosystem.

The focus of this note is limited to credential issuance. Presentation, verification, trust management, and ETSI-specific EUDI Wallet issuance requirements are outside the direct scope of CS-01 and should be treated separately.

## Short Answer

For WE BUILD CS-01, the reference interoperability shape is:

1. Wallet Units and Issuers support both wallet-initiated and issuer-initiated issuance.
2. All authorisation requests use PAR.
3. PKCE with `S256` is required.
4. Tokens are sender-constrained, for example through DPoP or mTLS.
5. Wallet Unit Attestation is used for client authentication at the PAR and Token endpoints.
6. The Credential Endpoint uses an access token and a proof JWT that binds the issued credential to the Wallet Unit’s subject key.
7. Deferred issuance uses `transaction_id`, not `acceptance_token`.

The document should therefore not present “no wallet attestation” or “mixed client authentication” as WE BUILD profile-compliant modes. They may be useful for general OpenID4VCI compatibility testing, but they are not the CS-01 reference conformance target.

## Terms

For this note:


| Term             | Meaning                                                                           |
| ---------------- | --------------------------------------------------------------------------------- |
| WU               | Wallet Unit: the wallet-side component acting on behalf of the Holder.            |
| Holder           | The person or representative controlling the Wallet Unit.                         |
| Issuer           | The entity that decides to issue the credential and controls issuance policy.     |
| AS               | Authorisation Server responsible for OAuth/OIDC authorisation and token issuance. |
| WUA              | Wallet Unit Attestation used by the Wallet Unit for client authentication.        |
| PAR              | Pushed Authorisation Request.                                                     |
| SD-JWT-VC        | SD-JWT-based Verifiable Credential format used by the CS-01 profile.              |
| `transaction_id` | Identifier returned when credential issuance is deferred.                         |


## WE BUILD CS-01 Issuance Baseline

The WE BUILD issuance profile is based on OpenID4VCI and HAIP. It requires a high-assurance OAuth-based issuance flow with the following mandatory features:


| Area                  | WE BUILD CS-01 Requirement                                                   |
| --------------------- | ---------------------------------------------------------------------------- |
| Credential format     | SD-JWT-VC                                                                    |
| Issuance modes        | Wallet-initiated issuance and issuer-initiated issuance via Credential Offer |
| Authorisation flow    | Authorisation Code Flow                                                      |
| PAR                   | Required for all authorisation requests                                      |
| PKCE                  | Required with `S256`                                                         |
| Tokens                | Sender-constrained access tokens, e.g. DPoP or mTLS                          |
| Wallet authentication | Wallet Unit Attestation at PAR and Token endpoints                           |
| Credential binding    | Proof JWT at the Credential Endpoint                                         |
| Deferred issuance     | Supported through `transaction_id`                                           |


## Profile Matrix


| Topic                                          | General OpenID4VCI                  | HAIP                                                                    | WE BUILD CS-01                          |
| ---------------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------- | --------------------------------------- |
| Credential format                              | Multiple formats possible           | High-assurance profile constraints                                      | SD-JWT-VC                               |
| Wallet-initiated issuance                      | Possible                            | Supported                                                               | Required                                |
| Issuer-initiated issuance via Credential Offer | Possible                            | Supported                                                               | Required                                |
| PAR                                            | Optional depending on issuer policy | High-assurance deployments normally require stronger request protection | Required for all authorisation requests |
| PKCE                                           | Commonly used                       | Required in high-assurance flows                                        | Required with `S256`                    |
| Sender-constrained tokens                      | Optional depending on issuer policy | Expected in high-assurance deployments                                  | Required                                |
| Wallet authentication at PAR                   | Optional depending on issuer policy | Required where client authentication is used                            | Required using Wallet Unit Attestation  |
| Wallet authentication at Token                 | Optional depending on issuer policy | Required where client authentication is used                            | Required using Wallet Unit Attestation  |
| Credential Endpoint proof                      | Proof object supported              | Proof required for binding                                              | JWT proof required                      |
| Deferred issuance                              | Supported                           | Supported                                                               | Supported using `transaction_id`        |
| Mixed client authentication                    | Deployment-specific                 | Not the main interoperability target                                    | Not the CS-01 reference shape           |


## Correct WE BUILD Request Shape

### 1. Wallet-Initiated Issuance

In the wallet-initiated flow:

1. The Wallet Unit retrieves Issuer metadata.
2. The Wallet Unit identifies the credential type and corresponding `scope`.
3. The Wallet Unit sends a PAR request.
4. The PAR request is client-authenticated using Wallet Unit Attestation.
5. The Authorisation Server returns a `request_uri`.
6. The Holder authenticates and consents.
7. The Wallet Unit sends a Token Request using the authorisation code and PKCE verifier.
8. The Token Request is also client-authenticated using Wallet Unit Attestation.
9. The Token Endpoint returns a sender-constrained access token.
10. The Wallet Unit sends a Credential Request with the access token and proof JWT.
11. The Issuer validates the access token, proof JWT, and issuance policy.
12. The Issuer returns the issued SD-JWT-VC, or a deferred response containing `transaction_id`.

### 2. Issuer-Initiated Issuance via Credential Offer

In the issuer-initiated flow:

1. The Issuer decides to issue one or more credentials.
2. The Issuer creates a Credential Offer.
3. The Credential Offer includes:
  - `credential_issuer`
  - grant information for the `authorization_code` grant
  - one or more credential type identifiers
  - a `scope` value for each offered credential type
4. The offer is delivered through a same-device link or cross-device QR code.
5. The Wallet Unit is invoked using the `openid-credential-offer://` scheme.
6. The Wallet Unit parses the offer and extracts the Issuer, credential types, and associated scopes.
7. The Wallet Unit starts the same PAR-based Authorisation Code Flow as in wallet-initiated issuance.
8. The Credential Request and possible Deferred Credential Request proceed in the same way as the wallet-initiated flow.

## Wallet Unit Attestation in WE BUILD CS-01

Wallet Unit Attestation is the CS-01 client authentication mechanism for the PAR and Token endpoints.

### PAR Endpoint

At the PAR endpoint, the Wallet Unit sends an authorisation request containing, at minimum:

```text
client_id
scope
code_challenge
code_challenge_method=S256
redirect_uri
response_type=code
state
nonce
```

The request must be client-authenticated using Wallet Unit Attestation.

The `client_id` in the PAR request must match the `sub` claim in the Wallet attestation JWT used for client authentication.

The PAR endpoint returns:

```text
request_uri
expires_in
```

Direct front-channel authorisation requests without PAR are not part of the WE BUILD CS-01 profile.

### Token Endpoint

At the Token Endpoint, the Wallet Unit sends:

```text
grant_type=authorization_code
code
redirect_uri
code_verifier
client authentication using Wallet Unit Attestation
```

The Token Endpoint validates:

```text
the authorisation code
the PKCE verifier
the Wallet Unit Attestation
the binding between client_id and the attestation subject
the sender-constraining mechanism
```

The Token Endpoint returns:

```text
access_token
token_type
expires_in
optional refresh_token
```

The access token must be sender-constrained.

## Credential Endpoint

The Credential Endpoint is separate from OAuth client authentication.

At the Credential Endpoint, the Wallet Unit sends:

```text
Authorization: Bearer {access_token}
format or credential configuration identifier
proof object
```

The proof object uses the JWT proof type.

The proof JWT binds the requested credential to the Wallet Unit’s subject key.

The Issuer validates:

```text
the access token
the sender-constraining mechanism
the proof JWT
the requested credential configuration
the issuance policy
```

If issuance succeeds immediately, the Issuer returns the issued SD-JWT-VC.

If issuance cannot be completed immediately, the Issuer returns a deferred issuance response.

## Deferred Credential Issuance

WE BUILD CS-01 uses `transaction_id` for deferred issuance.

If the Credential Issuer cannot immediately issue the credential, it returns:

```text
transaction_id
optional interval
```

The Wallet Unit must store the `transaction_id` and call the Deferred Credential Endpoint until:

```text
the credential is issued
the transaction remains pending
the transaction expires
the Issuer returns an unrecoverable error
```

The Deferred Credential Endpoint request includes:

```text
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "transaction_id": "..."
}
```

If issuance is complete, the response contains the issued credential and returns HTTP 200.

If issuance is still pending, the response contains the `transaction_id`, may include `interval`, and returns HTTP 202.

If the transaction is invalid or can no longer be completed, the Issuer returns an appropriate error such as:

```text
invalid_transaction_id
credential_request_denied
```

## Options Reframed for WE BUILD

The earlier profile options can be reframed as follows.

### Option 1: General OpenID4VCI Compatibility Mode

This mode may be useful for generic OpenID4VCI testing, but it is not sufficient for WE BUILD CS-01 conformance.

Characteristics:

```text
PAR may or may not be required
Wallet Unit Attestation may be absent
ordinary OAuth client authentication may be used
credential proof may still be required
```

Use this only when testing broad OpenID4VCI compatibility.

Do not label this as WE BUILD CS-01 conformant.

### Option 2: WE BUILD CS-01 Attestation Mode

This is the reference WE BUILD interoperability mode.

Characteristics:

```text
PAR required
PKCE S256 required
sender-constrained access token required
Wallet Unit Attestation at PAR
Wallet Unit Attestation at Token
Credential Endpoint proof JWT
SD-JWT-VC credential format
transaction_id for deferred issuance
```

This is the target mode for WE BUILD issuance conformance testing.

### Option 3: Mixed Client Authentication Compatibility Mode

Some deployments may accept attestation together with another OAuth client authentication method, such as `client_secret` or `private_key_jwt`.

This may be useful for backwards compatibility, migration, or issuer-specific testing.

However, this should not be treated as the WE BUILD CS-01 reference profile shape unless the CS-01 specification is explicitly extended to permit it.

For conformance purposes, the test suite should distinguish between:

```text
Wallet Unit Attestation as the actual client authentication method
```

and

```text
Wallet Unit Attestation as an additional signal alongside another client authentication method
```

Only the first should be treated as the CS-01 conformance target.

### Option 4: ETSI EUDI Wallet Issuance Profile

ETSI EUDI Wallet issuance requirements may introduce stricter or different distinctions between Wallet Instance Attestation, Wallet Unit Attestation, and key-attestation proofing.

Those requirements are useful for comparison, but they are not directly part of WE BUILD CS-01 unless explicitly incorporated into a later WE BUILD profile.

Therefore, ETSI-specific requirements should be kept in a separate note or appendix, rather than mixed into the main WE BUILD CS-01 conformance interpretation.

## Recommended WE BUILD Support Set

A Wallet Unit targeting WE BUILD CS-01 should support:

```text
Issuer metadata retrieval
Credential type to scope mapping
Wallet-initiated issuance
Issuer-initiated issuance via Credential Offer
openid-credential-offer:// invocation
same-device Credential Offer handling
cross-device QR Credential Offer handling
PAR for all authorisation requests
PKCE S256
Wallet Unit Attestation at PAR
Wallet Unit Attestation at Token
sender-constrained access tokens
Credential Request with JWT proof
SD-JWT-VC credential validation
Deferred Credential Request using transaction_id
```

An Issuer targeting WE BUILD CS-01 should support:

```text
OAuth/OIDC metadata publication
Credential Issuer metadata publication
mapping of credential types to unique scope values
Credential Offers using authorization_code grant
same-device and cross-device offer delivery
openid-credential-offer:// invocation support
PAR endpoint
Token Endpoint
Wallet Unit Attestation validation
sender-constrained access tokens
Credential Endpoint
JWT proof validation
SD-JWT-VC issuance
Deferred Credential Endpoint
transaction_id lifecycle management
```

## Implications for ITB+ Conformance Testing

The ITB+ test suite should separate the following test dimensions.

### 1. Metadata and Discovery

Check that the Issuer publishes:

```text
OAuth/OIDC metadata
PAR endpoint
Token endpoint
Credential Issuer metadata
supported credential types
scope mapping for each credential type
deferred_credential_endpoint where deferred issuance is supported
```

### 2. Credential Offer Processing

Check that:

```text
Credential Offers use authorization_code grant
each offered credential type maps to a scope
Wallet Units can parse the offer
Wallet Units can use the scope in the PAR request
same-device invocation is supported
cross-device QR invocation is supported
openid-credential-offer:// is supported
```

### 3. PAR Requirements

Check that:

```text
PAR is required
direct front-channel authorisation requests are rejected or not used
PKCE S256 parameters are present
state and nonce are present
client_id matches the attestation subject
Wallet Unit Attestation is validated
```

### 4. Token Endpoint Requirements

Check that:

```text
authorization_code grant is used
code_verifier matches the original code_challenge
Wallet Unit Attestation is validated
client_id matches the attestation subject
the returned access token is sender-constrained
```

### 5. Credential Endpoint Requirements

Check that:

```text
the access token is valid
the sender-constraining mechanism is enforced
the request identifies the SD-JWT-VC credential configuration
the proof object uses proof_type jwt
the proof JWT binds the credential to the Wallet Unit subject key
the issued credential is a valid SD-JWT-VC
```

### 6. Deferred Issuance Requirements

Check that:

```text
delayed issuance returns transaction_id
Wallet Units store transaction_id
Wallet Units call the Deferred Credential Endpoint
pending responses return HTTP 202
completed responses return HTTP 200
invalid or expired transactions return explicit errors
```

## Key Review Questions

When reviewing a Wallet Unit implementation, ask:

```text
Does it support both wallet-initiated and issuer-initiated issuance?
Does it process Credential Offers using authorization_code grant?
Does it use PAR for every authorisation request?
Does it use PKCE S256?
Does it authenticate at PAR using Wallet Unit Attestation?
Does it authenticate at Token using Wallet Unit Attestation?
Does its client_id match the attestation sub claim?
Does it support sender-constrained access tokens?
Does it send a JWT proof at the Credential Endpoint?
Does it handle transaction_id-based deferred issuance?
```

When reviewing an Issuer implementation, ask:

```text
Does it publish complete OAuth/OIDC and Credential Issuer metadata?
Does it map credential types to unique scope values?
Does it require PAR?
Does it reject or avoid direct front-channel authorisation requests?
Does it validate Wallet Unit Attestation at PAR?
Does it validate Wallet Unit Attestation at Token?
Does it issue sender-constrained access tokens?
Does it validate Credential Endpoint proof JWTs?
Does it issue SD-JWT-VC credentials?
Does it support transaction_id-based deferred issuance?
```

## Recommended Conformance Interpretation

For WE BUILD CS-01, the conformance target should be:

```text
OpenID4VCI + HAIP-based issuance
SD-JWT-VC credential format
Authorisation Code Flow
PAR required
PKCE S256 required
sender-constrained access tokens
Wallet Unit Attestation at PAR and Token
JWT proof at Credential Endpoint
transaction_id-based deferred issuance
```

The following should be treated as outside the core CS-01 conformance target:

```text
no wallet attestation
ordinary OAuth client authentication without Wallet Unit Attestation
mixed client authentication as the default profile shape
ETSI-specific WIA/WUA distinctions
ETSI-specific proofing that the same secure component controls WUA and holder-binding keys
acceptance_token-based deferred issuance
```

These may still be useful in broader compatibility or future-profile testing, but they should not be presented as the WE BUILD CS-01 reference interoperability shape.

## Sources

This note is based on:

```text
WE BUILD CS-01 Credential Issuance specification
OpenID4VCI 1.0
OpenID4VC High Assurance Interoperability Profile
SD-JWT-VC
WE BUILD ITB+ reference specification
```

## Implementation Plan for WE BUILD CS-01 Attestation Mode

This section turns Option 2 into an explicit implementation plan for the current `wallet-client` code base.

The target end state is:

```text
authorization_code only
PAR always used
PKCE S256 always used
Wallet Unit Attestation used as client authentication at PAR and Token
sender-constrained access token always used
JWT proof used at the Credential Endpoint
transaction_id used for deferred issuance
```

The plan below is organized as phases so the code can move from its current mixed-profile behavior to a clean CS-01 conformance mode without losing existing compatibility paths.

### Current Code Baseline

The current implementation already has the main building blocks:

- authorization-code flow in `wallet-client/src/server.js`
- PAR support in `runAuthorizationCodeIssuance()`
- PKCE generation via `createPkcePair()`
- OAuth client attestation headers via `buildOAuthClientAttestationHeaders()`
- DPoP generation for token and credential requests
- JWT proof generation for the Credential Endpoint
- deferred issuance polling with `transaction_id`

The main gaps are concentrated in these areas:

- mixed client authentication at PAR and Token
- weak profile separation between authorization-code and pre-authorized flows
- hard-coded `client_id`
- `scope: configurationId` instead of a proper scope mapping
- fallback behavior that is useful for generic VCI but too permissive for CS-01
- mock-style attestation generation where a clearer conformance attestation model is needed

### Phase 1: Introduce Explicit CS-01 Profile Mode

Goal:

- create a single switch that makes the wallet behave as a CS-01-conformant client

Implementation changes:

- add an explicit profile flag such as `webuild-cs01`
- thread that flag through the top-level issuance entry points in `wallet-client/src/server.js`
- separate:
  - generic compatibility mode
  - CS-01 conformance mode

Current code areas to change:

- the session/bootstrap logic that decides whether to run pre-authorized flow or authorization-code flow
- `runAuthorizationCodeIssuance()`
- any top-level API path that currently accepts either grant type without a profile gate

Acceptance criteria:

- the wallet can be started in CS-01 mode
- in CS-01 mode, only the authorization-code path is available
- in non-CS-01 mode, existing compatibility flows can remain

### Phase 2: Make PAR Mandatory in CS-01 Mode

Goal:

- enforce the CS-01 rule that all authorization requests use PAR

Implementation changes:

- in `runAuthorizationCodeIssuance()`, treat missing PAR metadata as fatal in CS-01 mode
- if the PAR request fails, stop the flow instead of falling back to direct authorization
- retain direct authorization fallback only in non-CS-01 compatibility mode

Current code areas to change:

- PAR discovery and fallback logic in `wallet-client/src/server.js` around the `parEndpoint` and `requirePushedAuthorizationRequests` handling
- the branch that appends authorization parameters directly to the authorization URL when PAR is absent or fails

Acceptance criteria:

- CS-01 mode never sends a direct front-channel authorization request
- CS-01 mode fails fast when PAR is unavailable or rejected
- compatibility mode can still keep current fallback behavior if desired

### Phase 3: Remove Mixed Client Authentication from CS-01 Mode

Goal:

- make Wallet Unit Attestation the actual client authentication method at PAR and Token

Implementation changes:

- stop sending `client_assertion` and `client_assertion_type` in CS-01 mode
- stop generating the separate `createWIA()` JWT for use as body `client_assertion` in CS-01 mode
- continue sending:
  - `OAuth-Client-Attestation`
  - `OAuth-Client-Attestation-PoP`

Current code areas to change:

- PAR request assembly in `runAuthorizationCodeIssuance()`
- token request assembly in `runAuthorizationCodeIssuance()`
- pre-authorized request assembly, if that code remains reachable outside CS-01 mode
- logging that currently redacts and records `client_assertion`

Current code references:

- `wallet-client/src/server.js` PAR request body where `client_assertion` is added
- `wallet-client/src/server.js` token request body where `client_assertion` is added
- `wallet-client/src/index.js` pre-authorized request body where `client_assertion` is added
- `wallet-client/src/lib/crypto.js` `createWIA()`

Acceptance criteria:

- in CS-01 mode, PAR and Token requests contain attestation headers only
- in CS-01 mode, no OAuth body `client_assertion` is sent
- compatibility mode may still retain mixed auth if intentionally supported

### Phase 4: Align `client_id` with Attestation Subject

Goal:

- enforce the CS-01 requirement that `client_id` matches the Wallet Unit Attestation subject

Implementation changes:

- define one source of truth for the wallet client identifier
- derive or inject the attestation subject from the same source
- validate the equality before building PAR and Token requests

Current code areas to change:

- `client_id: "wallet-client"` in the authorization request
- `client_id: "wallet-client"` in the token request
- attestation generation helper inputs in `buildOAuthClientAttestationHeaders()`

Acceptance criteria:

- `client_id` is no longer hard-coded in request builders
- attestation `sub` and outbound `client_id` are guaranteed to match
- mismatch is treated as a local construction error, not left for the issuer to discover

### Phase 5: Replace `scope: configurationId` with Real Scope Resolution

Goal:

- make authorization requests conform to the issuer's scope mapping rather than using an internal credential configuration ID as a stand-in

Implementation changes:

- parse credential-type-to-scope mapping from issuer metadata and Credential Offers
- store the selected scope in session state
- send that scope in the PAR request
- fail in CS-01 mode if the selected credential cannot be mapped to an unambiguous scope

Current code areas to change:

- authorization request construction in `runAuthorizationCodeIssuance()`
- session parsing of the Credential Offer and selected credential configuration
- any helper that currently assumes `configurationId` can be reused as `scope`

Acceptance criteria:

- CS-01 mode only sends issuer-defined scopes
- the selected credential and the requested scope are explicitly linked in wallet state
- missing or ambiguous mapping causes an early error

### Phase 6: Make Sender-Constraining Mandatory

Goal:

- ensure every CS-01 token is sender-constrained and that subsequent requests use the same binding

Implementation changes:

- treat DPoP generation failure as fatal in CS-01 mode
- verify that the token response is consistent with DPoP-bound token usage
- reuse the same DPoP keypair for:
  - token request
  - credential request
  - deferred credential request

Current code areas to change:

- DPoP generation around the token request in `runAuthorizationCodeIssuance()`
- DPoP reuse for credential request
- DPoP reuse for deferred polling

Acceptance criteria:

- CS-01 mode never falls back to bearer behavior
- credential and deferred requests always continue the sender-constrained context
- DPoP generation failure stops the flow

### Phase 7: Clarify the Attestation Model

Goal:

- make the temporary attestation model explicit: CS-01 mode uses only locally generated keys and locally generated attestation material until a trust framework exists

Implementation changes:

- treat locally generated keys as the only attestation source in CS-01 mode for now
- document in code and docs that this is a temporary implementation choice, not a completed trust-framework integration
- keep the request shape aligned with CS-01 even though the attestation is locally generated
- rename internal variables and comments so they refer consistently to Wallet Unit Attestation in the CS-01 flow
- leave a clean extension point for future replacement with trust-framework-backed attestation material

Current code areas to change:

- `buildOAuthClientAttestationHeaders()`
- `createWIA()` naming and call sites if it remains in the repository
- comments that currently mix WIA/WUA/OAuth client attestation terminology
- configuration or startup validation that should state whether the wallet is running in local-key attestation mode

Acceptance criteria:

- the CS-01 path makes clear that attestation is currently generated from local keys
- local-key attestation is the intentional and only attestation mode for now
- code and docs clearly state that trust-framework integration is not yet implemented
- terminology in code matches the WE BUILD model
- the code structure leaves a clear seam for a future trust-framework-backed attestation source

### Phase 8: Keep Credential Proof Logic and Tighten Its Contract

Goal:

- preserve the current working proof flow while making its CS-01 assumptions explicit

Implementation changes:

- document which key is the Wallet Unit subject key used for credential binding
- ensure the proof JWT always uses that key in CS-01 mode
- confirm that the deferred path preserves the same sender-constraining context as the initial credential request

Current code areas to change:

- proof key generation and `createProofJwt()` inputs
- `createWUA()` usage at the Credential Endpoint if it remains part of your chosen binding story
- deferred issuance polling logic

Acceptance criteria:

- credential binding proof is generated from a clearly defined wallet subject key
- the same binding context survives through deferred issuance
- proof generation assumptions are explicit in code and docs

### Phase 9: Move Pre-Authorized Issuance out of the CS-01 Path (out of scope for now)

Goal:

- prevent accidental use of non-CS-01 flow variants during conformance testing

Implementation changes:

- disable or reject pre-authorized issuance in CS-01 mode
- keep `pre-authorized_code` support only for non-CS-01 compatibility testing
- make the top-level flow selector profile-aware

Current code areas to change:

- `wallet-client/src/index.js`
- pre-authorized branches in `wallet-client/src/server.js`
- top-level session routing that currently accepts both grant types

Acceptance criteria:

- CS-01 mode cannot execute the pre-authorized flow
- pre-authorized support remains available only outside the conformance path

### Phase 10: Add Conformance-Focused Validation and Tests

Goal:

- make CS-01 conformance regressions visible immediately

Implementation changes:

- add tests for profile gating
- add request-construction tests for PAR and Token
- add tests for failure behavior
- add test fixtures for issuer metadata with explicit scope mapping

Minimum success tests:

- issuer-initiated authorization-code issuance via Credential Offer
- wallet-initiated issuance
- PAR success with attestation headers only
- token redemption with PKCE and DPoP
- credential request with JWT proof
- deferred issuance with `transaction_id`

Minimum failure tests:

- missing PAR endpoint
- PAR failure with no fallback
- `client_id` mismatch with attestation subject
- DPoP generation failure in CS-01 mode
- missing scope mapping
- attempted pre-authorized flow in CS-01 mode
- accidental body `client_assertion` in CS-01 mode

Acceptance criteria:

- the CS-01 test suite distinguishes conformance mode from compatibility mode
- mixed auth regressions are caught by tests
- PAR fallback regressions are caught by tests

### Recommended Delivery Order

The lowest-risk order for implementation is:

1. Add profile gating for `webuild-cs01`.
2. Make PAR mandatory in that mode.
3. Remove body `client_assertion` in that mode.
4. Unify `client_id` and attestation subject.
5. Add real scope resolution.
6. Make DPoP fatal and mandatory.
7. Separate mock attestation from conformance attestation input.
8. Lock pre-authorized flow out of CS-01 mode.
9. Add and pass conformance-focused tests.

### Definition of Done

The implementation can be treated as aligned with Option 2 when:

```text
all CS-01 authorization flows always use PAR
PAR and Token use Wallet Unit Attestation as the client authentication method
the client does not send parallel body client_assertion in CS-01 mode
client_id matches the attestation subject
PKCE S256 is always used
access tokens are sender-constrained
Credential requests use JWT proof bound to the Wallet Unit subject key
deferred issuance uses transaction_id
pre-authorized issuance is not used in the CS-01 conformance path
```

