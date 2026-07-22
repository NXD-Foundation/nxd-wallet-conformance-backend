# WE BUILD CS-01 / TS03 / ARF 2.9 Wallet Client Gap Analysis

Audit target: `wallet-client`

Target profile:

- WE BUILD CS-01 Credential Issuance v1.0: <https://github.com/webuild-consortium/wp4-architecture/blob/main/conformance-specs/cs-01-credential-issuance.md>
- TS03 Wallet Unit Attestation: <https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md>
- ARF 2.9.0: <https://eudi.dev/2.9.0/architecture-and-reference-framework-main/>

Important scope correction: this report is not an IETF OAuth attestation draft audit. The target is WE BUILD CS-01 credential issuance, which profiles OpenID4VCI, HAIP, ARF 2.9, TS03, and the referenced CS-04 WUA lifecycle/binding rules. CS-01 makes WUA mandatory: WIA is used for client authentication/session binding at PAR and Token, and KA is used for key binding at the Credential Endpoint.

Primary local files reviewed:

- `src/server.js`
- `src/lib/walletUnitAttestation.js`
- `src/lib/credentialProofBinding.js`
- `src/lib/crypto.js`
- `src/lib/dpopBinding.js`
- `src/lib/walletClientId.js`
- `src/lib/cs01Conformance.js`
- `test/cs01Conformance.test.js`
- `test/walletUnitAttestation.test.js`
- `test/credentialProofBinding.test.js`
- `test/dpopBinding.test.js`

## Executive Summary

The wallet client implements parts of the CS-01 protocol flow, especially PAR, authorization-code token exchange, DPoP, WUA-like headers, and a credential proof with a `key_attestation` header. It is not yet conformant with the WE BUILD CS-01 target profile because the WIA and KA are local prototype artifacts rather than Wallet Provider-issued, certificate-backed TS03/CS-04 attestations.

Highest-priority gaps for CS-01:

- WIA is not Wallet Provider-signed and does not carry `x5c`; CS-01 requires WIA as an OpenID4VCI Wallet Attestation with Wallet Provider signing certificate in `x5c`.
- WIA includes `iss`; CS-01/TS03 say Wallet Provider identity is inferred from `x5c` and `iss` is not used.
- WIA lacks TS03/CS-04 claims: `wallet_name`, `wallet_version`, `wallet_solution_certification_information`, `client_status`, and recommended `wallet_link`.
- PAR does not include `dpop_jkt`; CS-01 Section 7.3 requires `dpop_jkt` as the JWK Thumbprint of the WIA `cnf` key to bind the authorization code to the DPoP key.
- Token DPoP is present, but the client does not explicitly verify `access_token.cnf.jkt == thumbprint(WIA.cnf.jwk)` for the WIA used in the same issuance session.
- KA is locally generated and signed, not Wallet Provider-signed with `x5c`.
- KA now carries the CS-04 structural claims `certification`, `key_storage`, `user_authentication`, and `key_storage_status`; it remains a locally generated prototype attestation rather than a Wallet Provider-issued production attestation.
- The credential proof path only supports `jwt` proof with KA in the JOSE `key_attestation` header; this matches CS-01's Credential Endpoint path, but the KA content/signature is not conformant.
- The wallet does not evaluate `key_attestations_required` metadata to ensure presented KA `key_storage` and `user_authentication` meet or exceed issuer requirements.
- The current implementation still supports pre-authorized code flow, while CS-01 Section 7.1 says Authorization Code Flow is the only flow for credential issuance. Treat pre-authorized flow as outside CS-01 or disable it in CS-01 profile.

No CS-01 requirement was found for a PAR attestation challenge. Challenge retrieval belongs to the generic OAuth attestation draft, not the CS-01/TS03 requirements reviewed here. CS-01's PAR-specific binding requirement is `dpop_jkt`, not a challenge claim.

## Source Hierarchy Used

For this audit, requirements are applied in this order:

1. CS-01 credential issuance profile, because it is the explicit target profile.
2. CS-04 where referenced by CS-01 for WUA structure, validity, revocation, and binding. I did not find a public `cs-04` file in the `conformance-specs` directory during this pass, so TS03 is used for the underlying WIA/KA details that CS-01 cites.
3. TS03 Wallet Unit Attestation, for WIA/KA format, content, lifecycle, revocation, and algorithm rules.
4. ARF 2.9, for ecosystem trust model and Wallet Provider/Wallet Unit lifecycle context.

## CS-01 Section-by-Section Findings

### 5. Protocol Overview

CS-01 requires:

- Authorization Code and Pre-Authorized Code Flow are listed in the overview, but Section 7.1 later states Authorization Code Flow is the only flow for credential issuance.
- SD-JWT-VC credential format profile.
- Sender-constrained tokens, e.g. DPoP or mTLS.
- PKCE with `S256`.
- PAR for all authorization requests.
- WUA = WIA + KA per ARF 2.9, TS03, and CS-04.

Status: Partial.

Implemented:

- Authorization Code Flow exists.
- PAR exists and is mandatory in CS-01 mode.
- PKCE S256 is implemented in the codeflow path.
- DPoP is implemented for token and credential/resource requests.
- WIA-like headers and KA-like credential proof are implemented.

Gaps:

- WIA and KA are local prototypes, not TS03/CS-04 attestations.
- Pre-authorized flow remains implemented and tested; for CS-01 conformance it should be disabled or clearly marked non-CS-01.
- SD-JWT-VC support exists in the repo, but this audit focused on WUA/session binding rather than full SD-JWT-VC validation.

### 6.1 Wallet-Initiated Issuance Flow

Status: Partial.

Implemented:

- Metadata discovery exists.
- Credential/scope resolution exists.
- PAR is used for authorization requests.
- Authorization-code token request exists.
- Credential request with JWT proof exists.
- Credential validation/storage exists at a basic flow level.

Gaps:

- PAR request should include `nonce`; current `authzParams` include `state`, `client_id`, `redirect_uri`, `response_type`, PKCE, `scope`, and `authorization_details`, but no explicit `nonce` was seen in the reviewed PAR construction.
- PAR request should include `dpop_jkt` per Section 7.3; not implemented.
- PAR WIA must be TS03/CS-04 WIA; not implemented.

### 6.2 Issuer-Initiated Issuance via Credential Offer

Status: Partial.

Implemented:

- Credential Offer parsing exists and the wallet can consume issuer-initiated offers.
- Scope reuse from offers is implemented in the existing flow.

Gaps:

- CS-01 requires authorization-code grants in credential offers. The wallet also supports pre-authorized-code offers; this must be disabled or considered outside CS-01 mode.
- Same-device and cross-device invocation support is not fully proven by the reviewed server-side code alone.

### 6.3 Deferred Credential Request

Status: Partial.

Implemented:

- Deferred issuance code and tests are present in the repo.

Gaps:

- The audit did not fully verify deferred polling binding to the issuance session and DPoP/access-token sender constraints.
- Ensure deferred credential requests use sender-constrained access tokens consistently.

### 7.1 Common Requirements

CS-01 WU requirements:

- Support Authorization Code Flow as the only flow for credential issuance.
- Support SD-JWT-VC profile.
- Support sender-constrained tokens.
- Support PKCE S256.
- Support wallet-initiated and issuer-initiated issuance.
- Use WUA as defined in CS-04, with CS-04 authoritative for WUA structure, validity, revocation, and binding.

Status: Partial.

Implemented:

- Authorization Code Flow, DPoP, PKCE S256, wallet-initiated and issuer-initiated paths are present.

Gaps:

- Pre-authorized-code flow should not be active in CS-01 conformance mode.
- WUA is not CS-04/TS03 conformant.
- Sender-constrained token check is generic DPoP binding, not explicit WIA `cnf` binding.

### 7.2 Credential Offer

CS-01 WU requirements:

- Parse Credential Offer using `authorization_code` grant.
- Use the offer's `scope` in the authorization request.
- Support `openid-credential-offer://` invocation.

Status: Partial.

Implemented:

- Offer parsing and scope mapping are present.

Gaps:

- Ensure CS-01 mode rejects or ignores pre-authorized-code offers.
- Invocation via the custom URL scheme is not fully assessed from local server code.

### 7.3 Authorization Endpoint and PAR

CS-01 WU requirements:

- Use PAR for all authorization requests.
- Use `scope` to indicate credential type; each scope maps to a known credential type.
- Ensure PAR `client_id` matches WIA `sub`.
- Include `dpop_jkt`, the JWK Thumbprint of the WIA `cnf` key, in the PAR request.

Status: Partial.

Implemented:

- PAR is mandatory in CS-01 mode.
- Scope resolution and credential type mapping exist.
- Client-id alignment with attestation `sub` is checked for the local WIA-like JWT.

Gaps:

- Missing `dpop_jkt` in PAR.
- The WIA `sub` check is currently against a local self-issued attestation, not a Wallet Provider-signed WIA.
- PAR WIA lacks `x5c`, TS03 claims, and Wallet Provider trust binding.
- Direct authorization fallback should be impossible in CS-01 mode; current code appears to enforce PAR mandatory, but keep tests around this.

### 7.4 Token Endpoint and Wallet Attestation

CS-01 WU requirements:

- Authenticate at Token using WIA as OpenID4VCI Wallet Attestation (`typ: oauth-client-attestation+jwt`) and PoP (`oauth-client-attestation-pop+jwt`) in PAR and Token requests.
- WIA must convey Wallet Provider signing certificate in `x5c`, with intermediates as needed.
- Wallet Provider identity is inferred from `x5c`; `iss` is not used.
- Use WIA `cnf` key as DPoP key for access-token request.
- On access-token receipt, verify access token `cnf.jkt` equals JWK Thumbprint of the WIA `cnf` key; abort on mismatch.
- Ensure WIA `sub` equals `client_id` in PAR and Token.

Status: Not conformant for WIA; partial for PoP/DPoP mechanics.

Implemented:

- `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers are sent.
- `typ` values are set for local attestation and PoP.
- `sub`/`client_id` alignment is checked locally.
- DPoP is generated for token requests.
- DPoP-bound access token is checked generally.

Gaps:

- WIA is locally signed, not Wallet Provider-signed.
- WIA JOSE header uses `jwk`, not `x5c`.
- WIA includes `iss`; CS-01/TS03 says `iss` is not used.
- WIA lacks TS03 `wallet_name`, `wallet_version`, `wallet_solution_certification_information`, `client_status`, and optional `wallet_link`.
- WIA `cnf` key is not explicitly modeled as the DPoP key source.
- Access token `cnf.jkt` is not explicitly compared with `thumbprint(WIA.cnf.jwk)` for the same issuance session.

### 7.5 Credential Endpoint

CS-01 Wallet requirements:

- Send proof JWT claims required by issuer to bind credential to wallet subject key.
- Validate returned SD-JWT-VC signature, issuer identifier, key binding, and status information.
- Where issuer requires KA, include KA in the `key_attestation` header of the `jwt` proof.
- The proof must be signed by the key at index 0 of `attested_keys`.
- Where issuer requires key-attestation levels, present KA whose `key_storage` and `user_authentication` meet or exceed required levels.

Status: Partial.

Implemented:

- Credential request uses JWT proof.
- `key_attestation` is included in the proof header in the current proof-binding path.
- Single-key local path appears to sign with the same key that is attested.

Gaps:

- KA is locally signed, not Wallet Provider-signed.
- KA JOSE header lacks `x5c`.
- KA uses the standards spelling `typ: key-attestation+jwt`. The previous CS-04 example spelling `keyattestation+jwt` has been corrected locally and is tracked for upstream clarification.
- KA structural claims are now present and validated locally. The CS-04 object-shaped `certification` is intentionally retained; its interoperability with implementations expecting the OpenID4VCI string form is tracked separately.
- KA nonce binding is now included when an issuer nonce is available, and the proof path validates the nonce and `attested_keys[0]` binding before sending the request.
- No issuer metadata evaluation for `key_attestations_required` minimum `key_storage` and `user_authentication` levels.
- No explicit local assertion that proof signing key equals `attested_keys[0]` for multi-key/batch cases.
- Returned SD-JWT-VC validation was not fully re-audited in this pass.

### 7.6 Deferred Credential Endpoint

CS-01 Wallet requirements:

- Recognize deferred responses and store `transaction_id`.
- Poll Deferred Credential Endpoint until ready or terminal failure.
- Distinguish pending vs failed issuance in UI.
- Should apply polling interval/backoff and allow users to stop polling.

Status: Partial.

Implemented:

- Deferred issuance support and tests exist.

Gaps:

- Need explicit verification that deferred requests preserve sender-constrained access token handling.
- UI/UX pending-vs-failed behavior is not fully audited.

### 7.7 Server Metadata

CS-01 Wallet requirements:

- Retrieve and process issuer metadata, including credential type to `scope` mapping.
- Use mapping for authorization requests and Credential Offers.
- If `key_attestations_required` is published, use it to determine minimum acceptable `key_storage` and `user_authentication` levels.

Status: Partial.

Implemented:

- Metadata discovery and scope resolution exist.
- AS metadata validation checks `attest_jwt_client_auth` and some attestation alg metadata.

Gaps:

- No `key_attestations_required` handling for KA level selection.
- Metadata validation still contains older OAuth-draft oriented checks and should be reframed under CS-01/TS03/CS-04.
- Algorithm arrays are checked for existence but not consistently used for selection.

## TS03 / ARF 2.9 WUA Findings Used by CS-01

### WIA Format and Content

Required for CS-01 through TS03/CS-04:

- Wallet Provider-signed JWT.
- JOSE `x5c` certificate chain.
- `typ: oauth-client-attestation+jwt`.
- `sub` equals `client_id`.
- `cnf.jwk` binds the WIA to the Wallet Unit key.
- `wallet_name`, `wallet_version`, `wallet_solution_certification_information`.
- `client_status.status` and `client_status.exp`.
- Recommended `wallet_link`.
- No `iss`; Wallet Provider identity comes from `x5c`.

Current status: not conformant. Only `typ`, `sub`, and `cnf.jwk` are structurally present in the local prototype.

### KA Format and Content

Required for CS-01 through TS03/CS-04 when KA is required:

- Wallet Provider-signed JWT.
- JOSE `x5c` certificate chain.
- OID4VCI key-attestation type.
- `attested_keys` with proof key at index 0 for `jwt` proof.
- `certification`.
- `key_storage`.
- `user_authentication`.
- `key_storage_status.status` and `key_storage_status.exp`.
- One-use KA and one-use attested public key controls.

Current status: not conformant. The credential proof path includes a KA-like JWT, but it is local-key signed and lacks the required TS03/CS-04 fields.

### Lifecycle, Revocation, and Privacy

Required through TS03/CS-04:

- WIA token-level TTL less than 24h.
- Separate status maintenance periods via `client_status.exp` and `key_storage_status.exp`.
- Token Status List references for WIA/KA revocation.
- One-use WIA/KA controls or permitted per-issuer reuse state.
- Anti-linkability handling for status indices and attested keys.

Current status: missing except short local WIA-like TTL.

## Challenge at PAR

No CS-01/TS03 requirement was found for challenge retrieval at PAR or for a `challenge` claim in the attestation PoP. The required CS-01 PAR binding mechanism is `dpop_jkt`, not an attestation challenge.

So the gap analysis should not mark missing PAR challenge support as a CS-01/TS03 gap. It should mark missing `dpop_jkt` as a CS-01 gap.

## Updated Conformance Checklist

| Requirement | Status | Notes |
| --- | --- | --- |
| Authorization Code Flow supported | Present | Code flow exists |
| Authorization Code only in CS-01 mode | Missing/Partial | Pre-authorized flow still active |
| PAR mandatory for all auth requests | Present/Partial | Enforced in CS-01 mode; keep tests |
| PAR includes `client_id`, `scope`, PKCE S256, `redirect_uri`, `response_type`, `state`, `nonce` | Partial | `nonce` not seen in reviewed PAR params |
| PAR includes `dpop_jkt` from WIA `cnf` key | Missing | CS-01 Section 7.3 gap |
| PAR uses WIA client auth | Partial | Headers sent, WIA not conformant |
| Token uses WIA + PoP headers | Partial | Headers sent, WIA not conformant |
| WIA has Wallet Provider `x5c` | Missing | Current uses `jwk` |
| WIA omits `iss` | Missing | Current includes `iss` |
| WIA includes TS03 claims | Missing | `wallet_*`, certification, `client_status` absent |
| WIA `sub` equals `client_id` | Present for local prototype | Needs real WIA validation |
| Token DPoP uses WIA `cnf` key | Partial | Not explicitly modeled |
| Access token `cnf.jkt` equals WIA `cnf` thumbprint | Missing/Partial | Generic DPoP check only |
| Credential Endpoint uses JWT proof | Present | Current proof path |
| KA in `key_attestation` header when required | Partial | Header present, KA not conformant |
| KA has Wallet Provider `x5c` | Missing | Current uses local signing |
| KA includes `certification` | Present (CS-04 shape) | Object-vs-string interoperability clarification remains open |
| KA includes `key_storage` and `user_authentication` | Present | Local structural validation is covered by tests |
| KA includes `key_storage_status` | Present | Local structural validation is covered; live status trust remains out of scope |
| Proof signed by `attested_keys[0]` | Partial | Works in single-key path, needs assertion/tests |
| Evaluate `key_attestations_required` metadata | Missing | CS-01 Section 7.5/7.7 gap |
| Deferred credential polling | Partial | Present, binding/UI not fully audited |
| Credential Offer authorization_code support | Present/Partial | Pre-authorized offer behavior must be gated out |
| `openid-credential-offer://` invocation | Not fully assessed | Needs client invocation path review |
| No PAR challenge requirement | Not a gap | Use `dpop_jkt` instead |

## Recommended Implementation Plan for CS-01

1. Gate CS-01 mode to Authorization Code Flow only.
   - Reject or hide pre-authorized-code flows under `webuild-cs01`.
   - Keep pre-authorized flow only in a non-CS-01 compatibility profile.

2. Replace local WIA generation with provisioned Wallet Provider WIA.
   - WIA must be signed by Wallet Provider and include `x5c`.
   - Remove `iss` from TS03/CS-01 WIA assumptions.
   - Require TS03 claims and `client_status`.

3. Bind PAR to WIA `cnf` using `dpop_jkt`.
   - Compute JWK Thumbprint of the WIA `cnf.jwk`.
   - Add `dpop_jkt` to PAR request body.
   - Ensure the token-request DPoP key is the same WIA `cnf` key.

4. Enforce token response WIA/DPoP binding.
   - Store the WIA used for the issuance session.
   - On token response, verify `access_token.cnf.jkt` equals `thumbprint(WIA.cnf.jwk)`.
   - Abort issuance on mismatch.

5. Replace local KA generation with Wallet Provider-signed KA.
   - KA must include `x5c`, `certification`, `key_storage`, `user_authentication`, `key_storage_status`, and `attested_keys`.
   - Keep local KA only as a non-conformant test fixture.

6. Implement `key_attestations_required` handling.
   - Parse issuer metadata.
   - Select/request a KA whose `key_storage` and `user_authentication` meet or exceed required levels.
   - Fail closed if no suitable KA is available.

7. Add proof binding assertions.
   - Verify before sending that the proof JWT signing key is exactly `attested_keys[0]` in the KA.
   - Add tests for mismatch rejection.

8. Add WIA/KA lifecycle and anti-linkability state.
   - Track WIA and KA use.
   - Prevent unsupported reuse.
   - Model per-issuer reuse only if the Wallet Provider policy supports it.

9. Keep challenge handling out of the CS-01 gap list unless a target issuer separately mandates the generic OAuth attestation draft challenge mechanism.

## Bottom Line

The previous TS03-only rewrite was directionally correct about Wallet Provider-signed WIA/KA and `x5c`, but it was not completely aligned to your actual target profile. This version aligns the gap analysis to WE BUILD CS-01 first, then applies TS03 and ARF 2.9 as referenced by CS-01.

For your current code, the most immediate CS-01-specific fixes are `dpop_jkt` at PAR, explicit WIA `cnf` to DPoP/access-token `cnf.jkt` binding, disabling pre-authorized flow in CS-01 mode, and replacing local WIA/KA generation with Wallet Provider-issued TS03/CS-04 material.
