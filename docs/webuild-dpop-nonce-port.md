# WE BUILD wallet DPoP nonce port

## Provenance and baseline

Target baseline: `4e8aa506ae50438ea71c79a61825c9d721a7adf9` (`origin/main`).

- Portable APTITUDE source: `689061b1a2c4e090a93037cc6ca9f746f6027185`.
- Remaining APTITUDE source: `43b96bbd55a37837ab27d2fe9617114c5b262dfe`; preserved separately, not cherry-picked.
- Target portable cherry-pick: `3184355ff577427402703074deac78177a7f821f`, with `-x` provenance.
- WE BUILD integration is the following commit in this branch; its message records the source references.

Conformance baseline is the specification text checked into that target revision:

| Document | Version |
| --- | --- |
| CS-01 Credential Issuance | 1.0, 28 November 2025 |
| CS-04 Individual WUA Lifecycle | 1.1, 7 September 2026 |
| CS-05 Business WUA Lifecycle | 1.0, 5 August 2026 |
| OpenID4VCI | 1.0 |
| HAIP referenced by CS-01 | Implementers Draft 1 / draft 03 (`openid4vc-high-assurance-interoperability-profile-1_0-ID1.html`) |
| DPoP | RFC 9449 |

The port does not upgrade these references or resolve pre-existing inconsistencies between CS-01's overview, normative grant wording, and the repository's pre-authorized-flow relaxation. It preserves `main`'s current routing and opt-out behavior.

## Behavior and exclusions

The wallet responds to AS HTTP 400 JSON `use_dpop_nonce` errors and resource-server HTTP 401 DPoP challenges, including empty bodies. Successful and error response nonce headers update transaction-local state scoped by server role/identity and confirmation-key thumbprint. A retry keeps request parameters and the binding key, but creates a fresh DPoP proof. Query and fragment are excluded from `htu`; path and trailing slash are preserved.

The WE BUILD adapter preserves a single session WIA across PAR, token exchange and retries, creates fresh attestation PoP proofs, and retains both WIA/key and nonce state through the existing handoff serializer. Nonce negotiation permits two retries per logical request and five sends overall; the existing one attestation retry remains unchanged. DPoP-bound requests never recover by downgrading to Bearer. Compatibility-mode optional DPoP behavior remains optional.

Credential retries preserve serialized request bodies, proof/key-attestation material and credential `c_nonce`. The Nonce Endpoint's DPoP nonce is independent of JSON `c_nonce`; its requests do not carry an access token. Existing token-response credential-nonce acquisition/fallback policy remains unchanged. Deferred polling retains its transaction and interval while handling nonce challenges immediately within a poll attempt.

No HTTPS-only callback policy, invocation URI changes, combined attestation/DPoP authentication method, provider-key rotation behavior, or issuer nonce-enforcement changes are introduced. Existing CS-01 PAR, PKCE, attestation and token-key checks remain active. Existing key-attestation support and test-glob fixes on `main` are not overwritten.

There is no notification dispatcher or CLI issuance entry point in this `main` baseline. No new notification/CLI feature is introduced. The shared resource transport is reusable by a future DPoP-protected notification dispatcher.

Affected HTTP response diagnostics redact nonces, access tokens and proof material without changing protocol responses. Retry diagnostics include endpoint stage, status and retry count.

## Requirement-to-test mapping

| Requirement | Evidence |
| --- | --- |
| Signed nonce claim, URI binding, fresh proof identifiers | Portable `dpopNonceTransport` tests and real issuer integration |
| AS/resource and session/key nonce isolation; rotation | Portable transport tests |
| Malformed/missing challenges, unrelated failures, retry exhaustion | Portable transport tests |
| One WIA/key through PAR, handoff and token; fresh PoP | `dpopIssuanceTransport` session test |
| Authorization-code service integration and unchanged callback | Existing service end-to-end nonce test |
| Allowed pre-auth fields and disabled-flow policy | New pre-auth adapter test plus existing CS-01 gate |
| No CS-01 Bearer fallback; token-key mismatch rejection | Adapter compatibility test plus existing DPoP binding gate |
| Credential empty-body 401, selectors, independent c_nonce | Adapter resource tests and service end-to-end test |
| Deferred interval/transaction retained | Adapter deferred test plus existing polling gate |
| Encrypted response bytes retained through retry | JWE transport round-trip test; no new wallet decryption policy |
| Actual issuer challenge and single-use nonce recovery | `NONCE-WALLET` in issuer tests, backed by isolated Redis |
| CS-05 acceptance and existing nonce enforcement | Existing CS-05/nonce issuer tests |

## Validation results

| Gate | Before | After |
| --- | --- | --- |
| Wallet `test` | 368 passing, 15 failing | 383 passing, same 15 failing |
| Wallet `test:cs01` | 153 passing | 168 passing |
| Wallet `test:cs02` | 128 passing, 14 failing | 128 passing, same 14 failing |
| New portable/WE BUILD tests | Not present | 15 passing |
| Issuer nonce/CS-05 targeted tests | Existing issuer implementation unchanged | 17 passing, including new actual wallet transport integration |

Failure descriptions for the full wallet and CS-02 gates match their pre-port baselines exactly. The remaining failures concern existing X.509 request-fixture expectations (14 CS-02 cases plus one presentation error-response case), outside this nonce port.

Issuer checks ran with an isolated temporary Redis container and `REQUIRE_DPOP_NONCE_FOR_TOKEN=true` in the nonce scenarios. Tests covered the real issuer router; remote issuer interoperability and formal conformance certification were not performed. Installed dependencies were reused locally through ignored symlinks; no dependency versions changed.
