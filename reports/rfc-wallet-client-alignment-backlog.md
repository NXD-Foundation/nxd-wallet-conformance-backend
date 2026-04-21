# RFC001 + RFC002 Wallet-Client Compliance Review & Alignment Backlog

Reviewed against `~/Downloads/RFC001 (1).md` (APTITUDE RFC-01 Credential Issuance Profile, v0.1 Draft) and `~/Downloads/RFC002 (1).md` (APTITUDE RFC-02 Presentation Profile) on 2026-04-20.

Scope of this document:

- **Wallet-side behaviour only** (the `wallet-client/` folder and its helpers).
- Current implementation on `main`.
- Combined output: compliance findings (Part A) + prioritised alignment backlog (Part B).
- RFC-check IDs follow RFC001 §10.1 (`VCI-CHECK-NN`) and RFC002 §11.1.1 / §7.1 (`VP-CHECK-NN`, `APT-PRES-WALLET-*`).

Scoping decisions that shape the backlog:

- **This wallet is a testing wallet, not a certified Wallet Unit.** In line with that fact, **WIA and WUA are produced with self-signed key material that the wallet itself generates**. A real deployment would provision these attestations from an EUDI Wallet Provider; the backlog items below explicitly surface where the current "self-signed WIA/WUA" shortcut diverges from RFC text and what the minimum acceptable testing shape is.
- **ISO/IEC 18013-7 mdoc track** is scoped to **structural and invocation conformance only** on the wallet side, mirroring the verifier review. Full `SessionTranscript`, `OID4VPHandover`, `DeviceAuth` signing is deferred to a future cycle.
- **CS-03 QES** flows (`src/lib/cs03.js`, transaction-data signing) are **out of scope** for RFC001/RFC002 alignment and are **not** audited here.
- **Two entry points** exist in `wallet-client/src/`:
  - `src/index.js` — the thin CLI (~390 lines).
  - `src/server.js` — the HTTP-driven interactive wallet (~2490 lines) used by `POST /issue`, `POST /session`, `POST /present`, `POST /issue-codeflow`.
  Where the two diverge, the report notes the divergence explicitly because the CLI is used by some integration fixtures but the server is the canonical runtime.

---

## Part A — Compliance Review

### A.0 Executive summary

The wallet-client covers the happy-path surface area of both RFC001 (issuance) and RFC002 (presentation) but has meaningful compliance gaps against the RFC-aligned issuer and verifier that now exist in this repo.

What is already correct on the wallet side:

- Credential offer parsing for `openid-credential-offer://`, `haip://`, `haip-vci://`; inline `credential_offer` and `credential_offer_uri`; legacy `credentials` array/object.
- DPoP generation at `/token_endpoint` and `/credential` (RFC 9449, with `htu` normalization, `jti`, `ath` for resource calls when the token is DPoP-bound).
- `c_nonce` obtained from the token response or from `/nonce` when the token response omits it.
- Proof JWT with `typ: openid4vci-proof+jwt` and embedded `key_attestation` (WUA) in the protected header (RFC001 §7.5.1 Wallets-SHALL item 3).
- WUA structure with `typ: key-attestation+jwt`, `attested_keys` containing the proof key, `eudi_wallet_info`.
- WIA sent as `client_assertion` + `client_assertion_type: urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
- Deferred issuance polling.
- Authorization-code flow in `src/server.js` (including PAR, PKCE S256, signed request objects in some branches).
- OpenID4VP request reception over `openid4vp://` and `mdoc-openid4vp://`, including `request_uri_method=post`.
- DCQL consumption with cross-check against `transaction_data.credential_ids`.
- SD-JWT Key Binding JWT with `sd_hash` and nonce/audience binding (draft-14 §4.3.1).
- Response mode `direct_post` and `direct_post.jwt` (JWE via `EncryptJWT`) on the primary VP path.
- X.509 / DID client-identifier material can be consumed from `x5c`, `jwks`, `jwks_uri`, or DID on the incoming JAR.

The material gaps are:

1. **WIA and WUA are self-signed, with no Wallet Provider identity or PoP separation.** The RFC expects `iss` to identify the Wallet Provider and expects the token-endpoint side of WIA to be paired with an `OAuth-Client-Attestation-PoP` JWT. The CLI (`src/index.js`) does **not** send either of the `OAuth-Client-Attestation` / `OAuth-Client-Attestation-PoP` headers that the current issuer (post-P0-7/P0-8) increasingly expects for RFC001 §7.3–7.4 compliance. The server (`src/server.js`) does send both headers but against a self-signed issuer identity.
2. **CLI token-endpoint payload is JSON, not `application/x-www-form-urlencoded`.** OpenID4VCI §6 / OAuth 2.0 mandate the token endpoint body to be form-encoded; the current issuer in this repo now rejects several fixtures that are not form-encoded. The server path is form-encoded (correct), but the CLI is not.
3. **`package.json` does not declare `yargs`.** `src/index.js` imports it at module load; the CLI cannot start on a clean install.
4. **Wallet never sends `OAuth-Client-Attestation-PoP` from the CLI entry point**, and never sends a `cnf` PoP JWT signed by the key referenced in WIA `cnf` from either entry point.
5. **Issuer metadata is not fetched by the CLI** — `src/index.js` talks directly to `${apiBase}/nonce`, `${apiBase}/credential_deferred` etc. without reading `/.well-known/openid-credential-issuer`. That is acceptable against the current issuer because the endpoints happen to match, but the RFC §7.7 SHALL requires the wallet to build requests from metadata.
6. **Signed issuer metadata and `issuer_info` are not consumed.** The issuer now exposes `issuer_info` (`registration_certificate`, registrar info) and has a roadmap item (P2-1) to sign metadata with `x5c`. The wallet processes neither.
7. **`eu-eaa-offer://` is not accepted.** The issuer (per RFC001 §7.1 SHALL 13 / §8.1) accepts this scheme today; the wallet maps `haip`/`haip-vci` to `openid-credential-offer:` but does not accept `eu-eaa-offer:`.
8. **`proofs.attestation` path is not implemented.** The wallet can only send `proofs.jwt` with a single element. §7.5.2 is not exercised.
9. **No multi-proof batching and no multi-attested-key issuance.** RFC001 §7.5.1 items 4–6 imply the wallet may attest multiple keys in WUA; the current wallet always attests **exactly one** key (the proof key). That matches §7.5.1 item 6 (sign with the **first** key) but blocks testing the issuer's newly-landed **P1-12** multi-key issuance.
10. **No notification endpoint call.** RFC001 §7.1 / §8.7 requires the wallet to `POST /notification` with the `notification_id` the issuer returned in the credential response when notification is supported.
11. **Deferred polling does not respect the issuer-supplied `interval`.** The CLI uses `--poll-interval 2000`; the server uses a fixed retry budget; neither reads the `interval` value returned by `/credential` / `/credential_deferred`. RFC §7.6 SHOULD text.
12. **WIA TTL is set up to 24 hours** (`createWIA({ ttlHours: 1 })` in flows; `createWIA` caps at just under 24h) where TS3/HAIP recommend shorter-lived instance attestations. For a self-signed testing wallet this is a documentation/clarity issue, not a security one.
13. **JAR validation on the VP path only consumes the first `x5c` certificate; no chain / trust-list validation.** `verifyAuthorizationRequestJwt` (`src/lib/presentation.js:225–281`) does not validate an X.509 chain, check revocation, or verify that the `client_id` matches the `x509_hash:` prefix now mandated by the ETSI-aligned RFC002 scope.
14. **No `client_id_scheme` enforcement.** The wallet accepts whatever signing material is embedded in the JAR; it does not reject requests that advertise `client_id_scheme: x509_hash` unless the `client_id` actually matches `x509_hash:<sha256(x5c[0])>`.
15. **DCQL satisfaction is superficial.** When the verifier sends a DCQL query with multiple credential IDs, the wallet builds `vp_token` as `{ [id]: [theSameVpToken] }` for every id (`src/lib/presentation.js:937–975`). It does not select per credential-id constraints (format/meta/claims); a DCQL query that asks for two different credential formats will still receive one token copied per id.
16. **mdoc VP is structurally correct but cryptographically unbound.** `buildMdocPresentation` emits a `DeviceResponse` CBOR, but it never calls `getSessionTranscriptBytes`, never passes the transcript to a `DeviceAuth` signer, and never includes `mdoc_generated_nonce`. `getSessionTranscriptBytes` exists (`utils/mdlVerification.js:261–269`) but is unused on the submission path. The wallet's own `MDOC_PRESENTATION_FIX.md` already acknowledges this as future work.
17. **Selective disclosure on mdoc is absent.** The VP echoes the wallet's stored `IssuerSigned` data verbatim; no filtering by DCQL-requested namespaces/elements is applied. RFC §9.1 (SHOULD data minimisation) and `APT-PRES-WALLET-08` / `-11` indirectly expect the wallet to release only what was approved.
18. **No Holder consent UI.** `POST /present` authenticates via a `sessionId` and auto-submits. `APT-PRES-WALLET-08` and §6.1.4 require *explicit* Holder approval before presentation. For a test wallet this is a scoping decision, but the backlog should record it.
19. **`wallet_metadata` is not sent to the verifier** even when the verifier's request targets capabilities that would normally be negotiated through it. `utils/cryptoUtils.js` defines a `wallet_metadata` shape for *building* encrypted authorization requests (not for consuming them), and it is not wired into `performPresentation`.
20. **`vp_token` error response is never emitted in RFC002 §8.3.4 form.** On failure during presentation, the wallet's server replies with its own ad-hoc JSON shape, not with `error=invalid_presentation|malformed_response|user_cancellation|...` at the verifier's `response_uri`.
21. **No SD-JWT claim-set filtering.** The SD-JWT VP appends every disclosure the wallet holds for the credential; DCQL claim-paths (`claims` array) are not enforced when selecting which disclosures to include.
22. **CLI and server do not share issuance code.** The compliance delta between the two is structural: the server uses `buildOAuthClientAttestationHeaders`, form-encoded bodies, issuer metadata discovery, PAR, and retry logic; the CLI does none of these. A conformance run against either entry point will produce different verdicts.
23. **`src/index.js` typo / fragility**: `--key` argument is re-used for DPoP, proof, WIA, and WUA pairs; if the file is provided, the same key material signs four different JWTs (proof, DPoP, WIA, WUA). This is functionally tolerable but violates the intent of WIA/WUA as attestations issued by a distinct Wallet Provider. (Server path also derives separate key pairs from the same file handle for WIA vs proof, but still co-mingles.)

Overall assessment by track:

- **RFC001 baseline wallet**: partial — blockers are (1)–(4) and (10); metadata-driven request construction (5) is expected by §7.7 but is currently hard-coded.
- **RFC001 ETSI-aligned wallet**: not compliant — blockers are (6), (7), (8), (12), (14), plus the Wallet-Provider trust separation that (1) cannot satisfy while WIA/WUA remain self-signed.
- **RFC002 SD-JWT / ETSI-aligned wallet**: partial — blockers are (13), (14), (15), (20), (21).
- **RFC002 ISO/IEC 18013-7 remote mdoc wallet**: invocation and structurally working; cryptographically unbound — blockers are (16), (17).

### A.1 RFC001 — wallet obligations section by section

#### §5 Protocol Overview — partially aligned

Met:

- Authorisation-code and pre-authorized flows supported (`src/server.js:191-195, 352-374, 413-459`; `src/index.js:56-118`).
- Sender-constrained tokens via DPoP (`src/lib/crypto.js:99-119`; `src/server.js:995-1014`, `1189-1208`; `src/index.js:72-91`, `206-234`).
- `c_nonce` flow via token response or `/nonce` fallback (`src/index.js:130-142`; `src/server.js:1088-1110`, `1662-1684`).

Missing:

- `A128GCM` / `A256GCM` negotiation on credential-response encryption is not exercised from the wallet — the wallet never asks for encrypted credential responses, so `credential_response_encryption` is not sent in the credential request body. The issuer advertises both; this is a wallet gap when ETSI profile alignment is claimed.
- `eu-eaa-offer://` scheme not accepted on offer ingest (`src/index.js:319-327`, `src/server.js:482-489`).

#### §6.1.1 Configuration and discovery — partial

Met:

- Server-side: `discoverIssuerMetadata`, `discoverAuthorizationServerMetadata` (`src/server.js:549-651`, `658-697`) read issuer + AS metadata, including validation of `attest_jwt_client_auth`.

Missing / wrong:

- CLI does **not** fetch issuer metadata at all. RFC §7.7 Wallets SHALL 1–3.
- Signed issuer metadata with `x5c` is not consumed (neither CLI nor server).
- `issuer_info` is not consumed (neither CLI nor server). Registration certificate is not validated or shown to the Holder.

#### §6.1.2 User selects credential — aligned

- Offer resolution extracts `credential_configuration_ids` / legacy `credentials` and picks the first or the CLI-supplied `--credential` (`src/index.js:40-52`; `src/server.js:533-541`).

#### §6.1.3 PAR — partial

Met:

- Server uses PAR when the issuer advertises it (`src/server.js:1476-1536`).

Missing / wrong:

- CLI does not implement PAR at all. CLI does pre-authorized only.
- WIA is **not** sent at PAR in the CLI. Server does send WIA via `buildOAuthClientAttestationHeaders` (`src/server.js:866-904`, invoked around `1034-1039`, `1623-1629`).
- Neither entry point verifies the AS metadata's `client_id` binding before issuing a PAR request; the wallet trusts whatever URL the offer provided.
- WIA on the server is self-signed (see §7 below), so while the presence is right, the trust model is not.

#### §6.1.5 Token request — partial

Met (server):

- Form-encoded body, `authorization_details` as JSON string, WIA as `client_assertion` plus `OAuth-Client-Attestation` / `OAuth-Client-Attestation-PoP` headers, DPoP.

Missing / wrong:

- **CLI**: JSON body (should be `application/x-www-form-urlencoded`), no `OAuth-Client-Attestation` / `OAuth-Client-Attestation-PoP` headers. This breaks interop with the current issuer for flows that require attested client authentication.
- WIA PoP JWT on server is built by `createOAuthClientAttestationPopJwt` (`src/lib/crypto.js:211-233`) but it is signed by the same `publicJwk` that WIA's `cnf.jwk` was built from; this is the right key pair *conceptually* but only because WIA is self-signed (the Wallet-Provider-issued WIA would normally name a device-bound `cnf` key whose private material the wallet holds).
- No handling of §7.3 SHOULD: "treat expired or rejected WIA material as a recoverable client-authentication failure and obtain fresh attestation material before retrying."
- `tx_code` is sent by the CLI when the offer's `tx_code` structure requires it (`src/index.js:367-373`) but only as a placeholder "111…1" string; the server also sends any `tx_code` the offer advertised.

#### §6.1.6 / §8.6 Nonce Endpoint — aligned

- CLI and server both obtain a fresh `c_nonce` from `/nonce` when the token response omits it.
- When the issuer now requires `Authorization: Bearer|DPoP` at `/nonce` (issuer P1-11), the server sends it; the CLI also sends `Authorization: Bearer ${accessToken}` when calling `/nonce` (`src/index.js:132-134`).

#### §6.1.6 / §7.5 / §8.5 Credential Request — partial

Met:

- `proofs: { jwt: [proofJwt] }` shape (`src/index.js:199-204`; `src/server.js:1175-1179`).
- Proof JWT carries `typ: openid4vci-proof+jwt`, `jwk`, `iss=did:jwk:…`, `aud=credential_issuer`, fresh `nonce`, `iat`, `exp`, `jti`.
- WUA is embedded in the proof JWT's protected header as `key_attestation` (RFC §7.5.1 Wallets SHALL 3).
- WUA `attested_keys` contains the proof public key; the wallet signs the proof JWT with the corresponding private key (RFC §7.5.1 Wallets SHALL 6).
- DPoP on `/credential` when the access token is DPoP-bound.

Missing / wrong:

- `proofs.attestation` path is not implemented at all (§7.5.2).
- `proofs.jwt` always carries exactly one element — right per §7.5.1 item 1, but the wallet never exercises the "multiple attested keys in WUA → issuer returns multiple credentials" scenario, even though the issuer now supports it (P1-12). `attested_keys` is always `[publicJwk]`, never a longer list.
- The wallet does not request encrypted credential responses (`credential_response_encryption` is never set in the request body) even though the issuer advertises `["A128GCM", "A256GCM"]` (issuer P2-4).
- `credential_identifiers` returned in the token response's `authorization_details` (issuer P1-13) are **not** consumed by the wallet; the credential request always sends `credential_configuration_id` instead.

#### §6.3 / §7.6 / §8.8 Deferred issuance — partial

Met:

- Both entry points recognise HTTP 202 and a `transaction_id`; both poll `/credential_deferred`; both send DPoP when the access token is DPoP-bound.

Missing / wrong:

- Neither entry point honours the issuer-returned `interval` for back-off.
- Neither entry point handles the new `issuance_pending` / `expired_transaction_id` / `invalid_transaction_id` codes (issuer P1-7). The server's retry loop sees those as generic errors and bails.
- No persistence of deferred state across wallet restarts.

#### §7.1 / §8.7 Notification endpoint — not implemented

- No `notification_endpoint` reference anywhere in `wallet-client/` (keyword sweep: 0 hits). The issuer returns `notification_id` in credential responses (`routes/issue/sharedIssuanceFlows.js`) and now enforces binding to the token's session (issuer P1-8); the wallet silently ignores it.

#### §7.3 WIA (Wallet Instance Attestation) — partial (self-signed)

Met (structural):

- `createWIA` produces a JWT with `iss`, `aud`, `iat`, `exp`, `jti`, `cnf.jwk` and `typ: JWT` (`src/lib/crypto.js:156-179`).
- Sent as `client_assertion` + `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.

Missing / wrong:

- `iss` is set to the wallet's own `did:jwk` (`src/index.js:97`, `src/server.js:1020-1023`). RFC §7.3 expects `iss` to identify a **Wallet Provider** that the issuer can look up in a trusted list. Since this is a testing wallet, **this is an accepted shortcut**, but the report records it so that a future deployment can replace it without hunting.
- No `sub` claim. OAuth Attestation-Based Client Authentication draft defines `sub` as the wallet instance identifier; `createWIA` omits it.
- The WIA's `typ` is `JWT`. The OAuth Attestation-Based Client Authentication draft uses `oauth-client-attestation+jwt`. The wallet's dedicated `createOAuthClientAttestationJwt` helper (`src/lib/crypto.js:181-209`) does set `typ: oauth-client-attestation+jwt`, but the CLI path calls `createWIA` instead, so the CLI sends a generic `JWT` `typ`.
- TTL up to 24 hours. §7.3 SHOULD: "Treat expired or rejected WIA material as a recoverable client-authentication failure and obtain fresh attestation material before retrying" — no re-provisioning path exists because the attestation is generated in memory on every request.
- CLI does **not** send `OAuth-Client-Attestation` / `OAuth-Client-Attestation-PoP` headers. Server does (`buildOAuthClientAttestationHeaders`).

#### §7.5 WUA (Wallet Unit Attestation) — partial (self-signed)

Met (structural):

- `createWUA` produces `typ: key-attestation+jwt`, `iss`, `aud`, `iat`, `exp`, `jti`, `attested_keys: [publicJwk]`, `eudi_wallet_info` with `general_info` and `key_storage_info` (`src/lib/crypto.js:252-281`).
- Carried in the proof JWT's protected header `key_attestation` parameter (RFC §7.5.1 item 3 ✓).
- Proof JWT is signed by the private key whose public JWK is the **first** entry of `attested_keys` (RFC §7.5.1 item 6 ✓).

Missing / wrong:

- `iss` is the wallet's own `did:jwk`. Same note as WIA: acceptable shortcut for a testing wallet, but must be flagged.
- `attested_keys` is always length 1. No ability to drive multi-key issuance.
- No `status` claim or `status_list` reference, so the issuer cannot exercise WUA revocation / status checks. Issuer P1-3 tracks the issuer-side status-list consumer; without a status list on the wallet side, that issuer path cannot be end-to-end tested.
- `eudi_wallet_info.key_storage_info` is hard-coded to `software`/`software` (`src/index.js:170-178`, `src/server.js:1137-1146`). That's honest ("we are a software test wallet"), but for any attested trust level above `software` the shape is unused.

#### §7.7 Server metadata — partial

- Server path discovers issuer and AS metadata (see §6.1.1).
- Signed issuer metadata and `issuer_info` are **not** validated.
- OAuth metadata is discovered, but the wallet does not verify that the issuer's advertised `grant_types_supported` includes the grant the offer uses before proceeding (§7.7 SHALL 2).

### A.2 RFC001 §10.1 deployed-test-matrix mapping (wallet rows only)

| Check | RFC text | Current wallet status |
| --- | --- | --- |
| `VCI-CHECK-01` | Metadata discovery | Partial — server yes, CLI no. |
| `VCI-CHECK-02` | Authorisation-code flow with PAR / PKCE S256 | Partial — server yes, CLI not implemented. |
| `VCI-CHECK-03` | Pre-authorized flow | Yes. |
| `VCI-CHECK-03A` | WIA at PAR and Token + PoP of `cnf` key | Partial — server sends WIA + `OAuth-Client-Attestation*` headers but against a self-signed Wallet Provider identity. CLI sends `client_assertion` only, no attestation headers. |
| `VCI-CHECK-04` | Pre-auth `tx_code` handling | Partial — placeholder numeric code sent; no user prompt. |
| `VCI-CHECK-05` | Sender-constrained token use at `/credential` | Yes — DPoP `ath` computed correctly. |
| `VCI-CHECK-06` | Proof JWT correctness (`typ`, `iss`, `aud`, `nonce`, freshness) | Yes. |
| `VCI-CHECK-06A` | `key_attestation` / WUA in proof header, attested-key binding | Partial — structurally correct; WUA is self-signed; `attested_keys` always length 1. |
| `VCI-CHECK-07` | Signature-profile interop | Yes on ES256. Other algs not exercised. |
| `VCI-CHECK-08` | mdoc issuance with mdoc-appropriate proof path | Partial — wallet stores mdoc credentials but has not been exercised on issuance path. |
| `VCI-CHECK-09` | tx-code-aware flow | Partial — see `VCI-CHECK-04`. |
| `VCI-CHECK-10` | `A128GCM` / `A256GCM` response encryption | No — the wallet never asks for an encrypted credential response. |

### A.3 RFC002 — wallet obligations section by section

#### §5 Protocol overview — partial

Met:

- SD-JWT VC and mdoc tracks both addressable through `performPresentation` (`src/lib/presentation.js`).
- Signed JAR accepted (`verifyAuthorizationRequestJwt` at `src/lib/presentation.js:225-281`).
- `request_uri` resolution via GET or POST (`107-141`).

Missing / wrong:

- `client_id` / `client_id_scheme` validation per ETSI profile (`x509_hash:`). The wallet does not check the RFC002 ETSI-mandated prefix; any `client_id` that matches the JAR's `client_id` claim is accepted.
- `verifier_info` from the request JWT is not parsed or presented.

#### §6.1.3 Wallet validates request before consent — partial

- Wallet enforces `nonce` presence, `alg != none`, `client_id` vs deep-link consistency.
- No explicit "freshness" check beyond the JWT signature (no `exp`/`iat` window enforced on the JAR itself, only on disclosures).
- No trust-anchor check on the JAR signer (first `x5c[0]` is used as-is).
- No user-facing presentation of verifier identity / purpose (see §6.1.4 below).

#### §6.1.4 User interaction / Holder consent — not implemented

- `POST /present` submits automatically after request validation. No explicit approval step.
- `verifier_info` / purpose / requested credentials / selective-disclosure preview is not surfaced anywhere (no UI; the wallet is API-only).
- `APT-PRES-WALLET-15` — "Wallet SHALL NOT perform silent or automatic consent for requests that require user approval" — currently violated by design.

#### §6.1.5 Build the VP — partial

SD-JWT (met):

- KB JWT with `typ: kb+jwt`, `sd_hash`, `nonce`, `aud` (`src/lib/presentation.js:786-794`; `src/lib/crypto.js:54-64`).
- Disclosures appended (`attachKbJwtToSdJwt` at `src/lib/presentation.js:348-358`).

SD-JWT (missing):

- No filtering by DCQL `claims` array — all disclosures are attached regardless of what the verifier asked for. Fails §9.1 (data minimisation SHOULD).

JWT VC (met):

- Wallet signs a JWT-VP with `typ: openid4vp+jwt` embedding the VC (`src/lib/presentation.js:361-390, 886-899`).

mdoc (partial):

- `DeviceResponse` CBOR is constructed and base64url-encoded (`utils/mdlVerification.js:314-386`).
- `SessionTranscript` is not reconstructed or bound. `getSessionTranscriptBytes` exists but is unused.
- No `DeviceAuth` signing (`deviceSignature` / `deviceMac`).
- No `mdoc_generated_nonce` (keyword: 0 hits).
- `IssuerSigned` is echoed verbatim; no per-element selective disclosure.

#### §7.1 APT-PRES-WALLET-*  rollup

| ID | Requirement | Status |
| --- | --- | --- |
| `APT-PRES-WALLET-01` | Receive request via `request_uri` | Yes. |
| `APT-PRES-WALLET-02` | Support signed Request Objects | Yes (verifies JWS, but no trust-chain validation). |
| `APT-PRES-WALLET-03` | Validate request integrity | Partial — signature only, no chain / revocation. |
| `APT-PRES-WALLET-04` | Preserve request-response correlation | Yes (`nonce`, `state`, `aud`). |
| `APT-PRES-WALLET-05` | Validate before showing to user | N/A — no UI. |
| `APT-PRES-WALLET-06` | Reject invalid requests | Partial. |
| `APT-PRES-WALLET-07` | Present request to Holder transparently | Not implemented. |
| `APT-PRES-WALLET-08` | Holder explicit approval | Not implemented. |
| `APT-PRES-WALLET-09` | Generate OpenID4VP-conformant response | Yes. |
| `APT-PRES-WALLET-10` | Bind response to request via nonce/aud | Yes on SD-JWT; partial on mdoc. |
| `APT-PRES-WALLET-11` | Submit to verifier endpoint per request | Yes. |
| `APT-PRES-WALLET-12` | Use response mode the request requires | Yes (`direct_post`, `direct_post.jwt`). |
| `APT-PRES-WALLET-13` | SHALL NOT accept invalid/unsupported requests silently | Partial — errors raised but not returned as RFC-aligned error codes at `response_uri`. |
| `APT-PRES-WALLET-14` | Surface verifier info to Holder | Not implemented. |
| `APT-PRES-WALLET-15` | SHALL NOT silent-consent | Currently violated by design. |
| `APT-PRES-WALLET-MDOC-01` | Accept mdoc request | Yes. |
| `APT-PRES-WALLET-MDOC-02` | `request_uri` for ISO remote | Yes. |
| `APT-PRES-WALLET-MDOC-03` | Build `SessionTranscript` via OID4VP handover mapping | **No**. |
| `APT-PRES-WALLET-MDOC-04` | Generate `DeviceResponse` bound through `SessionTranscript` | **No** (`DeviceResponse` is built without transcript binding). |
| `APT-PRES-WALLET-MDOC-05` | Encode in `vp_token` base64url | Yes. |
| `APT-PRES-WALLET-MDOC-06` | Submit mdoc `vp_token` | Yes. |
| `APT-PRES-WALLET-MDOC-07` | Encrypt mdoc response | Partial — `direct_post.jwt` JWE supported; not defaulted for mdoc track. |

#### §8.2 / §8.3 Presentation Request and Response interfaces — partial

Met:

- `request_uri` GET and POST (`src/lib/presentation.js:107-141`).
- DCQL consumption (`525-583`).
- Response mode selection (`485-501`).
- `direct_post.jwt` encryption via verifier JWK (`1016-1104`).

Missing / wrong:

- ETSI-scope `client_id_scheme: x509_hash` not enforced by the wallet (it just reads whatever `client_id` the JAR carries).
- No `presentation_submission` synthesis for DCQL-only flows; correct by the RFC002 §8.3 reading, but the wallet always omits `presentation_submission` when DCQL is used — some RFC002 profile variants still require it. Left as-is for now.
- DCQL-to-`vp_token` mapping copies one VP across every `credentials[].id` (`src/lib/presentation.js:937-975`). A multi-credential DCQL query is not answered faithfully.

#### §8.3.4 Error responses — not aligned

- No `invalid_presentation`, `malformed_response`, `user_cancellation`, `expired_request`, `failed_correlation`, `failed_validation` codes returned to `response_uri`. Errors bubble up to the wallet-server HTTP caller instead.

#### §9 Privacy / security — partial

- Transaction-data base64url decoding + `credential_ids` subset check implemented (`522-582`), but `tx_hashes` (binding to a hash of the transaction-data entry) is not computed or embedded into the KB JWT for SD-JWT, nor into `DeviceResponse` for mdoc.
- Replay protection: verifier `nonce` is echoed; `state` echoed when present; JWT `jti` in KB JWT. OK.
- Data minimisation: not implemented (SD-JWT disclosures not filtered; mdoc elements not filtered).

### A.4 RFC002 §11.1.1 deployed-test-matrix mapping (wallet rows only)

| Check | RFC text | Current wallet status |
| --- | --- | --- |
| `VP-CHECK-01` | Request resolution and processing | Yes. |
| `VP-CHECK-02` | ETSI-aligned `client_id` prefix | **No** — wallet does not enforce `x509_hash:`. |
| `VP-CHECK-03` | Signed Request Object validation | Partial — JWS only, no chain / trust anchor. |
| `VP-CHECK-04` | `verifier_info` processing | **No**. |
| `VP-CHECK-05` | DCQL request satisfaction | Partial — shape correct, per-id format/meta satisfaction incomplete. |
| `VP-CHECK-06` | Response correlation | Yes (`state`, `nonce`). |
| `VP-CHECK-07` | Nonce binding | Yes for SD-JWT; mdoc transcript-nonce binding absent. |
| `VP-CHECK-08` | SD-JWT proof-binding (`sd_hash`, `aud`) | Yes. |
| `VP-CHECK-09` | Encrypted response handling | Yes for `direct_post.jwt`. |
| `VP-CHECK-10` | Transaction-data binding | Partial — validated structurally, not hash-bound into VP. |
| `VP-CHECK-11` | mdoc `DeviceResponse` validation | Wallet builds — no `SessionTranscript` binding. |
| `VP-CHECK-12` | Request-URI retrieval | Yes (GET + POST). |
| `VP-CHECK-13` | ISO mdoc invocation `mdoc-openid4vp://` | Yes — accepted on parse. |
| `VP-CHECK-14` | ISO mdoc request structure | Yes — DCQL `mso_mdoc` consumed. |
| `VP-CHECK-15` | ISO `SessionTranscript` binding | **No**. |
| `VP-CHECK-16` | ISO mdoc encrypted response | Partial — `direct_post.jwt` works, not defaulted on mdoc track. |
| `VP-CHECK-17` | ETSI authorization-endpoint invocation (`eu-eaap://`) | **No** — scheme not accepted. |
| `VP-CHECK-18` | Registration-material transport | **No** — `verifier_info` not consumed. |

### A.5 Assumptions baked into the backlog

- **WIA/WUA are and will remain self-signed for this testing wallet**, per user direction on 2026-04-20. The backlog does not ask for a Wallet Provider integration; it only asks for:
  1. Explicit documentation that the WIA/WUA `iss` is the wallet's own identity and is therefore not a trust anchor.
  2. Keeping the shape right (`typ`, claims set, PoP) so that the issuer's validation path against real WP keys can later be exercised with a one-line config change.
  3. Allowing the wallet to be configured to rotate the self-signed key pair (fresh attestation) on demand, so §7.3 SHOULD-text retry behaviour can be tested.
- **ISO/IEC 18013-7 mdoc cryptographic binding** is **future work**, matching the verifier review's scoping decision. The backlog tracks this as P2 / future.
- **CS-03 QES** and **DC API** flows are **not in scope** for this backlog.

---

## Part B — Alignment Backlog

Priority scheme (same as the issuer and verifier backlogs):

- **P0** — Blocks RFC baseline compliance, security-relevant, or blocks end-to-end testing against the already-aligned issuer/verifier.
- **P1** — Needed for RFC baseline conformance or clear implementation bug.
- **P2** — Needed only for the ETSI TS 119 472-3 aligned profile path or for future mdoc cryptographic binding.
- **P3** — Hygiene, metadata cleanup, known bugs not on the compliance-critical path.

Each item lists: **RFC anchor**, **code location**, **what to do**, **acceptance criterion**.

---

### B.1 P0 — blockers

#### P0-W-1. Fix CLI token-endpoint body and attestation headers

- RFC: RFC001 §6.1.5, §6.2.6, §7.4; OAuth 2.0 Attestation-Based Client Authentication.
- Code: `wallet-client/src/index.js:65-120`, `wallet-client/src/index.js:375-385` (`httpPostJson`).
- Do:
  - Send the token-endpoint body as `application/x-www-form-urlencoded` (use `URLSearchParams`), not JSON.
  - Add `OAuth-Client-Attestation: <WIA JWT>` and `OAuth-Client-Attestation-PoP: <PoP JWT>` headers, matching the server path's `buildOAuthClientAttestationHeaders` (`wallet-client/src/server.js:866-904`).
  - Continue sending `client_assertion` / `client_assertion_type` in the body as a backward-compatible fallback until the issuer drops it.
- Acceptance:
  - `POST /token_endpoint` from the CLI is form-encoded.
  - `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers are present on every token request from the CLI.
  - `wallet-client/test/tokenUtils.test.js` extended with a "CLI sends form body + attestation headers" unit test.

#### P0-W-2. Declare `yargs` in `wallet-client/package.json`

- RFC: n/a (build/runtime bug).
- Code: `wallet-client/package.json`, `wallet-client/src/index.js:2-3`.
- Do: add `"yargs": "^17.x"` to `dependencies`.
- Acceptance: `npm install --prefix wallet-client` followed by `node wallet-client/src/index.js --help` prints the usage string without a module-not-found error.

#### P0-W-3. Pull `notification_id` out of credential response and POST `/notification`

- RFC: RFC001 §7.1 SHOULD 3; §7.7 SHALL 4; §8.7.
- Code: new function in `wallet-client/src/server.js` near `validateAndStoreCredential` (around `1908-1983`); CLI path in `src/index.js:296-303`.
- Do:
  - When the credential response payload contains a `notification_id`, POST `{ notification_id, event: "credential_accepted" }` to the issuer's advertised `notification_endpoint` using the same access token (with DPoP if the access token is DPoP-bound).
  - Retry once on 5xx; surface 4xx as a wallet-side log event, not a hard fail.
  - Persist `notification_id` in the credential cache alongside the credential so deferred completion can also notify.
- Acceptance:
  - Against the current issuer, a successful issuance ends with a `POST /notification` visible in the issuer log, and the issuer's P1-8 bind check succeeds.

#### P0-W-4. Self-signed WIA/WUA: document and isolate the Wallet Provider identity

- RFC: RFC001 §7.3, §7.5 (`iss` = Wallet Provider).
- Code: `wallet-client/src/lib/crypto.js:156-179, 252-281`; `wallet-client/src/index.js:93-108, 156-185`; `wallet-client/src/server.js:1017-1170`.
- Do:
  - Introduce a single **`WALLET_PROVIDER_ID`** config field (env + optional `data/wallet-provider.json`) used as `iss` for both WIA and WUA. Default to the wallet's own `did:jwk` derived from a **dedicated** key pair stored under `wallet-client/walletprovider/` — separate from the device-bound proof key.
  - Rotate this pair independently of the proof key; the same pair signs WIA, WUA, and the OAuth-Client-Attestation PoP.
  - Update `createWIA` to also set `sub` to the wallet instance id (e.g., a stable UUID per `wallet-client` install persisted in Redis).
  - Change WIA `typ` used on the RFC001 path to **`oauth-client-attestation+jwt`** (the dedicated builder `createOAuthClientAttestationJwt` already does this — route both code paths through it).
  - Keep **all** key material self-signed; document in this report and in `wallet-client/README.md` that this is a **testing-only** arrangement.
- Acceptance:
  - `iss` on WIA and WUA is no longer `did:jwk:<proofKey>`; it is a distinct wallet-provider key.
  - A single env var switch would let the wallet consume an externally-minted WIA/WUA instead of self-signing (even if that switch is not implemented in this backlog cycle).
  - Unit tests assert `typ: oauth-client-attestation+jwt` for the client assertion sent at token/PAR; `typ: key-attestation+jwt` for the WUA in the proof header.

**Done (2026-04-20).** `WALLET_PROVIDER_ID` / `data/wallet-provider.json`; dedicated key `walletprovider/ec-p256-es256.json`; instance id via Redis (`WALLET_INSTANCE_ID` or `walletprovider/instance-id.txt` fallback). RFC001 token/PAR client attestation = `createOAuthClientAttestationJwt` (`typ: oauth-client-attestation+jwt`); WUA = `createWUA` with provider key + `sub` (`typ: key-attestation+jwt`). External hook: `WALLET_USE_EXTERNAL_ATTESTATION` + `WALLET_EXTERNAL_*`. Docs: `wallet-client/README.md`; tests: `test/walletProviderIdentity.test.js`.

#### P0-W-5. Stop co-mingling proof / DPoP / WIA / WUA keys when `--key` is supplied

**Done (2026-04-20).** Default device key `data/device-key.json` (`resolveDeviceKeyPath`, `WALLET_DEVICE_KEY_PATH`); WP key `data/wallet-provider-key.json`; `ensureOrCreateEcKeyPair` persists when a path is given. Server and CLI use distinct paths for proof/DPoP vs attestation.

- RFC: RFC001 §7.3, §7.5; general key-separation hygiene.
- Code: `wallet-client/src/index.js:77, 96, 150, 162`; `wallet-client/src/server.js:1000-1002, 1020, 1124, 1132`.
- Do:
  - Treat `--key` (or equivalent server config) as the **device-bound proof / DPoP key only**.
  - WIA/WUA signing key comes from the Wallet-Provider key bundle introduced in P0-W-4.
  - When no keys are on disk, generate and persist the proof/DPoP pair to `wallet-client/data/device-key.json` and the WP pair to `wallet-client/data/wallet-provider-key.json`, creating the folder if needed.
- Acceptance:
  - `ensureOrCreateEcKeyPair` is called with two distinct paths for proof vs WP.
  - Re-running the CLI does not regenerate either key unless the file is deleted.

#### P0-W-6. Build credential request from issuer metadata (CLI) **done CLI is out of scope should remove**

- RFC: RFC001 §6.1.1, §7.7 SHALL 1-3.
- Code: `wallet-client/src/index.js:54-65` (hard-coded `/token_endpoint`, `/nonce`, `/credential`, `/credential_deferred`).
- Do:
  - On startup, GET `${credential_issuer}/.well-known/openid-credential-issuer` and `${credential_issuer}/.well-known/oauth-authorization-server` (fallback `/.well-known/openid-configuration`).
  - Use the returned `token_endpoint`, `nonce_endpoint`, `credential_endpoint`, `deferred_credential_endpoint`, `notification_endpoint` rather than hard-coded paths.
  - Validate that the selected grant is in `grant_types_supported`, and that the wallet's preferred `credential_response_encryption.enc` / `alg` is advertised before requesting encryption.
- Acceptance:
  - CLI works against an issuer that mounts its endpoints at non-default paths (integration test with a prefixed issuer).

#### P0-W-7. Accept `eu-eaa-offer://` offer scheme

**Done (2026-04-20).** `normalizeCredentialOfferDeepLink` in `src/lib/credentialOfferScheme.js`; CLI + `resolveOfferConfig` in server; `/session` deep-link gate includes `eu-eaa-offer://`. Tests: `test/credentialOfferScheme.test.js`.

- RFC: RFC001 §6.2.3, §7.1 SHALL 13, §7.2 SHALL 8, §8.1.
- Code: `wallet-client/src/index.js:319-327`; `wallet-client/src/server.js:482-489`.
- Do: add `eu-eaa-offer://` to the normalisation regex (alongside `haip://`, `haip-vci://`).
- Acceptance:
  - Offer URIs starting with `eu-eaa-offer://` are resolved to the same credential-offer JSON shape as `openid-credential-offer://`.

---

### B.2 P1 — strong alignment / publishable claim

#### P1-W-1. Consume `credential_identifiers` from the token response

**Done (2026-04-20).** `buildCredentialRequestSelector` / `extractFirstCredentialIdentifierFromTokenResponse` in `utils/tokenUtils.js`; CLI + pre-auth + code-flow credential requests. Tests in `test/tokenUtils.test.js`.

- RFC: RFC001 §6.1.5, §6.2.7.
- Code: `wallet-client/src/server.js` (token handling around `1048-1110`, credential request around `1160-1180`); CLI `src/index.js:125-128, 199-204`.
- Do: if the token response sets `authorization_details[*].credential_identifiers`, use the first such identifier as `credential_identifier` in the credential request body, instead of `credential_configuration_id`. Keep `credential_configuration_id` as the fallback when the token response did not return identifiers.
- Acceptance: against an issuer that returns `credential_identifiers`, the wallet's credential request carries `credential_identifier`, not `credential_configuration_id`.

#### P1-W-2. Request encrypted credential responses when advertised **done** 

- RFC: RFC001 §5 (ETSI enc baseline); §6.1.6.
- Code: `wallet-client/src/server.js` credential request builder (~`1160-1180`); new helper `buildCredentialResponseEncryption({ ephemeralJwk, enc })`.
- Do:
  - Read `credential_response_encryption.alg_values_supported` and `enc_values_supported` from issuer metadata.
  - Generate an ephemeral ECDH-ES P-256 key pair, send `credential_response_encryption: { jwk, alg: "ECDH-ES", enc: <first advertised> }` in the request body.
  - Decrypt the JWE response using the ephemeral private key; continue the existing storage logic with the decrypted payload.
- Acceptance:
  - Integration test against the issuer with `enc: "A128GCM"` and `enc: "A256GCM"` both passing.

#### P1-W-3. Honour deferred `interval` and the new pending/terminal error codes

- RFC: RFC001 §6.3, §7.6; OIDC4VCI 1.0 §9.
- Code: `wallet-client/src/index.js:243-288`; `wallet-client/src/server.js:1280-1355, 1797-1870`.
- Do:
  - Read `interval` from the immediate `/credential` response (when deferred) and from `/credential_deferred` pending responses; sleep at least that many seconds between polls.
  - Recognise `error=issuance_pending` → continue polling.
  - Recognise `error=invalid_transaction_id` / `error=expired_transaction_id` → stop polling, surface a terminal failure.
  - Treat any other 4xx as a terminal failure.
- Acceptance: deferred flow against the post-P1-7 issuer completes without client-side retry-storms.

#### P1-W-4. Implement `proofs.attestation` path

- RFC: RFC001 §7.5.2 Wallets SHALL 1-3.
- Code: new branch in `wallet-client/src/server.js` credential request (`~1160-1180`); CLI branch in `src/index.js:199-204`.
- Do:
  - Add a `--proof-mode attestation` option (CLI) / config flag (server) that, instead of building a proof JWT, sends `proofs: { attestation: [<WUA JWT>] }` with the WUA carrying the proof key in `attested_keys`.
  - The WUA continues to be signed by the Wallet Provider key (self-signed for this testing wallet).
  - The attested key used for the KB / DPoP remains the same device-bound key as before.
- Acceptance:
  - Issuer-side `VCI-CHECK-06A` passes on both `proofs.jwt` and `proofs.attestation` modes.

#### P1-W-5. Support multi-attested-key WUA to drive multi-key issuance

- RFC: RFC001 §7.5.1 items 4-6; §7.5.2 items 2-3.
- Code: `wallet-client/src/lib/crypto.js:252-281`; server credential flow around `1124-1170`.
- Do:
  - Accept an optional `--attest-keys N` option / config. Generate `N` device-bound EC P-256 key pairs, include all `N` public JWKs in `attested_keys`, sign the proof JWT with the **first** private key.
  - Persist all `N` keys to the wallet credential cache so the wallet can use any of them for KB later.
- Acceptance:
  - Against the post-P1-12 issuer, a single credential request with `attested_keys.length === 3` results in 3 issued credentials, each bound to a different attested key (end-to-end test).

#### P1-W-6. Enforce RFC002 `client_id_scheme: x509_hash` on ETSI-aligned requests

- RFC: RFC002 §5.2, §8.2, §8.2.2; `VP-CHECK-02`.
- Code: `wallet-client/src/lib/presentation.js:225-291` (`verifyAuthorizationRequestJwt`), deep-link parser `93-104`.
- Do:
  - If the request JWT's `client_id_scheme` claim is `x509_hash` (or if the `client_id` has prefix `x509_hash:`), require a non-empty `x5c` in the JWT header, verify the signature against the leaf certificate, and **verify** that `client_id == "x509_hash:" + base64url(SHA-256(DER(leaf)))`.
  - If the scheme is `x509_san_dns`, keep the existing looser validation but warn.
  - Reject any other scheme with an RFC002 `invalid_request`-shaped error (see P1-W-10).
- Acceptance:
  - A request whose `client_id` does not match the hash of its `x5c[0]` is rejected before Holder consent (or before auto-submission).

#### P1-W-7. Parse and surface `verifier_info`

- RFC: RFC002 §8.2.2, `APT-PRES-WALLET-14`, `VP-CHECK-04`, `VP-CHECK-18`.
- Code: `wallet-client/src/lib/presentation.js` (new helper `parseVerifierInfo(payload)`); expose through the wallet server's `POST /present` response for integration testing.
- Do:
  - Pull `verifier_info` out of the request JWT payload, normalise `registration_certificate`, `rp_registrar_uri`, `service_description`, `purpose`, `privacy_policy_uri`, `intended_use`.
  - Return it in the wallet's `/present` response alongside the submission outcome so that a calling test harness can assert it surfaced correctly.
- Acceptance:
  - `POST /present` returns a `verifier_info` object that matches what the post-P0-2 verifier emits.

#### P1-W-8. Fix DCQL `vp_token` per-id satisfaction

- RFC: RFC002 §8.2.3.1, `VP-CHECK-05`, `VP-CHECK-14`.
- Code: `wallet-client/src/lib/presentation.js:937-983`.
- Do:
  - For each `dcql_query.credentials[]` entry, run the existing credential-selection logic **scoped to that entry's `format`, `meta`, `claims`**, producing a per-entry VP token (SD-JWT with KB or mdoc `DeviceResponse`).
  - Emit `vp_token` as `{ [entry.id]: [vpForThatEntry] }` — one VP per entry, not a single VP repeated.
  - Reject the request if any required entry cannot be satisfied by the wallet's stored credentials.
- Acceptance:
  - A DCQL query with two `credentials[]` entries of different formats (`dc+sd-jwt`, `mso_mdoc`) is answered with two distinct VPs.

#### P1-W-9. Filter SD-JWT disclosures by DCQL `claims`

- RFC: RFC002 §9.1 (SHOULD); `APT-PRES-WALLET-10`.
- Code: `wallet-client/src/lib/presentation.js:786-884` (KB construction + `attachKbJwtToSdJwt`).
- Do:
  - Parse `dcql_query.credentials[].claims` (JSON pointer / path list).
  - When attaching disclosures to the SD-JWT, include only the disclosures whose decoded claim path appears in the verifier's `claims` list.
  - When the verifier omits `claims`, fall back to the current behaviour (include all disclosures).
- Acceptance:
  - An SD-JWT VP built for a request that asks only `["given_name"]` contains exactly the `given_name` disclosure plus the KB JWT, and nothing else.

#### P1-W-10. Return RFC002 §8.3.4 error codes to `response_uri`

- RFC: RFC002 §8.3.4.
- Code: `wallet-client/src/lib/presentation.js:1132-1344` (submission path); `wallet-client/src/server.js` `POST /present`.
- Do:
  - When presentation is rejected locally (invalid request, missing credential, user-cancellation equivalent), POST `{ error: <code>, error_description }` to the verifier's `response_uri` using the same response mode the request asked for, with codes from `{invalid_presentation, malformed_response, user_cancellation, expired_request, unsupported_credential_format, missing_required_proof, failed_correlation, failed_validation}`.
  - Mirror the error in the wallet server's JSON response so the test harness can assert it.
- Acceptance:
  - A deliberately-malformed request produces an `error=malformed_response` at the verifier's `response_uri`, not an ad-hoc 500 from the wallet server.

#### P1-W-11. Persist `client_id` and RFC002 session state on the wallet side

- RFC: RFC002 §8.3.1; `APT-PRES-WALLET-04`. **done**
- Code: `wallet-client/src/lib/presentation.js` session object build-up around `485-510`; `wallet-client/src/server.js` presentation session storage.
- Do:
  - Store `{ client_id, response_uri, response_mode, nonce, state, dcql_query, transaction_data }` in Redis keyed by the wallet session id before building the VP, so that the submission path and any error-response path (P1-W-10) can read them.
- Acceptance:
  - Wallet logs for a single presentation show the exact `client_id` and `response_uri` used, and P1-W-10 can read them after a failure.

#### P1-W-12. Bind `transaction_data` hash into the VP **done** 

- RFC: RFC002 §8 transaction-data binding; `VP-CHECK-10`.
- Code: `wallet-client/src/lib/presentation.js:522-582` (decode) + KB JWT builder.
- Do:
  - For SD-JWT VPs, add `transaction_data_hashes` to the KB JWT payload: for each advertised `transaction_data` entry, compute `base64url(SHA-256(entry.raw))`, using the verifier's advertised hash algorithm from `transaction_data_hashes_alg_values` (fall back to SHA-256). Add `transaction_data_hashes_alg` with the selected algorithm.
  - For mdoc VPs, document that transaction-data hashing will be wired through the `SessionTranscript` work (future; see P2-W-3).
- Acceptance:
  - KB JWT for a presentation that carries a CS-03 / payment transaction-data entry includes `transaction_data_hashes`; the verifier accepts it.

---

### B.3 P2 — ETSI-aligned profile / future mdoc cryptographic binding

#### P2-W-1. Fresh-attestation-on-rejection for WIA

- RFC: RFC001 §7.3 SHOULD.
- Code: `wallet-client/src/server.js` token handler retry branch (`~1050-1110`).
- Do: on `400 invalid_client` / `invalid_dpop_proof` from the token endpoint where the error description suggests expired WIA, rotate the WP key pair (from P0-W-4) and retry once.

#### P2-W-2. Accept `eu-eaap://` same-device VP invocation **done**

- RFC: RFC002 §8.1 `VP-CHECK-17`.
- Code: `wallet-client/src/lib/presentation.js:93-104` (deep-link scheme parse).
- Do: add `eu-eaap://` as an accepted scheme alongside `openid4vp://`, `mdoc-openid4vp://`.

#### P2-W-3. mdoc cryptographic binding — wire `SessionTranscript`, `OID4VPHandover`, `mdoc_generated_nonce`, `DeviceAuth` **done**

- RFC: RFC002 §8.2.5, `APT-PRES-WALLET-MDOC-03/04/10`, `VP-CHECK-15`.
- Code: `wallet-client/utils/mdlVerification.js:261-269` (transcript builder), `:314-386` (`buildMdocPresentation`), `wallet-client/src/lib/presentation.js:937-983` (mdoc submission branch).
- Do (sequenced):
  1. Generate a fresh `mdoc_generated_nonce` per presentation.
  2. Build `SessionTranscript = [null, null, ["OID4VPHandover", client_id, response_uri, mdoc_generated_nonce, verifier_nonce]]` via `getSessionTranscriptBytes`.
  3. CoSE-sign `DeviceAuthentication([SessionTranscript, docType, deviceNameSpacesBytes])` with the device-bound key, attach as `deviceSignature` inside `DeviceAuth`.
  4. Pass the transcript through to `direct_post.jwt` as `apu` / `apv` or through `wallet_metadata.mdoc_generated_nonce` when the verifier expects it there.
- Acceptance: end-to-end mdoc presentation against a transcript-validating verifier (future work).

#### P2-W-4. mdoc selective disclosure **done**

- RFC: RFC002 §9.1.
- Code: `wallet-client/utils/mdlVerification.js` selective-build helper.
- Do: filter `issuerSigned.nameSpaces` to the elements requested by the DCQL `claims` list; re-serialize `IssuerSigned` with only the selected `DataElementIdentifier` entries; update `valueDigests` accordingly (or rely on the subset-disclosure mechanism from ISO 18013-5 §9).

#### P2-W-5. Consume signed issuer metadata and `issuer_info` **Done**

- RFC: RFC001 §7.7 SHALL 5 (ETSI), §8.9.
- Code: `wallet-client/src/server.js:549-592` (`discoverIssuerMetadata`).
- Do: when the issuer response is a JWS with `application/jwt` or `typ: jwt`, verify against `x5c` in the protected header; extract the payload; surface `issuer_info.registration_certificate` to the test harness for assertion.

#### P2-W-6. `wallet_metadata` parameter on VP requests **done**

- RFC: RFC002 §8.2 (optional wallet_metadata).
- Code: `wallet-client/src/lib/presentation.js:107-141` (`request_uri` POST body).
- Do: when POSTing to `request_uri`, include `wallet_metadata` advertising supported `vp_formats`, `response_modes`, `mdoc_generated_nonce` (for mdoc track), and the wallet's encryption JWK for `direct_post.jwt`.

---

### B.4 P3 — hygiene

#### P3-W-1. Reconcile CLI and server issuance code paths

- Code: `wallet-client/src/index.js`, `wallet-client/src/server.js`.
- Do: extract the shared issuance steps (`buildTokenRequest`, `postTokenEndpoint`, `fetchNonce`, `buildCredentialRequest`, `pollDeferred`, `notify`) into `wallet-client/src/lib/issuance.js` and call from both. Avoids the CLI-vs-server compliance drift noted in A.0 item 22.

#### P3-W-2. Drop `--poll-interval` / `--poll-timeout` in favour of issuer-provided `interval`

- Code: `wallet-client/src/index.js:17-22, 243-288`.
- Do: remove the CLI flags after P1-W-3 lands (or keep as overrides for edge-case interop testing, but not as defaults).

#### P3-W-3. Clean up unused directories and helpers

- Code: `wallet-client/X25519/`, `wallet-client/utils/cryptoUtils.js` (parts unused by `server.js`/`presentation.js`).
- Do: either delete the directory or wire it into a documented path. `X25519/` is copied by `wallet-client/Dockerfile:27` but never referenced in code; same check for `x509/`, `x509EC/` if confirmed unused after P1-W-6.

#### P3-W-4. Add wallet-side RFC-001 / RFC-002 deployed-test matrix

- RFC: RFC001 §10.1; RFC002 §11.1.1.
- Code: new files `wallet-client/docs/rfc001-wallet-test-matrix.yml`, `wallet-client/docs/rfc002-wallet-test-matrix.yml`.
- Do: one row per `VCI-CHECK-NN` / `VP-CHECK-NN` with a concrete CLI / server invocation that exercises it against the local issuer and verifier. Mirrors the shape of `aptitude-vci.yml` / `aptitude-vp.yml` at the repo root.

#### P3-W-5. Replace the hard-coded `"Test Wallet Client"` in `eudi_wallet_info`

- Code: `wallet-client/src/index.js:170-178`, `wallet-client/src/server.js:1137-1146`.
- Do: move name, version, `storage_type`, `protection_level` into `wallet-client/data/wallet-info.json`. Log a single clear warning at startup if `protection_level` is left at `"software"` (the default for this self-signed testing wallet).

---

### B.5 Suggested phasing

1. **Phase 1 (make the CLI usable against the current issuer)**: P0-W-1, P0-W-2, P0-W-6, P0-W-7, P1-W-3.
2. **Phase 2 (attestation path correctness while staying self-signed)**: P0-W-3, P0-W-4, P0-W-5, P1-W-4, P1-W-5, P3-W-5.
3. **Phase 3 (RFC002 ETSI-aligned)**: P1-W-6, P1-W-7, P1-W-8, P1-W-9, P1-W-10, P1-W-11, P1-W-12.
4. **Phase 4 (issuance shape extras)**: P1-W-1, P1-W-2, P2-W-5.
5. **Phase 5 (future work)**: P2-W-1, P2-W-2, P2-W-3, P2-W-4, P2-W-6, P3-W-*.

---

## Traceability matrix (summary)

| Backlog item | RFC §§ | RFC-check coverage |
| --- | --- | --- |
| P0-W-1, P0-W-4, P0-W-5 | RFC001 §7.3, §7.4 | `VCI-CHECK-03A` |
| P0-W-2 | build | n/a (runtime bug) |
| P0-W-3 | RFC001 §7.1, §8.7 | notification section |
| P0-W-6 | RFC001 §7.7 | `VCI-CHECK-01` |
| P0-W-7 | RFC001 §8.1 | `VCI-CHECK-09` (invocation) |
| P1-W-1 | RFC001 §6.1.5 | `VCI-CHECK-02` |
| P1-W-2 | RFC001 §5 (ETSI) | `VCI-CHECK-10` |
| P1-W-3 | RFC001 §6.3, §7.6 | deferred matrix |
| P1-W-4, P1-W-5 | RFC001 §7.5.1, §7.5.2 | `VCI-CHECK-06A` |
| P1-W-6 | RFC002 §5.2, §8.2.2 | `VP-CHECK-02` |
| P1-W-7 | RFC002 §8.2.2 | `VP-CHECK-04`, `VP-CHECK-18` |
| P1-W-8 | RFC002 §8.2.3.1 | `VP-CHECK-05`, `VP-CHECK-14` |
| P1-W-9 | RFC002 §9.1 | data minimisation |
| P1-W-10 | RFC002 §8.3.4 | error taxonomy |
| P1-W-11 | RFC002 §8.3.1 | `VP-CHECK-06`, `VP-CHECK-08` |
| P1-W-12 | RFC002 §8 | `VP-CHECK-10` |
| P2-W-1 | RFC001 §7.3 | recoverable-WIA SHOULD |
| P2-W-2 | RFC002 §8.1 | `VP-CHECK-17` |
| P2-W-3, P2-W-4 | RFC002 §8.2.5, §9.1 | `VP-CHECK-11`, `VP-CHECK-15`, `APT-PRES-WALLET-MDOC-03/04/10` |
| P2-W-5 | RFC001 §7.7, §8.9 | ETSI metadata |
| P2-W-6 | RFC002 §8.2 | `wallet_metadata` |
| P3-W-* | hygiene | n/a |

---

## Bottom line

The wallet-client has the right protocol shape for both RFC001 and RFC002 but is currently the weakest of the three roles in this repo against the RFC text. The CLI entry point is the more non-compliant of the two — it bypasses metadata discovery, uses a JSON token-endpoint body, does not send the OAuth-Attestation headers the issuer now requires, and does not notify. The server entry point is closer, but still misses encrypted credential responses, `credential_identifiers`, multi-attested-key issuance, RFC002 `x509_hash` validation, `verifier_info` surfacing, DCQL per-entry satisfaction, and RFC002 error codes.

With P0 and P1 items landed, the wallet can credibly claim:

- **RFC001 baseline wallet**: compliant against this repo's post-P0/P1 issuer, with WIA/WUA explicitly self-signed for testing.
- **RFC001 ETSI-aligned wallet**: partial — real Wallet-Provider trust material is out of scope; shape, keys, and headers are correct.
- **RFC002 SD-JWT / ETSI-aligned wallet**: compliant against this repo's post-P0 verifier.
- **RFC002 ISO/IEC 18013-7 remote mdoc wallet**: invocation and structurally compliant; cryptographic `SessionTranscript` / `DeviceAuth` binding deferred to P2-W-3 as future work.

Until P0-W-4 lands, every line of this report that says "WIA" or "WUA" means **self-signed WIA / WUA using wallet-generated keys** and therefore should be read as a shape-correctness guarantee, not a trust-framework guarantee.
