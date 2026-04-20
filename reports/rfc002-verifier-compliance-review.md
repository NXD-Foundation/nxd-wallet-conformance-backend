# RFC002 Verifier Compliance Review & Alignment Backlog

Reviewed against `~/Downloads/RFC002 (1).md`.  
Initial review: 2026-04-16. Revalidated and merged with alignment backlog: 2026-04-20.

Scope of this document:

- Verifier-side behaviour only.
- Current implementation on `main`.
- Combined output: compliance findings (Part A) + prioritised alignment backlog (Part B).
- RFC-check IDs follow RFC002 §11.2 (`VP-CHECK-NN`) and §7.2 (`APT-PRES-VER-*`).

Scoping decisions that shape the backlog:

- **ISO/IEC 18013-7 mdoc track** is scoped to **structural and invocation conformance only** in this round. Full cryptographic `SessionTranscript` / `IssuerAuth` / `DeviceAuth` validation is explicitly deferred and tracked under "Future work" (Part B §4).
- **RFC002-strict becomes the default** on the primary x509 and standardized verifier routes. Legacy behaviour (`x509_san_dns`, unsigned `direct_post`) stays reachable as opt-in query parameters for interop testing.
- The legacy `/direct_post_jwt/:id` response route is **consolidated** into `/direct_post/:id` rather than hardened in place.

---

## Part A — Revalidated Compliance Review

### A.0 Executive summary

The verifier implementation is materially closer to RFC002 conformance than the issuer side. What is already correct:

- Signed request-object generation (JAR) with `typ: oauth-authz-req+jwt`.
- `request_uri`-based invocation, both GET and POST (`request_uri_method`).
- Same-device and cross-device invocation patterns for the generic OpenID4VP / SD-JWT flows.
- `direct_post`, `direct_post.jwt`, and `dc_api.jwt` response-mode handling.
- `direct_post` state correlation and SD-JWT `nonce` / `sd_hash` validation on the modern `/direct_post/:id` path.
- DCQL-based request generation.
- Encrypted response decryption for `direct_post.jwt` and `dc_api.jwt` using the verifier JWKS.

The material gaps against RFC002 are:

1. `client_id` defaults to `x509_san_dns:` everywhere; RFC002 ETSI-aligned scope requires `x509_hash:`.
2. `verifier_info` is never emitted in request objects, and there is no structured source for it.
3. There is no `mdoc-openid4vp://` invocation scheme; the mdoc route still emits `openid4vp://`.
4. There is no `eu-eaap://` same-device invocation scheme.
5. The mdoc response path decodes CBOR and filters claims but performs **no cryptographic validation at all** — no `IssuerAuth` (MSO), no `DeviceAuth`, no `SessionTranscript` reconstruction. (This was labelled "partial" in the previous review; it is more accurately "absent".)
6. `ETSI mandatory encrypted response` is not the default on the ETSI-aligned routes.
7. Legacy `/direct_post_jwt/:id` route bypasses the strong validation stack used by `/direct_post/:id`.
8. The main session helpers do **not** persist `client_id`, so SD-JWT `aud` validation is skipped on most routeUtils-based flows even though the response handler has a conditional check for it.
9. `direct_post.jwt` correlation is only partial: `state` is checked for one encrypted-payload branch, but not consistently across the unencrypted and encrypted-JWT-string branches.
10. Several verifier routes still pass `presentation_definition` into `buildVpRequestJWT()`, but that builder now rejects PEX entirely; these branches are stale and in some cases runtime-broken, not merely dead code.
11. No dedicated verifier-metadata publication endpoint.
12. Error-response taxonomy does not follow RFC002 §8.3.4's codes.

Overall assessment by track:

- Baseline OpenID4VP verifier: partial but workable on the DCQL-based paths.
- RFC002 SD-JWT / ETSI-aligned verifier: partial — blockers are (1), (2), (6), (8), (9).
- RFC002 ISO/IEC 18013-7 remote mdoc verifier: structurally partial, cryptographically non-conformant.

### A.1 Section-by-section

#### §1–§4 Introduction, Scope, Roles

Informational. Verifier code surface is split across
`routes/verify/verifierRoutes.js`, `routes/verify/x509Routes.js`, `routes/verify/mdlRoutes.js`,
`routes/verify/vpStandardRoutes.js`, `utils/routeUtils.js`, `utils/cryptoUtils.js`,
`utils/mdlVerification.js`, and configuration in `data/verifier-config.json`.

#### §5 Protocol overview

Partially aligned.

Implemented:

- Signed request-object generation via `buildVpRequestJWT()` — `utils/cryptoUtils.js:313`.
- `request_uri`-based invocation URL generation — `utils/routeUtils.js:1182`, `:1327`.
- SD-JWT validation paths including `nonce` and `sd_hash` — `routes/verify/verifierRoutes.js:1234`, `:1264`, `:1364`, `:1986`.
- Encrypted response handling — `routes/verify/verifierRoutes.js:656`, `:924`.
- mdoc/DCQL request generation — `routes/verify/mdlRoutes.js:61`.

Wrong / missing:

- ETSI-aligned `client_id` requirement is not the default. `CONFIG.CLIENT_ID` is set to `x509_san_dns:${hostname}` in `utils/routeUtils.js:217`.
- `verifier_info` is not present anywhere in the request payload construction — `utils/cryptoUtils.js:313–659`.
- The shared request URL helper emits `openid4vp://` only — `utils/routeUtils.js:1468`. The mdoc route uses the same helper — `routes/verify/mdlRoutes.js:61`.
- Active mdoc verification only decodes CBOR and filters claims — `utils/mdlVerification.js:15–207`.
- `storeVPSessionData()` and `handleSessionCreation()` do not persist `client_id`, so the later `aud` check guarded by `vpSession.client_id` is usually skipped on the primary verifier flows — `utils/routeUtils.js:1244–1293`, `:1529–1544`, `routes/verify/verifierRoutes.js:1341`, `:1987`.
- Several request-generation routes still supply `presentation_definition`, but `buildVpRequestJWT()` now throws when PEX is passed — `utils/cryptoUtils.js:358`, `routes/verify/x509Routes.js:143`, `routes/verify/didRoutes.js:61`, `routes/verify/didJwkRoutes.js:64`, `routes/verify/vpStandardRoutes.js:161`.

New finding (refinement over initial review):

- `buildVpRequestJWT` hard-codes `jwtPayload.aud = "https://self-issued.me/v2"` at `utils/cryptoUtils.js:339`, discarding the `audience` argument callers pass in. This is not the main RFC002 blocker, but the current API is misleading and should either document that constant explicitly or stop accepting an unused override parameter.

#### §6 High-level flows

##### 6.1.1 Presentation Request Creation — mostly aligned

Request generation stores session-bound `nonce`, `state`, `response_mode`, and DCQL — `utils/routeUtils.js:1198–1293`. JAR is signed and exposed via `request_uri` — `:1295–1327`.

Gaps: ETSI-aligned `client_id` and `verifier_info`. The shared session helper also fails to persist `client_id`, which weakens later response-time audience validation.

##### 6.1.2 Wallet Invocation — partial

Implemented: `openid4vp://?request_uri=...&client_id=...` + QR — `utils/routeUtils.js:1191`, `:1327`. GET / POST `request_uri_method` variants in `routes/verify/x509Routes.js:143`, `:184`.

Missing: `mdoc-openid4vp://`, `eu-eaap://`.

##### 6.1.6 Presentation Submission — aligned

Multiple `direct_post*` endpoints exist — `routes/verify/verifierRoutes.js:253`, `:2298`.

##### 6.1.7 Result Handling — broadly aligned

Modern path persists outcome in session — `routes/verify/verifierRoutes.js:1455`, `:1652`.

Gaps:

- `/direct_post_jwt/:id` uses a legacy in-memory session array and does not run the same checks — `routes/verify/verifierRoutes.js:2298–2383`.
- `direct_post.jwt` does not enforce `state` uniformly across all branches. It checks `state` for one encrypted-payload-object path (`routes/verify/verifierRoutes.js:1059–1079`), but not for the unencrypted JWT branch or the encrypted-JWT-string branch.

##### 6.2 Cross-Device Presentation Flow — broadly aligned for SD-JWT

Gap: mdoc track is not clearly separated from generic invocation mechanics. RFC002 excludes cross-device ISO mdoc, so the generic route should not advertise an `mso_mdoc` presentation over cross-device.

#### §7.2 Verifier Requirements

Met:

- OpenID4VP request / response handling.
- Response endpoint.
- Signed request objects.
- `request_uri` support.
- Transaction-data binding in request construction — `utils/cryptoUtils.js:370`.

Missing / wrong:

- `APT-PRES-VER-08` / `APT-PRES-VER-09` — validation is only **partial** on the modern SD-JWT path: `direct_post` has strong `state` correlation, but `direct_post.jwt` has only partial `state` correlation; `sd_hash` is enforced, but `aud` is checked only when `vpSession.client_id` is present, which the primary session helper does not store.
- `APT-PRES-VER-14` — structured verifier metadata including `verifier_info`: **not implemented**.
- ETSI `client_id` prefix (`x509_hash`): **not met by default**.
- `APT-PRES-VER-MDOC-04` — inputs needed for `SessionTranscript`: **partial** (client_id and response_uri flow through, but `mdoc_generated_nonce` / wallet nonce extraction is a stub).
- `APT-PRES-VER-MDOC-10` — reconstruct and validate `SessionTranscript`: **not implemented in the active path**.

#### §8 Interface definitions

##### 8.1 Wallet Invocation Interface — partial

Implemented: `openid4vp://` + QR. Missing: `mdoc-openid4vp://` (SHALL for ISO remote mdoc), `eu-eaap://` (SHOULD for ETSI same-device).

##### 8.2 Presentation Request Interface — partially aligned

Implemented: `client_id`, `nonce`, `state`, `response_mode`, `response_uri`, `aud`, DCQL, transaction data — `utils/cryptoUtils.js:313`. Integrity protection — `:426`. `x509_hash` support path exists — `:471`.

Missing / wrong:

- Main x509 flow uses `x509_san_dns` — `utils/routeUtils.js:217`, `routes/verify/x509Routes.js:148`.
- No `verifier_info` field.
- `data/verifier-config.json` carries no structured registrar data.
- Several routes still pass `presentation_definition` even though the shared JAR builder rejects PEX (`utils/cryptoUtils.js:358`). In `vpStandardRoutes.js` this is stale code; in some legacy generate-request routes it is a real runtime breakage.

##### 8.2.1 Baseline structural requirements — partial

Met: verifier identifier, response destination, nonce/state, integrity.

Missing: user-displayable structured verifier info beyond `client_metadata`, privacy-policy reference, purpose.

##### 8.2.2 ETSI-aligned request-object requirements — not compliant

Met: signed JAR, `client_metadata` present for non-redirect schemes — `utils/cryptoUtils.js:321`.

Missing: `x509_hash` default, `verifier_info`, registrar/registration-certificate material.

##### 8.2.3 Credential-format considerations — mostly aligned

Met: SD-JWT + DCQL, `mso_mdoc` + DCQL, transaction-data binding for CS-03.

##### 8.2.3.1 ISO/IEC 18013-7 remote mdoc request — only partially aligned

Met: DCQL with `format: "mso_mdoc"` — `utils/routeUtils.js:478`, `routes/verify/mdlRoutes.js:70`; request exposed by `request_uri` — `:95`.

Missing: `mdoc-openid4vp://`, `verifier_info`, real `SessionTranscript` enforcement.

##### 8.2.5 ISO/IEC 18013-7 session binding — not implemented as required

- `getSessionTranscriptBytes` helper exists — `utils/mdlVerification.js:248`, duplicated at `routes/verify/verifierRoutes.js:52`.
- Active verification does not reconstruct or verify the transcript — `utils/mdlVerification.js:15–207`.
- `extractDeviceNonce` is a placeholder returning `null` — `utils/mdlVerification.js:266`.
- No `IssuerAuth` (MSO COSE_Sign1) verification.
- No `DeviceAuth` signature / MAC verification.

##### 8.3 Presentation Response Interface — broadly aligned

Implemented: `direct_post` with `state`, `direct_post.jwt` with `response`, `dc_api.jwt`, DCQL-shape checks.

##### 8.3.1 Baseline response requirements — mostly aligned

Met: `direct_post` state correlation, SD-JWT nonce checks, SD-JWT `sd_hash` checks, and claim filtering on the modern path — `routes/verify/verifierRoutes.js:1234–1417`, `:1492–2006`.

Gaps:

- `direct_post.jwt` state handling is incomplete.
- SD-JWT `aud` checking is conditional on `vpSession.client_id` and therefore skipped on most routeUtils-based flows.
- `/direct_post_jwt/:id` — `routes/verify/verifierRoutes.js:2298` — does not enforce the richer correlation and proof-validation logic.

##### 8.3.2 ETSI-aligned response protection — partially aligned

Implemented: `direct_post.jwt` JWE decryption — `:924`; `dc_api.jwt` handling — `:656`; verifier metadata advertises encryption support — `data/verifier-config.json:21`.

Missing: encrypted responses mandatory under ETSI, but the generator defaults to `direct_post` in several routes — `utils/routeUtils.js:114`, `routes/verify/x509Routes.js:137`.

##### 8.3.3 Credential-format considerations — mostly aligned for SD-JWT, partial for mdoc

SD-JWT key-binding `sd_hash` checks are implemented. `aud` checks exist in code but are only effective when `vpSession.client_id` has been stored up front.

Gap: mdoc validation is structural only.

##### 8.3.3.1 ISO/IEC 18013-7 remote mdoc response — only partially aligned

Met: base64url CBOR decode — `utils/mdlVerification.js:74`; doc structure / docType presence — `:96`; claim filtering — `routes/verify/verifierRoutes.js:828`.

Missing: `DeviceResponse` cryptographic validation, `SessionTranscript` binding, device nonce extraction, strict `docType` match against the stored request.

##### 8.3.4 Error responses — partial

The RFC defines a machine-readable code taxonomy (`invalid_presentation`, `malformed_response`, `user_cancellation`, `expired_request`, `unsupported_credential_format`, `missing_required_proof`, `failed_correlation`, `failed_validation`). The verifier returns ad-hoc codes (`invalid_request`, `verification_failed`, `claims_mismatch`, `server_error`). Minor but visible to conformance testing.

##### 8.4 Verifier Metadata Interface — partially aligned

Local `client_metadata` supplied inline in the JAR and declared in `data/verifier-config.json:1`. No dedicated published endpoint (e.g. `/.well-known/openid-verifier-metadata`), no published `verifier_info`.

#### §9 Privacy and Security Considerations

Strengths: `direct_post` `state` correlation is enforced, SD-JWT `nonce` / `sd_hash` are enforced on the modern path, encrypted responses are supported, and transaction data is bound to session state.

Gaps: ETSI mandatory encrypted mode not default; mdoc session-binding & replay-resistance absent; `direct_post.jwt` correlation is incomplete; `/direct_post_jwt/:id` bypasses modern checks.

#### §10 Conformance

- SD-JWT verifier: partial — blocked by `x509_hash`, `verifier_info`, encrypted-by-default, and incomplete response correlation / audience validation on the main flows.
- ISO mdoc verifier: structural only — blocked by `mdoc-openid4vp://` and (out of scope this round) cryptographic `SessionTranscript` validation.

### A.2 RFC002 §11.2 deployed-test-matrix mapping

| Check | RFC text | Current status |
| --- | --- | --- |
| `VP-CHECK-01` | Request resolution and processing | Partial — `request_uri` resolution is implemented, but several legacy PEX-based request generators are stale/broken because the shared JAR builder rejects `presentation_definition`. |
| `VP-CHECK-02` | ETSI-aligned verifier identification | Partial — `x509_hash` signing path exists, but the default and primary x509 routes still use `x509_san_dns`. |
| `VP-CHECK-03` | Signed Request Object validation | Yes on the verifier-generation side — signed JARs are produced for the x509 / DID-based flows. |
| `VP-CHECK-04` | Structured verifier-information processing | No — `verifier_info` is not emitted and there is no structured verifier-info source file. |
| `VP-CHECK-05` | DCQL request satisfaction | Broadly yes — DCQL request generation is implemented for SD-JWT and mdoc tracks. |
| `VP-CHECK-06` | Response correlation | Partial — `direct_post` enforces `state`, but `direct_post.jwt` does not enforce it consistently across all branches. |
| `VP-CHECK-07` | Nonce binding | Partial — nonce checks exist for SD-JWT, but the ISO mdoc handover / transcript correlation is absent. |
| `VP-CHECK-08` | SD-JWT proof-binding validation | Partial — `sd_hash` and nonce are checked, but `aud` validation is skipped on most primary flows because `client_id` is not stored in the session. |
| `VP-CHECK-09` | Encrypted response handling | Partial — `direct_post.jwt` / `dc_api.jwt` decryption works, but encrypted response is not the default ETSI-aligned route behavior. |
| `VP-CHECK-10` | Transaction-data binding | Yes — transaction data is bound into the request/session flow and validated structurally. |
| `VP-CHECK-11` | mdoc `DeviceResponse` validation | No — the active path decodes and filters claims but does not perform ISO cryptographic validation. |
| `VP-CHECK-12` | Request-URI retrieval | Yes — both GET and POST `request_uri_method` variants are implemented. |
| `VP-CHECK-13` | ISO mdoc invocation method | No — `mdoc-openid4vp://` is not implemented. |
| `VP-CHECK-14` | ISO mdoc request structure | Partial — DCQL `mso_mdoc` requests include `format` and `doctype_value`, but the surrounding ISO-specific verifier-info and track separation are incomplete. |
| `VP-CHECK-15` | ISO `SessionTranscript` binding | No — not reconstructed or validated. |
| `VP-CHECK-16` | ISO mdoc encrypted response | Partial — encrypted response modes are supported, but not defaulted or consistently shaped as an ISO-specific path. |
| `VP-CHECK-17` | ETSI authorization-endpoint invocation | No — `eu-eaap://` is not implemented. |
| `VP-CHECK-18` | Remote verifier registration information transport | No — no `verifier_info`, no registration material transport. |

### A.3 Findings added during revalidation (not in the prior review)

1. The previous `VP-CHECK` table did not follow RFC002 §11.2 numbering. This revision corrects the mapping to the actual RFC check IDs and descriptions.
2. The main session helpers do not persist `client_id`, so SD-JWT `aud` validation is often skipped in the primary x509 / mdl / standardized flows.
3. `direct_post.jwt` state correlation is partial, not full: one encrypted branch checks it, the others do not.
4. Several `presentation_definition` request-generation branches are now stale or broken because `buildVpRequestJWT()` rejects PEX input.
5. `/direct_post_jwt/:id` is not just inconsistent — it can bypass `nonce` / `state` / `sd_hash` checks entirely.
6. No dedicated verifier-metadata publication endpoint.
7. RFC002 §8.3.4 error-code taxonomy is not followed.
8. `data/verifier-config-mdl.json` exists but is only wired into a single DC API mdl route; track separation is ad-hoc.
9. The mdoc cryptographic gap is wider than "partial": there is **no** `IssuerAuth` / `DeviceAuth` / `SessionTranscript` validation at all today.

### A.4 What the prior review got slightly wrong or imprecise

- "SD-JWT `aud` validation implemented" was too strong. The code path exists, but because `vpSession.client_id` is usually absent on the primary flows, the effective status is **partial**.
- "`presentation_definition` branches are dead code" was too soft. Some of those branches are stale; some are now runtime-broken because the shared JAR builder rejects PEX input.
- The old `VP-CHECK` table did not use RFC002 §11.2's actual check numbering and descriptions. The corrected mapping is in A.2.

---

## Part B — Alignment Backlog

All items use the chosen scope:

- ISO mdoc = **structural + invocation only**.
- RFC002-strict = **default** on primary x509 + standardized routes; legacy = opt-in.
- `/direct_post_jwt/:id` = **remove / consolidate**, not harden.

### B.1 P0 — blockers for any RFC002 conformance claim

#### P0-1 — Default `client_id_scheme = x509_hash` on ETSI-aligned routes

- Add `CONFIG.ETSI_CLIENT_ID` (or rename `CONFIG.CLIENT_ID`) that computes `x509_hash:<b64url(SHA-256(leafDer))>` on startup. Logic already present at `utils/cryptoUtils.js:491–496` — hoist it into `utils/routeUtils.js`.
- Primary flows become RFC002-strict by default:
  - `routes/verify/x509Routes.js` — both GET and POST `request_uri_method` branches.
  - `routes/verify/vpStandardRoutes.js` when `profile=etsi`/`rfc002`.
  - `routes/verify/mdlRoutes.js` when the track is ISO mdoc.
- Legacy `x509_san_dns` remains reachable via `?client_id_scheme=x509_san_dns`.
- Update `data/verifier-config.json` with `client_id_schemes_supported: ["x509_hash","x509_san_dns"]` and set `client_id` to the `x509_hash:` value.
- **Satisfies:** `VP-CHECK-02`; closes the ETSI `client_id` gap in §8.2.2.

#### P0-2 — Emit `verifier_info` in the signed request object

- New config file `data/verifier-info.json` (mirrors the pattern of `data/issuer-registration.json` on the VCI side) with:
  - `verifier_id` (e.g. DNS or legal-entity identifier)
  - `service_description`
  - `rp_registrar_uri` (stub URL acceptable for now)
  - `registration_certificate` (x5c of the verifier signing cert, or placeholder)
  - `intended_use`
  - `purpose`
  - `privacy_policy_uri`
- Extend `buildVpRequestJWT` to accept `verifier_info` and include it in the JAR payload — `utils/cryptoUtils.js:313–355`.
- Populate from config by default; allow per-request override through `routes/verify/*`.
- **Satisfies:** `APT-PRES-VER-14`, `VP-CHECK-04`, `VP-CHECK-18`; closes §8.2.1 and §8.2.2 gaps.

#### P0-3 — Encrypted response default on ETSI-aligned routes

- Flip RFC002-strict routes from `response_mode: "direct_post"` default to `"direct_post.jwt"`.
- Leave `direct_post` available through `?response_mode=direct_post` for interop / legacy.
- Fail fast at startup if `data/verifier-config.json` does not contain an `enc` JWK.
- **Satisfies:** `VP-CHECK-09`; closes §8.3.2.

#### P0-4 — ISO mdoc invocation via `mdoc-openid4vp://`

- Parameterise `createOpenID4VPRequestUrl(..., { scheme })` in `utils/routeUtils.js:1468`.
- `routes/verify/mdlRoutes.js` uses `scheme: "mdoc-openid4vp"` by default for same-device; `openid4vp` stays available via query param for interop.
- Update QR rendering and any wallet-selector copy.
- **Satisfies:** `VP-CHECK-13`; closes the invocation gap in §8.1 / §8.2.3.1.

#### P0-5 — Consolidate `/direct_post_jwt/:id` into `/direct_post/:id`

- Remove `/direct_post_jwt/:id` — `routes/verify/verifierRoutes.js:2298` (plus its session storage at `:2365`).
- Ensure any callers that pointed at it now target `/direct_post/:id`, then remove the bypass path entirely.
- Remove the legacy in-memory session array; session state goes through the existing Redis-backed store.
- **Satisfies:** §8.3.1 gap; closes the privacy/security concern in §9.

#### P0-6 — Fix response-correlation data on the modern path

- Persist `client_id` in `storeVPSessionData()` / `handleSessionCreation()` so the existing SD-JWT `aud` check becomes effective on the primary x509 / mdl / standardized flows.
- Make `direct_post.jwt` enforce `state` consistently across the encrypted-object, encrypted-JWT-string, and unencrypted-JWT branches.
- Re-run the `direct_post` / `direct_post.jwt` tests after the session-shape change.
- **Satisfies:** `APT-PRES-VER-08`, `APT-PRES-VER-09`, `VP-CHECK-06`, `VP-CHECK-08`.

### B.2 P1 — strong alignment / publishable claim

#### P1-1 — `eu-eaap://` same-device invocation (SHOULD)

- Add a `scheme: "eu-eaap"` branch to `createOpenID4VPRequestUrl`.
- Expose on ETSI-aligned same-device flow (either through `?scheme=eu-eaap` or through a dedicated `/vp/etsi/same-device` endpoint depending on UX).
- **Satisfies:** `VP-CHECK-17`.

#### P1-2 — Published verifier-metadata endpoint

- Add `GET /.well-known/openid-verifier-metadata` returning a merged document of `data/verifier-config.json` + `data/verifier-info.json` + JWKS (public keys only).
- Reference the endpoint from `client_metadata` where relevant.
- **Satisfies:** §8.4.

#### P1-3 — `aptitude-vp.yml` deployed-test matrix + initiation doc

- Create `aptitude-vp.yml` mirroring the shape of `aptitude-vci.yml`, with one row per `VP-001…VP-007`.
- Create `docs/rfc002-vp-test-case-initiation.md` mirroring `docs/rfc001-vci-test-case-initiation.md`.
- Each `VP-NNN` row maps to a concrete URL on this verifier with all query params pre-filled (track, client_id_scheme, response_mode, request_uri_method, scheme).
- **Satisfies:** §11.2 deployed-test matrix obligation.

#### P1-4 — Normalise verifier error codes to RFC §8.3.4

- Centralise all `res.status(4xx).json({ error: "..." })` call sites into a single helper in `utils/routeUtils.js`.
- Map existing codes:
  - `invalid_request` → `malformed_response` or `invalid_presentation` depending on source.
  - `verification_failed` → `failed_validation`.
  - `claims_mismatch` → `failed_validation` with a sub-reason.
  - `server_error` → stays.
- Add `failed_correlation`, `missing_required_proof`, `expired_request`, `user_cancellation`, `unsupported_credential_format` where relevant.
- **Satisfies:** §8.3.4.

### B.3 P2 — hygiene / polish

#### P2-1 — Remove `presentation_definition_*.json` loaders

- Delete or refactor the PEX-loading branches in `routes/verify/vpStandardRoutes.js` and the legacy generate-request routes, since the shared JAR builder rejects PEX input (`utils/cryptoUtils.js:358`).
- Remove associated fixture files under `data/` if unused elsewhere.

#### P2-2 — Name the `self-issued.me/v2` override and stop clobbering `audience`

- Introduce `DC_API_SELF_ISSUED_AUDIENCE = "https://self-issued.me/v2"` in `utils/cryptoUtils.js`.
- Either document that this constant is intentionally authoritative for VP requests, or remove the misleading `audience` parameter from callers. The current issue is clarity, not a proven RFC002 conformance failure.
- Add a code comment citing OpenID4VP §5.10.1.
- Covers line `utils/cryptoUtils.js:339`.

#### P2-3 — Tighten mdoc structural checks against stored request context

- In `utils/mdlVerification.js::validateMdlClaims`, check `document.docType` against the `doctype_value` set in the stored DCQL query.
- Reject disclosed namespaces/elements that were not requested (currently only the inverse direction is checked).
- **Satisfies:** `APT-PRES-VER-MDOC-07`, `APT-PRES-VER-MDOC-08` at the structural level.

#### P2-4 — Track-aware loading of `data/verifier-config*.json`

- Load `verifier-config.json` for SD-JWT track and `verifier-config-mdl.json` (renamed: `verifier-config-mdoc.json`) for the ISO mdoc track at the route entry point, instead of only for the one DC API mdl endpoint.

### B.4 Future work (explicitly out of scope this round)

These items would be required for a full RFC002 ISO mdoc conformance claim but are parked for a future cycle:

- **F-1** COSE_Sign1 verification of `issuerSigned.issuerAuth` (MSO) against a configured issuer trust list, including decoding the MSO and checking `valueDigests` against disclosed elements.
- **F-2** Reconstruct `SessionTranscript` = `[null, null, ["OpenID4VPHandover", client_id, response_uri, mdoc_generated_nonce, nonce]]` (or the v1.0 equivalent) and verify `deviceAuth` (`deviceSignature` or `deviceMac`) against it.
- **F-3** Wire `mdoc_generated_nonce` (from JWE `apu`/`apv` or `wallet_metadata.mdoc_generated_nonce`) and `wallet_nonce` through the transcript.
- **F-4** Replace the placeholder `extractDeviceNonce` — `utils/mdlVerification.js:266` — with a real extractor.
- **F-5** Trust-framework / trusted-list processing for `registration_certificate` in `verifier_info`.

Until F-1…F-5 land, the verifier explicitly documents that the ISO mdoc track is **invocation-and-structural conformant but not cryptographically binding**.

### B.5 Suggested order of execution

1. P0-1 + P0-2 + P0-3 together in a single branch (they all touch `buildVpRequestJWT` + `CONFIG` + the x509/standardized routes).
2. P0-4 (small, self-contained).
3. P0-5 + P0-6 together (remove the legacy bypass and fix the surviving path's session correlation).
4. P1-3 (the deployed-test matrix) — once P0 is in, the matrix reflects the new default behaviour.
5. P1-2 (metadata endpoint) once `verifier_info` shape is stable from P0-2.
6. P1-1, P1-4, and all P2 items in any order.
7. Future work (F-1…F-5) tracked separately.

---

## Bottom Line

After P0 lands, the verifier can credibly claim:

- Baseline OpenID4VP verifier: compliant on the maintained DCQL-based paths.
- RFC002 SD-JWT / ETSI-aligned verifier: compliant.
- RFC002 ISO/IEC 18013-7 remote mdoc verifier: **invocation and structurally** compliant; cryptographic `SessionTranscript` / `IssuerAuth` / `DeviceAuth` validation is explicitly deferred to future work.

After P1 lands, the verifier additionally has a published metadata endpoint and a deployed-test matrix (`aptitude-vp.yml`) suitable for plugging into the APTITUDE conformance harness.
