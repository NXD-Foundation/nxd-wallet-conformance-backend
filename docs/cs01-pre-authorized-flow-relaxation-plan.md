# CS-01 Pre-Authorized Flow Relaxation — Implementation Plan

This note plans how to relax the current **authorization-code-only** constraint in WE BUILD CS-01 mode so that `webuild-cs01` wallets and issuers support **both** grant types — **authorization code** and **pre-authorized code** — once the CS-01 specification is updated accordingly. Neither flow replaces the other; CS-01 conformance requires both to remain available.

It complements the existing CS-01 attestation implementation plan in [haip-etsi-wallet-attestation-options.md](./haip-etsi-wallet-attestation-options.md) (especially Phase 9, which intentionally locked pre-auth out of the conformance path).

## Background

### CS-01 v1.0 (28 November 2025)

The published CS-01 Credential Issuance spec currently states:

- §7.1: Authorisation Code Flow is the **only** flow for credential issuance.
- §7.2 / §6.2: Credential Offers **MUST** use `authorization_code`.
- §8.4: Token requests use `grant_type=authorization_code`.

§5 Protocol Overview also mentions “Pre-Authorised Code Flow”, which conflicts with §7.1. For ITB+ today, §7.x normative text is treated as authoritative.

### Planned spec relaxation

CS-01 is expected to be updated to permit **both**:

- wallet-initiated and issuer-initiated **authorization code** issuance (unchanged baseline), and
- issuer-initiated **pre-authorized code** issuance via Credential Offer.

This plan assumes the updated spec will **not** downgrade HA requirements for pre-auth (WUA, sender-constrained tokens, SD-JWT-VC proof binding, deferred `transaction_id`, etc.), but will remove the blanket prohibition on pre-authorized grants.

### OpenID4VCI v1.0 baseline

This plan is anchored in OpenID4VCI v1.0:

- OpenID4VCI v1.0 supports both `authorization_code` and `urn:ietf:params:oauth:grant-type:pre-authorized_code`.
- A Credential Offer identifies offered credentials with top-level `credential_configuration_ids`.
- The `grants` object tells the wallet which OAuth grant types the Authorization Server is prepared to process for that offer.
- When multiple grants are present, OpenID4VCI leaves the choice to the wallet.
- For pre-authorized code, the grant object carries `pre-authorized_code`, optional `tx_code`, and optional `authorization_server`. OpenID4VCI v1.0 does **not** define `scope` as a pre-auth grant parameter.
- For auth-code, `scope` is used in the Authorization Request. It can be discovered from `credential_configurations_supported[configurationId].scope` or supplied through a profile-specific convention.
- For pre-auth, the wallet can identify the requested Credential Configuration in the Token Request with `authorization_details` containing `credential_configuration_id`, and then request the credential with `credential_configuration_id` or `credential_identifier`. This is optional for a single offered Credential Configuration, but required by this plan when the offer contains multiple `credential_configuration_ids` and the wallet must narrow the request.

CS-01 may add stricter HA requirements on top of this baseline, such as WUA and DPoP, but it should not require non-VCI fields in a Credential Offer unless the updated CS-01 specification explicitly defines them.

### Operational trigger

Remote wallet deployments running `WALLET_PROFILE=webuild-cs01` currently reject real-world pre-auth offers such as:

```json
"grants": {
  "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
    "pre-authorized_code": "...",
    "tx_code": { "input_mode": "numeric", "length": 4 }
  }
}
```

Local runs succeed when `WALLET_PROFILE` is unset (`compatibility` default). The failure is profile enforcement, not issuer metadata discovery.

## Problem Summary


| Item                           | Current state                                                                                                                     |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| Wallet CS-01 grant routing     | `selectVciGrantRoute()` rejects any offer without `authorization_code`                                                            |
| Wallet `/session` and `/issue` | `assertPreAuthorizedAllowed()` blocks pre-auth in `webuild-cs01`                                                                  |
| Wallet pre-auth implementation | Already sends WUA headers, DPoP, and credential proof binding — but only reachable outside CS-01 mode                             |
| Issuer pre-auth routes         | Exist (`preAuthSDjwRoutes.js`, `vciStandardRoutes.js`) but are not profiled as CS-01 conformance targets                          |
| Issuer token endpoint          | WUA optional for pre-auth; DPoP optional (bearer fallback)                                                                        |
| Credential selection (CS-01)   | Auth-code path resolves scope for the Authorization Request; pre-auth path does not yet validate/use `credential_configuration_ids` and `authorization_details` as the VCI v1.0 identification model |
| CS-01 tests                    | Explicitly assert pre-auth is rejected in CS-01 mode                                                                              |
| Docs / matrices                | [vci-preauth-pid-x509-wallet-matrix.md](./vci-preauth-pid-x509-wallet-matrix.md) describes compatibility-mode pre-auth, not CS-01 |


Relevant code paths:

- `wallet-client/src/lib/profile.js` — grant gating (`assertCs01AuthorizationCodeGrant`, `assertPreAuthorizedAllowed`, `selectVciGrantRoute`)
- `wallet-client/src/server.js` — `/session`, `/issue`, `runPreAuthorizedIssuance()`
- `wallet-client/src/lib/scopeResolution.js` — CS-01 scope requirements
- `wallet-client/test/cs01Conformance.test.js`, `wallet-client/test/profile.test.js`
- `routes/issue/sharedIssuanceFlows.js` — shared token/credential/deferred handlers
- `routes/issue/preAuthSDjwRoutes.js` — pre-auth offer generation

## Target Profile Shape (pending final CS-01 wording)

Until the updated CS-01 text is published, implement against these **working assumptions**:

### Design principle: dual-grant CS-01

CS-01 mode **MUST** support both issuance paths with full HA requirements on each:

- **Authorization code** — wallet-initiated and issuer-initiated (via Credential Offer with `authorization_code` grant). PAR, PKCE, WUA, DPoP, scope or `authorization_details`, JWT proof. Unchanged from current CS-01 implementation.
- **Pre-authorized code** — issuer-initiated (via Credential Offer with `urn:ietf:params:oauth:grant-type:pre-authorized_code` grant). DPoP, Wallet Unit Attestation sent by the wallet, `credential_configuration_ids`, optional token-request `authorization_details` except when narrowing multiple offered configurations, JWT proof. No PAR.

Offers may advertise one grant or both. The wallet selects the applicable route; both routes are first-class CS-01 conformance paths.


| Flow                                    | Entry              | PAR          | Token grant                                            | WUA at token | DPoP         | Credential proof                          |
| --------------------------------------- | ------------------ | ------------ | ------------------------------------------------------ | ------------ | ------------ | ----------------------------------------- |
| Auth code (wallet- or issuer-initiated) | Offer or discovery | **Required** | `authorization_code`                                   | **Required** | **Required** | JWT + WUA header (existing CS-01 path)    |
| Pre-authorized (issuer-initiated)       | Credential Offer   | **Not used** | `urn:ietf:params:oauth:grant-type:pre-authorized_code` | **Required** | **Required** | JWT + WUA header (same as auth-code path) |


### Pre-auth-specific rules (assumed)

1. **PAR does not apply** — there is no authorization endpoint step; do not require PAR for pre-auth offers.
2. **`tx_code`** — when advertised in the offer, the wallet **MUST** collect and send it; issuers **MUST** validate it when advertised.
3. **Credential identification** — pre-auth follows OpenID4VCI v1.0: select one of the offered `credential_configuration_ids`, send `authorization_details` with that `credential_configuration_id` in the Token Request when narrowing/identifying the requested credential is needed, and request the credential by `credential_configuration_id` or returned `credential_identifier`. Do **not** require `scope` on the pre-auth grant; that field is not defined by OpenID4VCI v1.0.
4. **Multi-configuration offers** — if a pre-auth offer contains multiple `credential_configuration_ids`, the wallet **MUST** narrow the Token Request with `authorization_details`.
5. **Refresh tokens** — refresh token support for pre-auth issuance is RECOMMENDED / SHOULD, not mandatory.
6. **Deferred issuance** — unchanged: `transaction_id` (not `acceptance_token`), poll with Bearer + DPoP, 202 pending + `interval`, terminal `invalid_transaction_id` / `credential_request_denied`.
7. **Transaction code model** — `tx_code` is the OpenID4VCI token-request transaction code only. The pre-auth Token Endpoint exchanges the code once and returns either an access token or a normal token error such as `invalid_grant`; it does **not** use HAIP/draft-era `authorization_pending` / `slow_down` polling. Waiting semantics belong to the Credential / Deferred Credential endpoints via `202`, `transaction_id`, and `interval`.
8. **No compatibility downgrade in CS-01** — pre-auth in CS-01 mode still forbids legacy body `client_assertion` and bearer-only fallback.
9. **WUA enforcement stage** — the wallet should send Wallet Unit Attestation on pre-auth token requests, but issuers should not hard-fail missing/invalid WUA yet. For now, issuers log and report WUA non-compliance.

### Grant selection when both grants are present (wallet)

When a Credential Offer contains **both** grants, the wallet must still support **either** path — selection picks which one to execute for that session, not which ones CS-01 allows:

1. If updated CS-01 specifies a preference, follow the spec.
2. Until then:
  - offer has **only** `authorization_code` → auth-code path
  - offer has **only** `pre-authorized_code` → pre-auth path
  - offer has **both** → prefer `authorization_code` for wallet-initiated sessions; for issuer-initiated deep links, prefer the grant that matches how the offer was constructed (default: `authorization_code` if both are present unless the request specifies `grantPreference`)
3. ITB+ test suites should include scenarios for **auth-code-only**, **pre-auth-only**, and **dual-grant** offers.

## Open Questions for CS-01 Authors and Answers

Resolve these before marking conformance complete:

1. Can a CS-01 Credential Offer include **only** `pre-authorized_code`, or must it also advertise `authorization_code`? YES
2. Should CS-01 make token-request **authorization_details** mandatory for pre-auth, even though OpenID4VCI v1.0 treats it as optional? Keep authorization_details optional generally
3. If a pre-auth offer contains multiple `credential_configuration_ids`, must the wallet always narrow the Token Request with `authorization_details`? YES
4. Is **refresh token** support expected for pre-auth issuance? Recommended / SHOULD, not MUST
5. Does §5 “Pre-Authorised Code Flow” imply HAIP-level tx_code polling (`authorization_pending` / `slow_down`), or only OpenID4VCI tx_code? Only OpenID4VCI tx_code at token request, not HAIP-level polling; delayed issuance is expressed after token exchange via `/credential` and `/credential_deferred`.
6. Must issuers enforce WUA on pre-auth token requests, or is it wallet-only until issuers catch up? For now: do not hard-fail; log/report WUA non-compliance


## Implementation Plan

### Phase 0 — Spec tracking and optional opt-out

**Goal:** Track the pending CS-01 spec revision while enabling **dual-grant** CS-01 behavior (auth-code **and** pre-auth).

1. Both grant types in `webuild-cs01` are **enabled by default** — no opt-in flag required.
2. Auth-code flow remains fully supported; this plan adds pre-auth alongside it, not instead of it.
3. Add an optional env flag for legacy strict deployments only, e.g. `CS01_DISABLE_PRE_AUTHORIZED=true`, which blocks pre-auth but **still allows** auth-code issuance.
4. Document the opt-out flag in wallet-client deployment config (`docker-compose.yml`, remote env) for environments that must remain on CS-01 v1.0 semantics until the revised spec is published.

**Acceptance:** `WALLET_PROFILE=webuild-cs01` accepts auth-code offers and pre-auth offers; only explicit opt-out blocks pre-auth.

---

### Phase 1 — Dual-grant wallet routing

**Goal:** Allow **both** auth-code and pre-authorized routes in CS-01; block pre-auth only when explicitly opted out.

**Files:**

- `wallet-client/src/lib/profile.js`
- `wallet-client/src/server.js`

**Changes:**

1. Remove the CS-01 authorization-code-only assumption from `profile.js` module comments and `selectVciGrantRoute()`.
2. Replace `assertCs01AuthorizationCodeGrant()` hard-fail with grant selection logic shared by CS-01 and compatibility modes:
  - if offer has `authorization_code` → `authorization_code` route → `runAuthorizationCodeIssuance()` (unchanged)
  - else if offer has `urn:ietf:params:oauth:grant-type:pre-authorized_code` → `pre-authorized_code` route → `runPreAuthorizedIssuance()`
  - else → `Cs01ProfileError` with clear `unsupported_grant_type`
3. Narrow `assertPreAuthorizedAllowed()` to guard **only** when pre-auth is explicitly disabled (`CS01_DISABLE_PRE_AUTHORIZED=true`). Auth-code flow is never blocked by this guard.
4. Update `/session` and `/issue` error messages to distinguish:
  - pre-auth explicitly disabled via opt-out flag (auth-code offers still work)
  - offer has no supported grant (neither grant present)
5. **Release gate:** ship Phase 1 together with Phase 2 so routing is not enabled before CS-01 DPoP/WUA hardening is in place on the pre-auth path.

**Acceptance:**

- CS-01 + auth-code-only offer → `runAuthorizationCodeIssuance()` is invoked (PAR, PKCE, WUA, DPoP unchanged)
- CS-01 + pre-auth-only offer → `runPreAuthorizedIssuance()` is invoked
- CS-01 + dual-grant offer → route selected per grant selection rules; both paths must be test-covered
- CS-01 + `CS01_DISABLE_PRE_AUTHORIZED=true` + pre-auth-only offer → explicit opt-out error
- CS-01 + `CS01_DISABLE_PRE_AUTHORIZED=true` + auth-code offer → auth-code path still works

---

### Phase 2 — Apply CS-01 security requirements to pre-auth

**Goal:** Pre-auth in CS-01 mode meets the same HA bar as auth-code, minus PAR.

**Files:**

- `wallet-client/src/server.js` (`runPreAuthorizedIssuance`)
- `wallet-client/src/lib/dpopBinding.js`
- `wallet-client/src/lib/walletUnitAttestation.js`

**Changes:**

1. In CS-01 mode, treat DPoP generation failure as **fatal** for pre-auth token request (mirror auth-code).
2. In CS-01 mode, send WUA headers on pre-auth token requests; never send legacy body `client_assertion`.
3. Apply `assertDpopBoundToken()` after token response in pre-auth path.
4. Reuse `buildCredentialRequestProof()` / WUA key attestation header on `/credential` (already wired; add CS-01 assertions in tests).
5. Store refresh-token metadata if the AS returns a `refresh_token`; do not require it for success.

**Acceptance:**

- CS-01 pre-auth token request includes `DPoP` and attempts `OAuth-Client-Attestation` headers, with no body `client_assertion`
- Bearer-only fallback is unreachable in CS-01 pre-auth mode
- Pre-auth succeeds without a `refresh_token`, but preserves one when returned

---

### Phase 3 — Grant-route-aware credential identification

**Goal:** Credential identification follows OpenID4VCI v1.0 for the active grant route.

**Files:**

- `wallet-client/src/lib/scopeResolution.js`
- `wallet-client/src/server.js` (`runPreAuthorizedIssuance`, `runAuthorizationCodeIssuance`)
- `utils/routeUtils.js` (issuer offer construction)

**Changes:**

1. Keep `resolveCredentialScope()` focused on the auth-code Authorization Request:
   - offer `grants.authorization_code.scope` when present
   - issuer metadata `credential_configurations_supported[configurationId].scope`
   - CS-01: fail if no scope is available for an auth-code Authorization Request unless CS-01 explicitly permits `authorization_details`-only auth-code requests
2. Add a pre-auth credential selection helper, e.g. `resolvePreAuthorizedCredentialSelection({ profile, configurationId, issuerMeta, offerConfig })`, that:
   - validates the selected `configurationId` is present in top-level `credential_configuration_ids`
   - validates the selected `configurationId` exists in issuer metadata
   - returns token-request `authorization_details` of type `openid_credential` with `credential_configuration_id` when the offer contains multiple `credential_configuration_ids`, or when the wallet explicitly needs to narrow the token request
   - does **not** require or read `scope` from the pre-auth grant
3. Call the pre-auth selection helper from `runPreAuthorizedIssuance()` after grant selection.
4. Keep `authorization_details` optional for single-configuration pre-auth offers. For multi-configuration offers, send `authorization_details` using the selected `credential_configuration_id` and `locations` when `issuerMeta.credential_issuer` is available.
5. Do not add `scope` to the pre-auth grant in `createCredentialOfferConfig()` as a VCI requirement. If a future CS-01 revision defines a profile-specific extension, implement it as an optional extension and ignore it for VCI v1.0 compatibility.

**Acceptance:**

- CS-01 pre-auth offer with valid `credential_configuration_ids` and no grant `scope` → issuance proceeds
- CS-01 pre-auth single-configuration Token Request may omit `authorization_details`
- CS-01 pre-auth multi-configuration Token Request contains `authorization_details` with the selected `credential_configuration_id`
- CS-01 pre-auth offer whose selected `configurationId` is missing from `credential_configuration_ids` or issuer metadata → explicit credential selection error
- CS-01 auth-code path unchanged: Authorization Request scope from offer grant and/or metadata per existing rules

---

### Phase 4 — Issuer CS-01 pre-auth hardening

**Goal:** Issuer behavior matches what CS-01 wallets will send.

**Files:**

- `routes/issue/sharedIssuanceFlows.js` (token + credential handlers)
- `routes/issue/preAuthSDjwRoutes.js`
- `utils/routeUtils.js` (offer construction)
- `data/issuer-config.json` (scope on configurations used in ITB+)

**Changes:**

1. **WUA observability** on pre-auth token requests: validate WUA when possible, but do not hard-fail yet. Log and report missing/invalid WUA as CS-01 non-compliance.
2. **DPoP policy** — optional: reject pre-auth token requests without DPoP when `HAIP_PROFILE_REQUIRE_DPOP_FOR_TOKEN=true` (already used for auth-code).
3. **`tx_code` validation** — enforce when advertised in offer session metadata (gap noted in [vci-preauth-pid-x509-wallet-matrix.md](./vci-preauth-pid-x509-wallet-matrix.md)). This is OpenID4VCI token-request `tx_code`, not HAIP-level `authorization_pending` / `slow_down` polling. A pre-auth token exchange either succeeds or returns a normal token error; it does not become a polling loop.
4. Add a **CS-01 pre-auth offer route** (or extend `vciStandardRoutes.js`) that emits:
   - `urn:ietf:params:oauth:grant-type:pre-authorized_code`
   - top-level `credential_configuration_ids`
   - optional `tx_code` variant for ITB+ PIN scenarios
5. Fix **deferred pre-auth session lookup** — `getDeferredSessionTransactionId()` currently scans only `code-flow-sessions:*`; include `pre-auth-sessions:*` (known gap from deferred issuance review).
6. Preserve `refresh_token` when returned by the AS; issuer support is RECOMMENDED / SHOULD, not a conformance hard requirement.

**Acceptance:**

- End-to-end CS-01 pre-auth issuance against this issuer succeeds with WUA + DPoP
- Missing/invalid WUA is visible in logs/reports but does not fail issuance for now
- Deferred pre-auth issuance can poll `/credential_deferred` successfully

---

### Phase 5 — Deferred issuance alignment (shared)

**Goal:** Meet CS-01 §7.6 / §8.7 for both grant types.

**Files:**

- `routes/issue/sharedIssuanceFlows.js` (`handleDeferredCredentialIssuance`, `/credential_deferred`)
- `wallet-client/src/server.js` (poll loop)

**Changes:**

1. Return **202** + `transaction_id` + `interval` from `/credential_deferred` while pending.
2. Return **`invalid_transaction_id`** vs **`credential_request_denied`** for expired / denied transactions.
3. Wallet: honor issuer `interval` (seconds) from 202 responses; stop polling on terminal errors.
4. Require Bearer (and DPoP in CS-01) on `/credential_deferred`.

**Acceptance:** Deterministic test: `/credential` → 202 → poll → 200 credential.

---

### Phase 6 — Tests and ITB+ fixtures

**Goal:** Conformance suite covers pre-auth without regressing auth-code CS-01 tests.

**Files:**

- `wallet-client/test/fixtures/cs01Fixtures.js` — add VCI v1.0-shaped `cs01PreAuthorizedOffer`, `cs01PreAuthorizedOfferWithTxCode`, and multi-configuration pre-auth fixtures
- `wallet-client/test/profile.test.js` — update grant routing: CS-01 supports both grant types
- `wallet-client/test/cs01Conformance.test.js` — replace “rejects pre-auth” with:
  - auth-code path unchanged in CS-01
  - pre-auth allowed by default in CS-01
  - pre-auth blocked only when `CS01_DISABLE_PRE_AUTHORIZED=true` (auth-code still works)
  - pre-auth sends DPoP and attempts WUA
  - pre-auth credential selection uses `credential_configuration_ids`; token-request `authorization_details` is required only when narrowing multiple offered configurations
- New: `wallet-client/test/issuanceCs01PreAuth.test.js` (integration-style)
- Issuer: `tests/sharedIssuanceFlows.test.js` — CS-01 pre-auth token + credential scenarios

**Minimum success tests:**

- Issuer-initiated auth-code offer → PAR → token (WUA + DPoP) → credential → stored VC
- Wallet-initiated auth-code issuance → same HA path
- Issuer-initiated pre-auth offer → token (WUA + DPoP) → credential → stored VC
- Pre-auth offer with `tx_code` → PIN required → valid PIN succeeds
- Pre-auth without `refresh_token` → succeeds
- Pre-auth with returned `refresh_token` → stores/preserves refresh metadata
- Dual-grant offer → both routes independently testable
- Pre-auth deferred → poll with `transaction_id` → credential

**Minimum failure tests:**

- CS-01 pre-auth with missing WUA headers logs/reports non-compliance without hard failure
- CS-01 pre-auth with DPoP failure (wallet-side fatal)
- Pre-auth offer references a credential configuration missing from issuer metadata
- Multi-configuration pre-auth offer without an unambiguous selected configuration
- `CS01_DISABLE_PRE_AUTHORIZED=true` + pre-auth-only offer → explicit opt-out error

---

### Phase 7 — Documentation and deployment

**Goal:** Operators and ITB+ users know how to run both modes.

**Files to update:**

- [haip-etsi-wallet-attestation-options.md](./haip-etsi-wallet-attestation-options.md) — revise Phase 9 and Definition of Done
- [vci-preauth-pid-x509-wallet-matrix.md](./vci-preauth-pid-x509-wallet-matrix.md) — add CS-01 column
- `wallet-client/docker-compose.yml` — document optional `CS01_DISABLE_PRE_AUTHORIZED` opt-out
- README / wallet-client deployment notes — explain that `WALLET_PROFILE=webuild-cs01` supports **authorization_code and pre-authorized_code** by default

**Acceptance:** A remote deployment with `WALLET_PROFILE=webuild-cs01` runs CS-01 pre-auth interop without profile changes or opt-in flags.

## Recommended Delivery Order

1. Phase 0 — spec tracking and optional opt-out flag
2. Phase 1 + Phase 2 — wallet grant routing and CS-01 security on pre-auth path (single release gate)
3. Phase 3 — grant-route-aware credential identification
4. Phase 4 — issuer hardening + deferred session fix
5. Phase 5 — deferred endpoint behavior (can parallelize with 4)
6. Phase 6 — tests
7. Phase 7 — docs and deployment defaults

## Definition of Done

Relaxed CS-01 pre-auth can be declared done when:

```text
CS-01 mode supports both authorization_code and pre-authorized_code grant types
Pre-auth opt-out (CS01_DISABLE_PRE_AUTHORIZED) blocks only pre-auth; auth-code remains available
Auth-code CS-01 path (PAR, PKCE, WUA, DPoP, scope, JWT proof) remains unchanged and tested
CS-01 pre-auth token requests send Wallet Unit Attestation when available (header-based, no body client_assertion)
Issuers log/report WUA non-compliance on pre-auth token requests without hard-failing for now
CS-01 pre-auth access tokens are sender-constrained (DPoP); no bearer fallback
Credential requests on both paths use JWT proof + WUA key_attestation binding
Credential identification is route-aware: auth-code uses scope/authorization_details for the Authorization Request; pre-auth uses credential_configuration_ids and token-request authorization_details only when needed to narrow the request
tx_code is enforced when advertised
Refresh token support for pre-auth is implemented as SHOULD / best effort, not required for success
Deferred issuance uses transaction_id with 202/interval polling and terminal error codes
ITB+ can run auth-code and pre-auth scenarios with WALLET_PROFILE=webuild-cs01
```

## Migration Notes for Existing Deployments


| Deployment                                         | Action                                                                               |
| -------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Remote ITB+ wallet (`WALLET_PROFILE=webuild-cs01`) | After Phase 1–2: both auth-code and pre-auth work by default                         |
| Local dev (unset profile)                          | No change required; `compatibility` already allows both grant types                  |
| Issuers serving pre-auth offers (e.g. Spherity)    | No non-standard grant `scope` required; ensure top-level `credential_configuration_ids` and issuer metadata are consistent |
| Issuers serving auth-code offers                   | No change; existing CS-01 auth-code path remains                                     |
| Legacy strict CS-01 v1.0 testers                   | Set `CS01_DISABLE_PRE_AUTHORIZED=true` to block pre-auth only; auth-code still works |


## References

- WE BUILD CS-01 Credential Issuance v1.0 (28 November 2025) — §5, §6.2, §7.1, §7.2, §7.6, §8.2, §8.4
- OpenID4VCI v1.0 — §3.3, §3.4, §3.5, §4.1.1, §5.1.2, §6.1, §6.1.1, §8.3, §9
- [haip-etsi-wallet-attestation-options.md](./haip-etsi-wallet-attestation-options.md) — current CS-01 implementation plan (Phase 9 lock-out)
- [vci-preauth-pid-x509-wallet-matrix.md](./vci-preauth-pid-x509-wallet-matrix.md) — pre-auth compatibility matrix
- [vci-authorization-code-wallet-matrix.md](./vci-authorization-code-wallet-matrix.md) — auth-code matrix (unchanged baseline)

