# RFC001 — How to Initiate HAIP/ETSI-Aligned VCI Test Cases

Reference: APTITUDE **RFC-01 Credential Issuance Profile** v0.1 (Draft), §10.2 *Deployed Test Case Matrix* (`VCI-001 … VCI-010`).

This note explains **how to trigger (initiate the request for)** the **HAIP / ETSI-aligned subset** of the RFC001 VCI test cases against this issuer.

It intentionally narrows the broader RFC001 matrix to the cases that align with HAIP / ETSI issuer-trust expectations, namely **X.509-based issuer signing** plus the ETSI/HAIP issuance controls around signed metadata, WIA/WUA, PAR, DPoP, and credential response encryption.

The non-ETSI issuer-signature variants from RFC001 (`jwk`, `kid-jwk`, `did:web`) are intentionally **out of scope** for this note.

It covers:

- which HTTP endpoint the tester (or a wallet) hits to generate a credential offer,
- which query parameters select **grant type** (authorization-code vs pre-authorized), **credential format** (SD-JWT vs mdoc), the **X.509 issuer signature profile**, and **tx-code** behavior,
- what the subsequent wallet-driven protocol steps look like (PAR → token → credential, or token → credential),
- how the `A128GCM` / `A256GCM` variants (VCI-009 / VCI-010) are driven by the wallet's `credential_response_encryption` request parameter within the X.509-based SD-JWT path.

The single most useful entrypoint is the standardized **`GET /vci/offer`** (see [`routes/issue/vciStandardRoutes.js`](../routes/issue/vciStandardRoutes.js)). Every in-scope case below can be triggered with one `curl` call to that endpoint.

---

## 1. Environment

- Issuer base URL: `SERVER_URL` (default `http://localhost:3000`). The examples below use `BASE` as a placeholder:
  ```bash
  export BASE="${SERVER_URL:-http://localhost:3000}"
  ```
- Optional: when a wallet talks through a reverse proxy, set **`TRUST_FORWARDED_ISSUER_URL=true`** so DPoP `htu` and proof `aud` line up with the public URL (see `utils/routeUtils.js` → `getPublicIssuerBaseUrl`).
- `ISSUER_SIGNATURE_TYPE` environment variable: for **HAIP** flows, set this to `x509`. In this HAIP/ETSI-only note, `x509` is the only issuer-signature profile considered in scope. See [`utils/credGenerationUtils.js`](../utils/credGenerationUtils.js) (`effectiveSignatureType`).
- The issuer metadata already advertises both `A128GCM` and `A256GCM` under `credential_response_encryption.enc_values_supported` (`data/issuer-config.json`), so VCI-009 / VCI-010 are selected **by the wallet** when it builds the credential request.

---

## 2. Unified entrypoint: `GET /vci/offer`

`GET /vci/offer` is the normalized way to generate an offer for the HAIP/ETSI-aligned cases covered here: **VCI-005 / VCI-006 / VCI-007 / VCI-008 / VCI-009 / VCI-010**. It creates the issuance session, returns a deep link + QR, and pre-configures the session so that the downstream `/par`, `/token_endpoint`, and `/credential` handlers behave correctly.

| Query parameter | Values | Effect |
| --- | --- | --- |
| `flow` | `authorization_code` \| `pre_authorized_code` | Selects grant type. `authorization_code` sessions go through PAR + `/authorize` + `/token_endpoint`; `pre_authorized_code` sessions go straight to `/token_endpoint`. |
| `tx_code_required` | `true` \| `false` (default `false`) | Only meaningful for `pre_authorized_code`. When `true`, the offer carries `tx_code` metadata **and** the token endpoint requires a non-empty `tx_code` on redemption (RFC001 §6.2.6, backlog item **P0-6**). |
| `credential_type` | e.g. `urn:eu.europa.ec.eudi:pid:1:mso_mdoc`, `ETSIRfc001PidVcSdJwt`, `ETSIRfc001PidX509Attr` | The `credential_configuration_id` included in the offer. |
| `credential_format` | `sd-jwt` \| `mso_mdoc` (informational; actual format is driven by the chosen `credential_type` in issuer metadata) | Documentary; the issuer picks the format from the configuration referenced by `credential_type`. |
| `signature_type` | `x509` | Issuer-side signing profile used to sign the issued credential in this HAIP/ETSI-only profile. In authorization-code flows this results in `client_id_scheme=x509_san_dns`. |
| `session_id` | any string (default: auto) | Overrides the session / offer id, handy for reproducible test runs. |
| `offer_scheme` | `haip` \| `eu_eaa` | URL scheme used for the `deepLink` (`haip://`, `eu-eaa-offer://`). For ETSI-aligned wallet invocation, prefer `eu_eaa`. |

Response shape:

```json
{ "qr": "data:image/png;base64,…", "deepLink": "eu-eaa-offer://…", "sessionId": "…" }
```

The wallet scans / follows the `deepLink`, fetches the referenced `credential_offer_uri`, and drives the protocol from there. If you explicitly request `offer_scheme=haip`, the scheme becomes `haip://…` instead.

---

## 3. Generic flow once the offer is triggered

### 3.1 Authorization-code flow (covers **VCI-005 / VCI-009 / VCI-010**)

1. Wallet resolves `credential_offer_uri` → receives `{ credential_issuer, credential_configuration_ids, grants: { authorization_code: { issuer_state } } }`.
2. Wallet fetches issuer metadata (`/.well-known/openid-configuration`, `/.well-known/openid-credential-issuer`) to find `pushed_authorization_request_endpoint`, `authorization_endpoint`, `token_endpoint`, `credential_endpoint`, and the credential config.
3. Wallet **MUST** use PAR: `POST /par` (RFC001 §7.3; backlog **P0-1**) with `client_id`, `response_type=code`, `redirect_uri`, PKCE `S256` (backlog **P1-6**), `state`, `authorization_details` / `scope`, `issuer_state`, and `OAuth-Client-Attestation` (WIA) + `OAuth-Client-Attestation-PoP` headers when ETSI-aligned (backlog **P0-7**).
4. Wallet directs user to `GET /authorize?request_uri=...&client_id=...` → server issues an authorization `code`.
5. Wallet calls `POST /token_endpoint` with `grant_type=authorization_code`, `code`, `code_verifier`, `redirect_uri`, **DPoP** header (RFC001 §7.1; backlog **P1-9** → DPoP is mandatory & unconditional), and WIA + PoP. Response carries sender-constrained `access_token` (`cnf.jkt`), `c_nonce`, `c_nonce_expires_in`, and `authorization_details` with per-entry `credential_identifiers` (backlog **P1-10**, **P1-13**).
6. Wallet calls `POST /credential` with `Authorization: DPoP <token>`, a fresh `DPoP` proof (sender-constraint, backlog **P0-4**), the `credential_configuration_id` / `credential_identifier`, and the `proofs` structure (RFC001 §7.5). Either:
   - **`proofs.jwt`** — exactly one JWT (`typ = openid4vci-proof+jwt`, `aud` = issuer base URL, `nonce = c_nonce`, `iss`, key in header as `jwk` / `kid`, and for the device-bound/PID path also the `key_attestation` header carrying the WUA — backlog **P1-1**, **P1-2**, **P1-4**, **P1-5**); or
   - **`proofs.attestation`** — exactly one WUA.

### 3.2 Pre-authorized code flow (covers **VCI-006 / 007 / 008**)

1. Wallet resolves `credential_offer_uri` → `{ …, grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "…", "tx_code"?: { length, input_mode, description } } } }`.
2. (Only if `tx_code` is advertised) Wallet prompts the holder for a PIN / OTP.
3. Wallet calls `POST /token_endpoint` with `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`, `pre-authorized_code`, optional `tx_code`, and **DPoP** header. Missing / empty `tx_code` when required → `400 invalid_grant` (backlog **P0-6**).
4. Wallet proceeds to `/credential` as in 3.1 step 6.

### 3.3 Deferred issuance continuation

If the issuer returns `{ transaction_id, interval }` instead of a credential, the wallet polls `POST /credential_deferred` with the same `Authorization` + a fresh DPoP and the `transaction_id` (backlog **P0-5**, **P1-7**).

---

## 4. Per-test-case triggers

All examples assume the server is running and reachable at `$BASE`. Replace `BASE=http://localhost:3000` with your deployed URL. Each test case is triggered by a **single** call from the tester; the rest of the flow is the wallet's work.

### VCI-005 — Authorization-code, mdoc, X.509

mdoc (`mso_mdoc`) PID issuance with issuer certificate in `x5c`.

```bash
curl -G "$BASE/vci/offer" \
  --data-urlencode "flow=authorization_code" \
  --data-urlencode "credential_type=urn:eu.europa.ec.eudi:pid:1:mso_mdoc" \
  --data-urlencode "credential_format=mso_mdoc" \
  --data-urlencode "signature_type=x509" \
  --data-urlencode "offer_scheme=eu_eaa"
```

- Covers: `VCI-CHECK-01, 02, 03, 03A, 05, 06, 06A, 07, 08`.
- `signature_type=x509` → `client_id_scheme=x509_san_dns`. mdoc signing uses the X.509 cert chain at `./x509EC/client_certificate.crt`.
- `VCI-CHECK-08` is exercised by the wallet sending a **JWT proof** for an mdoc configuration — the issuer must reject with `invalid_proof` when the proof type does not match the mdoc path.

### VCI-006 — Pre-authorized, SD-JWT, X.509, **no** tx-code

```bash
curl -G "$BASE/vci/offer" \
  --data-urlencode "flow=pre_authorized_code" \
  --data-urlencode "tx_code_required=false" \
  --data-urlencode "credential_type=ETSIRfc001PidVcSdJwt" \
  --data-urlencode "credential_format=sd-jwt" \
  --data-urlencode "signature_type=x509" \
  --data-urlencode "offer_scheme=eu_eaa"
```

- Covers: `VCI-CHECK-01, 04, 05, 06, 06A, 07`.
- Token request: `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code` + `pre-authorized_code` from the offer, **no** `tx_code`.
- SD-JWT JOSE header carries the issuer `x5c` certificate chain (base64 DER of `x509EC/client_certificate.crt`).

### VCI-007 — Pre-authorized with tx-code metadata, SD-JWT, X.509

```bash
curl -G "$BASE/vci/offer" \
  --data-urlencode "flow=pre_authorized_code" \
  --data-urlencode "tx_code_required=true" \
  --data-urlencode "credential_type=ETSIRfc001PidVcSdJwt" \
  --data-urlencode "credential_format=sd-jwt" \
  --data-urlencode "signature_type=x509" \
  --data-urlencode "offer_scheme=eu_eaa"
```

- Covers: `VCI-CHECK-01, 04, 05, 06, 06A, 07, 09`.
- Offer carries `tx_code: { length: 4, input_mode: "numeric", description: "…" }`.
- Token endpoint requires a **non-empty** `tx_code` (any value is accepted — value-level PIN/OTP verification is out of scope, see backlog **P0-6**). Missing / whitespace-only → `400 invalid_grant`.

### VCI-008 — Pre-authorized, mdoc, X.509, no tx-code

```bash
curl -G "$BASE/vci/offer" \
  --data-urlencode "flow=pre_authorized_code" \
  --data-urlencode "tx_code_required=false" \
  --data-urlencode "credential_type=urn:eu.europa.ec.eudi:pid:1:mso_mdoc" \
  --data-urlencode "credential_format=mso_mdoc" \
  --data-urlencode "signature_type=x509" \
  --data-urlencode "offer_scheme=eu_eaa"
```

- Covers: `VCI-CHECK-01, 04, 05, 06, 06A, 07, 08`.
- mdoc issuance with `x5c` signer. `VCI-CHECK-08` as in VCI-005: issuer must reject a JWT proof sent for the mdoc configuration.

### VCI-009 — Authorization-code, SD-JWT, `enc=A128GCM`

The **trigger** in this HAIP/ETSI-only profile is the X.509 SD-JWT authorization-code path; the wallet selects the algorithm in the credential request:

```bash
# Offer (HAIP/ETSI-aligned X.509 SD-JWT path)
curl -G "$BASE/vci/offer" \
  --data-urlencode "flow=authorization_code" \
  --data-urlencode "credential_type=ETSIRfc001PidVcSdJwt" \
  --data-urlencode "credential_format=sd-jwt" \
  --data-urlencode "signature_type=x509" \
  --data-urlencode "offer_scheme=eu_eaa"
```

Then at the Credential Endpoint, the wallet sends:

```json
{
  "credential_configuration_id": "ETSIRfc001PidVcSdJwt",
  "proofs": { "jwt": ["<openid4vci-proof+jwt>"] },
  "credential_response_encryption": {
    "jwk": { "kty": "EC", "crv": "P-256", "alg": "ECDH-ES", "x": "...", "y": "..." },
    "enc": "A128GCM"
  }
}
```

- Covers: `VCI-CHECK-01, 02, 03, 03A, 05, 06, 06A, 07, 10`.
- The issuer advertises `enc_values_supported = ["A128GCM", "A256GCM"]` (`data/issuer-config.json`) and returns a compact JWE whose content-encryption header is `A128GCM` (`utils/credentialResponseEncryption.js`).

### VCI-010 — Authorization-code, SD-JWT, `enc=A256GCM`

Same trigger as VCI-009 but the wallet sets `credential_response_encryption.enc = "A256GCM"`:

```json
{
  "credential_configuration_id": "ETSIRfc001PidVcSdJwt",
  "proofs": { "jwt": ["<openid4vci-proof+jwt>"] },
  "credential_response_encryption": {
    "jwk": { "kty": "EC", "crv": "P-256", "alg": "ECDH-ES", "x": "...", "y": "..." },
    "enc": "A256GCM"
  }
}
```

- Covers: `VCI-CHECK-01, 02, 03, 03A, 05, 06, 06A, 07, 11`.

---

## 5. Legacy / direct entrypoints (for reference)

You don't need these for the HAIP/ETSI-aligned subset covered here — `GET /vci/offer` covers every in-scope row — but they may be useful for isolated debugging.

| Purpose | Endpoint | Notes |
| --- | --- | --- |
| Auth-code SD-JWT (non-dynamic) | `GET /offer-code-sd-jwt` | Query: `credentialType`, `signatureType`, `client_id_scheme`, `offer_scheme`. |
| Auth-code SD-JWT (dynamic) | `GET /offer-code-sd-jwt-dynamic` | Session marked `isDynamic`. |
| Auth-code SD-JWT (deferred) | `GET /offer-code-defered` | Session marked `isDeferred`; `/credential` returns `transaction_id`. |
| Pre-auth w/ tx-code | `GET /offer-tx-code` | Query: `credentialType`, `signatureType`, `offer_scheme`. |
| Pre-auth w/o tx-code | `GET /offer-no-code` | Query: `credentialType`, `signatureType`, `offer_scheme`. |
| Multi-credential offer | `GET /offer-no-code-batch` | Useful for exercising multiple `credential_configuration_ids` in one offer (pre-authorized and authorization-code variants, backlog **P3-4**). |
| HAIP pre-auth w/ tx-code | `GET /haip-offer-tx-code` | Forces `haip://` scheme, sets `isHaip=true`; `ISSUER_SIGNATURE_TYPE=x509` selects the HAIP X.509 signer. |
| PID-specific pre-auth | `GET /issue-pid-pre-auth` | Hard-codes `urn:eu.europa.ec.eudi:pid:1` + `requireTxCode=true`. |
| PID-specific auth-code | `GET /issue-pid-code` | Hard-codes `urn:eu.europa.ec.eudi:pid:1`. |

All of the above return a `{ qr, deepLink, sessionId }` envelope.

---

## 6. Cross-reference: test case ↔ issuer primitives

| Test case | `flow` | `credential_type` | `credential_format` | `signature_type` | Key runtime primitives |
| --- | --- | --- | --- | --- | --- |
| VCI-005 | `authorization_code` | `urn:eu.europa.ec.eudi:pid:1:mso_mdoc` | `mso_mdoc` | `x509` | `client_id_scheme=x509_san_dns`; mdoc signed with issuer cert; wrong-proof-type path covers `VCI-CHECK-08` |
| VCI-006 | `pre_authorized_code` | `ETSIRfc001PidVcSdJwt` | `sd-jwt` | `x509` | Token redemption without `tx_code`; SD-JWT signed with `x5c` |
| VCI-007 | `pre_authorized_code` (`tx_code_required=true`) | `ETSIRfc001PidVcSdJwt` | `sd-jwt` | `x509` | Offer advertises `tx_code`; token requires non-empty `tx_code` (**P0-6**) |
| VCI-008 | `pre_authorized_code` | `urn:eu.europa.ec.eudi:pid:1:mso_mdoc` | `mso_mdoc` | `x509` | mdoc pre-auth; wrong-proof-type rejection exercises `VCI-CHECK-08` |
| VCI-009 | `authorization_code` | `ETSIRfc001PidVcSdJwt` | `sd-jwt` | `x509` | Wallet adds `credential_response_encryption.enc=A128GCM` on `/credential` |
| VCI-010 | `authorization_code` | `ETSIRfc001PidVcSdJwt` | `sd-jwt` | `x509` | Wallet adds `credential_response_encryption.enc=A256GCM` on `/credential` |

---

## 7. Quick sanity checks

After triggering an offer, you can quickly confirm the session was created and the flow is wired correctly:

```bash
# 1. Trigger
OFFER=$(curl -s -G "$BASE/vci/offer" \
  --data-urlencode "flow=pre_authorized_code" \
  --data-urlencode "tx_code_required=true" \
  --data-urlencode "credential_type=ETSIRfc001PidVcSdJwt" \
  --data-urlencode "signature_type=x509" \
  --data-urlencode "offer_scheme=eu_eaa")
echo "$OFFER" | jq .

# 2. Fetch the offer document the wallet will retrieve
SESSION=$(echo "$OFFER" | jq -r .sessionId)
curl -s "$BASE/credential-offer-tx-code/$SESSION" | jq .

# 3. Discovery (should advertise DPoP, S256, A128GCM+A256GCM, ETSI formats, issuer_info)
curl -s "$BASE/.well-known/openid-credential-issuer" | jq '.credential_configurations_supported.ETSIRfc001PidVcSdJwt, .credential_response_encryption'
curl -s "$BASE/.well-known/oauth-authorization-server" | jq '.grant_types_supported, .code_challenge_methods_supported, .dpop_signing_alg_values_supported'

# 4. Poll session status (either pre-auth or code-flow cache is consulted)
curl -s "$BASE/issueStatus?sessionId=$SESSION" | jq .
```

---

## 8. Related documents

- `reports/rfc001-alignment-backlog.md` — what each P0/P1/P2/P3 backlog item enforces at the endpoints listed above.
- `reports/rfc001-issuer-compliance-review.md` — deeper RFC001 § → code mapping.
- `docs/vci-authorization-code-wallet-matrix.md` — wallet-side matrix for the authorization-code flow.
- `docs/vci-preauth-pid-x509-wallet-matrix.md` — wallet-side matrix for the pre-auth X.509 PID flow (baseline for VCI-006 / VCI-007).
- `docs/mdoc-credential-generation.md` — mdoc issuance internals (VCI-005 / VCI-008).
