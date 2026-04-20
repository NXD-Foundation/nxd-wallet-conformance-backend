# RFC002 — How to Initiate APTITUDE / §11.2 VP Test Cases

Reference: APTITUDE **RFC-02 Verifiable Presentation Profile** (Draft), §11.2 *Deployed Test Case Matrix* (`VP-001 … VP-007`, plus **`VP-006A`** in the RFC table for `eu-eaap://`).

This note explains **how to trigger (initiate)** the matrix scenarios against **this** verifier. It mirrors the style of [`rfc001-vci-test-case-initiation.md`](rfc001-vci-test-case-initiation.md) for the issuer side.

The machine-readable matrix with fully expanded URLs lives in **[`aptitude-vp.yml`](../aptitude-vp.yml)** at the repository root.

**Normative scope (RFC002):** For the ETSI-aligned SD-JWT track, the RFC requires `client_id` with the **`x509_hash`** Client Identifier Prefix (RFC002 §5 / §8.2.2). The §11.2 matrix rows **VP-001 … VP-006** are all **x509_hash** PID scenarios (or **VP-007** mdoc); **`x509_san_dns`**, **`did:web`**, and **`did:jwk`** are **not** part of RFC002 §11.2. They remain available on this codebase for broader interop only — see **§9** below.

---

## 1. Environment

- Verifier base URL: `SERVER_URL` (default `http://localhost:3000`). Examples use `BASE`:

  ```bash
  export BASE="${SERVER_URL:-http://localhost:3000}"
  ```

- Optional: when a wallet talks through a trusted reverse proxy, set **`TRUST_FORWARDED_ISSUER_URL=true`** so security-sensitive URLs line up with the public origin (see `utils/routeUtils.js` → `getPublicIssuerBaseUrl`).

- Ensure verifier encryption/signing config is loaded (`data/verifier-config.json` with JWKs for JAR and, for `direct_post.jwt`, response encryption).

---

## 2. Unified entrypoint: `GET /vp/request`

All §11.2 rows are started with a **single GET** to **`/vp/request`**. Implementation: [`routes/verify/vpStandardRoutes.js`](../routes/verify/vpStandardRoutes.js).

The response is JSON with (at least) QR and deep-link material for the wallet, e.g.:

```json
{ "qr": "data:image/png;base64,…", "deepLink": "…", "sessionId": "…" }
```

| Query parameter | Typical values | Effect |
| --- | --- | --- |
| `session_id` | string (optional) | Stable session id for reproducible runs; default is a fresh UUID. |
| `profile` | `dcql` \| `tx` \| … | For **PID** rows in this matrix use **`dcql`** or **`tx`** so the JAR is built with **`dcql_query`**. (`profile=etsi` with PID still loads `presentation_definition` (PEX); the JAR builder rejects PEX — do not use `etsi` for these initiation URLs until that path is fixed.) |
| `credential_profile` | `pid` \| `mdl` | PID (SD-JWT) vs mDL (`mso_mdoc`). |
| `client_id_scheme` | **`x509_hash`** (§11.2) | **RFC002 §11.2 rows use `x509_hash` only** for the SD-JWT track. Other values exist in code for non-RFC interop (§9). |
| `request_uri_method` | `post` \| `get` | How the wallet retrieves the signed request object from `request_uri`. **VP-006** uses **`get`** to exercise the §11.2 “request_uri retrieval” row (VP-CHECK-12); other PID rows use **`post`**. |
| `response_mode` | `direct_post.jwt` | RFC002 ETSI-aligned encrypted responses use **`direct_post.jwt`** for the matrix. |
| `scheme` | `openid4vp` \| `eu-eaap` | PID wallet invocation: **`openid4vp://`** vs **`eu-eaap://`**. **VP-006A** (`eu-eaap`, VP-CHECK-17) is given as a second URL under **`VP-006`** in `aptitude-vp.yml`. |
| `invocation_scheme` | `mdoc-openid4vp` \| `openid4vp` | **mDL (VP-007):** the server reads **`invocation_scheme`** (not `scheme`). |
| `tx_data` | `true` \| `false` | With `profile=tx`, `true` embeds transaction data (**VP-004**). **`false`** is used for **VP-003** (tx track without a transaction payload). |
| `jar_alg` | `ES256` \| `RS256` | **VP-002** uses **`RS256`** as the second §11.2 “request variant” on this deployment. |

Shortcut: **`GET /vp/etsi/same-device`** redirects to `/vp/request` with `profile=etsi` merged into the query; it is **not** used for the §11.2 YAML rows until PID+`etsi` stops loading PEX.

---

## 3. After initiation: wallet steps (summary)

1. Holder opens the **`deepLink`** (or scans the QR).
2. Wallet resolves **`request_uri`** (GET or POST per `request_uri_method`) and obtains the signed request object (JAR).
3. Wallet builds the presentation (SD-JWT VC, mdoc `DeviceResponse`, etc.) and POSTs it to the verifier **`response_uri`** using the negotiated **`response_mode`**.
4. Tester may poll verifier session / status endpoints documented elsewhere (e.g. `verificationStatus` patterns in [`testCaseRequests.yml`](../testCaseRequests.yml)).

---

## 4. Per-test-case triggers (RFC002 §11.2)

Each subsection is a **one-shot** `curl` against `$BASE`. Canonical URLs are in **`aptitude-vp.yml`**.

### VP-001 — Baseline ETSI PID DCQL (`family_name`), `x509_hash`, POST `request_uri`, `direct_post.jwt`

```bash
curl -sG "$BASE/vp/request" \
  --data-urlencode "session_id=apt-vp-001" \
  --data-urlencode "profile=dcql" \
  --data-urlencode "credential_profile=pid" \
  --data-urlencode "client_id_scheme=x509_hash" \
  --data-urlencode "request_uri_method=post" \
  --data-urlencode "response_mode=direct_post.jwt" \
  --data-urlencode "scheme=openid4vp" | jq .
```

### VP-002 — Second ETSI-aligned variant (RS256 JAR)

RFC002 defines a second selective-claim variant without fixing HTTP mechanics. This deployment uses **`jar_alg=RS256`** vs ES256 for VP-001.

```bash
curl -sG "$BASE/vp/request" \
  --data-urlencode "session_id=apt-vp-002" \
  --data-urlencode "profile=dcql" \
  --data-urlencode "credential_profile=pid" \
  --data-urlencode "client_id_scheme=x509_hash" \
  --data-urlencode "request_uri_method=post" \
  --data-urlencode "response_mode=direct_post.jwt" \
  --data-urlencode "scheme=openid4vp" \
  --data-urlencode "jar_alg=RS256" | jq .
```

### VP-003 — Third ETSI-aligned variant (`profile=tx`, no `transaction_data`)

```bash
curl -sG "$BASE/vp/request" \
  --data-urlencode "session_id=apt-vp-003" \
  --data-urlencode "profile=tx" \
  --data-urlencode "credential_profile=pid" \
  --data-urlencode "client_id_scheme=x509_hash" \
  --data-urlencode "request_uri_method=post" \
  --data-urlencode "response_mode=direct_post.jwt" \
  --data-urlencode "scheme=openid4vp" \
  --data-urlencode "tx_data=false" | jq .
```

### VP-004 — Transaction data (`profile=tx`, `tx_data=true`)

```bash
curl -sG "$BASE/vp/request" \
  --data-urlencode "session_id=apt-vp-004" \
  --data-urlencode "profile=tx" \
  --data-urlencode "credential_profile=pid" \
  --data-urlencode "client_id_scheme=x509_hash" \
  --data-urlencode "request_uri_method=post" \
  --data-urlencode "response_mode=direct_post.jwt" \
  --data-urlencode "tx_data=true" \
  --data-urlencode "scheme=openid4vp" | jq .
```

### VP-005 — ETSI PID presentation (same initiation URL as VP-001 here)

RFC002 **VP-005** is a separate matrix row with the same VP-CHECK set as VP-001; this verifier’s default DCQL matches VP-001, so **`aptitude-vp.yml`** repeats the VP-001 URL with a distinct `session_id`.

```bash
curl -sG "$BASE/vp/request" \
  --data-urlencode "session_id=apt-vp-005" \
  --data-urlencode "profile=dcql" \
  --data-urlencode "credential_profile=pid" \
  --data-urlencode "client_id_scheme=x509_hash" \
  --data-urlencode "request_uri_method=post" \
  --data-urlencode "response_mode=direct_post.jwt" \
  --data-urlencode "scheme=openid4vp" | jq .
```

### VP-006 — `request_uri` retrieval variant (GET) + **VP-006A** `eu-eaap`

**VP-006** (VP-CHECK-12): GET `request_uri` retrieval.

```bash
curl -sG "$BASE/vp/request" \
  --data-urlencode "session_id=apt-vp-006" \
  --data-urlencode "profile=dcql" \
  --data-urlencode "credential_profile=pid" \
  --data-urlencode "client_id_scheme=x509_hash" \
  --data-urlencode "request_uri_method=get" \
  --data-urlencode "response_mode=direct_post.jwt" \
  --data-urlencode "scheme=openid4vp" | jq .
```

**VP-006A** (VP-CHECK-17): same-device **`eu-eaap://`** invocation (RFC002 §11.2 separate row; nested under VP-006 in `aptitude-vp.yml`).

```bash
curl -sG "$BASE/vp/request" \
  --data-urlencode "session_id=apt-vp-006a" \
  --data-urlencode "profile=dcql" \
  --data-urlencode "credential_profile=pid" \
  --data-urlencode "client_id_scheme=x509_hash" \
  --data-urlencode "request_uri_method=post" \
  --data-urlencode "response_mode=direct_post.jwt" \
  --data-urlencode "scheme=eu-eaap" | jq .
```

### VP-007 — ISO remote mdoc (`mdoc-openid4vp`)

```bash
curl -sG "$BASE/vp/request" \
  --data-urlencode "session_id=apt-vp-007" \
  --data-urlencode "profile=dcql" \
  --data-urlencode "credential_profile=mdl" \
  --data-urlencode "client_id_scheme=x509_hash" \
  --data-urlencode "request_uri_method=post" \
  --data-urlencode "response_mode=direct_post.jwt" \
  --data-urlencode "invocation_scheme=mdoc-openid4vp" | jq .
```

---

## 5. Cross-reference: §11.2 row ↔ query parameters

| Case | `profile` | `credential_profile` | `client_id_scheme` | `request_uri_method` | `response_mode` | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| VP-001 | `dcql` | `pid` | `x509_hash` | `post` | `direct_post.jwt` | `scheme=openid4vp` |
| VP-002 | `dcql` | `pid` | `x509_hash` | `post` | `direct_post.jwt` | `jar_alg=RS256` |
| VP-003 | `tx` | `pid` | `x509_hash` | `post` | `direct_post.jwt` | `tx_data=false` |
| VP-004 | `tx` | `pid` | `x509_hash` | `post` | `direct_post.jwt` | `tx_data=true` |
| VP-005 | `dcql` | `pid` | `x509_hash` | `post` | `direct_post.jwt` | Same URL shape as VP-001 here |
| VP-006 | `dcql` | `pid` | `x509_hash` | `get` | `direct_post.jwt` | `scheme=openid4vp` |
| VP-006A | `dcql` | `pid` | `x509_hash` | `post` | `direct_post.jwt` | `scheme=eu-eaap` |
| VP-007 | `dcql` | `mdl` | `x509_hash` | `post` | `direct_post.jwt` | `invocation_scheme=mdoc-openid4vp` |

---

## 6. Legacy / alternate entrypoints (optional)

For debugging you can still use older per-scheme routes (e.g. `GET /x509/generateVPRequest`, `GET /x509/generateVPRequestDCQL`). The **§11.2 matrix** is normalized on **`GET /vp/request`** for APTITUDE parity with **`aptitude-vci.yml`**.

---

## 7. Quick sanity checks

```bash
# Verifier metadata (RFC002 §8.4)
curl -s "$BASE/.well-known/openid-verifier-metadata" | jq .

# VP-001
curl -sG "$BASE/vp/request" \
  --data-urlencode "session_id=apt-vp-001" \
  --data-urlencode "profile=dcql" \
  --data-urlencode "credential_profile=pid" \
  --data-urlencode "client_id_scheme=x509_hash" \
  --data-urlencode "request_uri_method=post" \
  --data-urlencode "response_mode=direct_post.jwt" \
  --data-urlencode "scheme=openid4vp" | jq .
```

---

## 8. Related documents

- [`aptitude-vp.yml`](../aptitude-vp.yml) — deployed-test matrix (YAML).
- [`reports/rfc002-verifier-compliance-review.md`](../reports/rfc002-verifier-compliance-review.md) — §11.2 `VP-CHECK-*` mapping and known gaps.
- [`testCaseRequests.yml`](../testCaseRequests.yml) — broader VP-STD-* and x509 entrypoints (not limited to RFC002 §11.2).
- [`routes/verify/vpStandardRoutes.js`](../routes/verify/vpStandardRoutes.js) — `/vp/request` implementation.

---

## 9. Out of scope for RFC002 §11.2 (interop only)

The following **are implemented** on this verifier but are **not** rows in RFC002 §11.2:

- **`client_id_scheme=x509_san_dns`** — legacy X.509 DNS SAN client id (contrast RFC002 ETSI **`x509_hash`** SHALL).
- **`client_id_scheme=did:web`** / **`did:jwk`** — decentralized identifier schemes; not in the §11.2 deployed matrix.
- **`response_mode=direct_post`** (plaintext) — useful for interop; RFC002 ETSI track emphasizes encrypted responses for the rows above.

For examples, see [`testCaseRequests.yml`](../testCaseRequests.yml) (`VP-STD-*`).
