# VP requests & standardized VCI offers — parameters and localhost URIs

Reference for **`GET /vp/request`** (first), **`GET /vci/offer`**, and related legacy offer routes. Derived from:

- `routes/issue/vciStandardRoutes.js`
- `routes/verify/vpStandardRoutes.js`
- `routes/issue/codeFlowSdJwtRoutes.js`
- `routes/issue/preAuthSDjwRoutes.js`
- `utils/routeUtils.js`

**Base URL in examples:** `http://localhost:3000` — swap for your deployed origin (and path prefix) when needed.

---

## 1. VP requests — ready-to-use URIs (`localhost:3000`)

Open in a browser or **GET** in Postman/curl. Responses are JSON (`qr`, `deepLink`, `sessionId`, …).

### Common presets

**PID · DCQL · `x509_hash` · POST `request_uri` · `direct_post.jwt` · `openid4vp`**

```
http://localhost:3000/vp/request?profile=dcql&credential_profile=pid&client_id_scheme=x509_hash&request_uri_method=post&response_mode=direct_post.jwt&scheme=openid4vp
```

**mDL · DCQL · `mdoc-openid4vp`**

```
http://localhost:3000/vp/request?profile=dcql&credential_profile=mdl&client_id_scheme=x509_hash&request_uri_method=post&response_mode=direct_post.jwt&invocation_scheme=mdoc-openid4vp
```

**Accommodation Voucher + PID · combined DCQL**

Requests `reservationReference` from the Accommodation Voucher
(`booking_reference_credential`) and `family_name` from PID for guest-name matching.

```
http://localhost:3000/vp/request?profile=dcql&credential_profile=booking_pid&client_id_scheme=x509_hash&request_uri_method=post&response_mode=direct_post.jwt&scheme=openid4vp
```

**PID · transaction-data profile (`tx`)** **IGNORE FOR NOW**

```
http://localhost:3000/vp/request?profile=tx&credential_profile=pid&client_id_scheme=x509_hash&request_uri_method=post&response_mode=direct_post.jwt&scheme=openid4vp&tx_data=true
```

**PID · `request_uri` via GET (no `request_uri_method=post` on wallet link)**

```
http://localhost:3000/vp/request?profile=dcql&credential_profile=pid&client_id_scheme=x509_hash&request_uri_method=get&response_mode=direct_post.jwt&scheme=openid4vp
```

**ETSI / RFC002-style defaults (`profile=etsi` → redirect; defaults include `eu-eaap` + `direct_post.jwt` when scheme omitted)**

**IGNORE USES PEX instad of DCQL**

```
http://localhost:3000/vp/request?profile=etsi&credential_profile=pid&client_id_scheme=x509_hash&request_uri_method=post
```

**Shortcut: same as calling `/vp/request` with `profile=etsi` (302 redirect)**
**IGNORE USES PEX instad of DCQL**

```
http://localhost:3000/vp/etsi/same-device?credential_profile=pid&client_id_scheme=x509_hash&request_uri_method=post
```

**Stable VP session id**

```
http://localhost:3000/vp/request?session_id=my-vp-session-001&profile=dcql&credential_profile=pid&client_id_scheme=x509_hash&request_uri_method=post&response_mode=direct_post.jwt&scheme=openid4vp
```

**`did:web` verifier client id scheme** (`:` encoded as `%3A`)
**IGNORE USES did:web out of SCOPE**

```
http://localhost:3000/vp/request?profile=dcql&credential_profile=pid&client_id_scheme=did%3Aweb&request_uri_method=post&response_mode=direct_post.jwt&scheme=openid4vp
```

**`did:jwk` verifier client id scheme**
**IGNORE USES did:jwk out of SCOPE**

```
http://localhost:3000/vp/request?profile=dcql&credential_profile=pid&client_id_scheme=did%3Ajwk&request_uri_method=post&response_mode=direct_post.jwt&scheme=openid4vp
```

**PID · same-device EU EAAP scheme (explicit)**
**IGNORE doesnt work why????**


```
http://localhost:3000/vp/request?profile=dcql&credential_profile=pid&client_id_scheme=x509_hash&request_uri_method=post&response_mode=direct_post.jwt&scheme=eu-eaap
```

**mDL · generic `openid4vp` (not ISO `mdoc-openid4vp`)**

```
http://localhost:3000/vp/request?profile=dcql&credential_profile=mdl&client_id_scheme=x509_hash&request_uri_method=post&response_mode=direct_post.jwt&invocation_scheme=openid4vp
```

---

### `GET /vp/request` — parameter reference

Returns JSON: **`qr`**, **`deepLink`**, **`sessionId`**, and sometimes **`invocationScheme`**.

| Query parameter | Role | Allowed / default |
|-----------------|------|-------------------|
| **`session_id`** | Stable session id | Optional. **Only `session_id` is read** (not `sessionId`). If omitted, a UUID is generated. |
| **`profile`** | Presentation shape | **`dcql`** (default), **`tx`**, **`mdl`**, **`etsi`**, **`rfc002`**. |
| | | **`dcql`** / **`tx`**: DCQL (`DEFAULT_DCQL_QUERY` or **`DEFAULT_MDL_DCQL_QUERY`** for mDL). |
| | | **`mdl`** + **`credential_profile=mdl`**: tries `./data/presentation_definition_mdl.json`; if missing, default mDL DCQL. |
| | | **`etsi`**: PID invocation defaults to **`eu-eaap`** when **`scheme` / `invocation_scheme`** omitted. |
| | | **`rfc002`**: like **`etsi`** for **`x509` → `x509_hash`** mapping; PID invocation still defaults to **`openid4vp`**. |
| **`credential_profile`** | Credential query preset | **`pid`** (default), **`pidfull`**, **`booking_pid`** (Accommodation Voucher + PID; requests `reservationReference` + `family_name`), **`mdl`**. |
| **`client_id_scheme`** | Verifier identity | **`x509`**, **`x509_hash`**, **`x509_san_dns`**, **`did:web`**, **`did:jwk`**. |
| | | **`x509`** with **`profile=etsi` or `rfc002`** → **`x509_hash`**; else **`x509_san_dns`**. |
| **`request_uri_method`** | Wallet fetch of JAR | **`post`** (default). Only **`post`** (lowercase) adds POST semantics; otherwise GET. |
| **`response_mode`** | VP response | Omitted → **`direct_post`**, except **`profile=etsi` or `rfc002`** → default **`direct_post.jwt`**. |
| **`jar_alg`** | JAR signing alg | Default **`ES256`**. |
| **`tx_data`** | Transaction data | **`true`** enables **`transaction_data`**. |
| **`invocation_scheme`** | mDL wallet scheme | **`mdoc-openid4vp`** (default), **`openid4vp`**, **`mdoc_openid4vp`**. |
| **`scheme`** | PID wallet scheme | **`openid4vp`**, **`eu-eaap`**, **`eu_eaap`**; with **`profile=etsi`** and empty → **`eu-eaap`**. |
| **`verifier_info`** / per-field **`verifier_*`** | Verifier metadata overrides | See **`VERIFIER_INFO_KEYS`** in `utils/routeUtils.js`. |

### `GET /vp/etsi/same-device`

Forces **`profile=etsi`** and **302** redirects to **`/vp/request?...`** with your other query params preserved.

---

## 2. Standardized VCI offers — ready-to-use URIs (`localhost:3000`)

**Pre-authorized code · tx-code · EU EAA offer scheme**

```
http://localhost:3000/vci/offer?flow=pre_authorized_code&tx_code_required=true&credential_type=ETSIRfc001PidVcSdJwt&credential_format=sd-jwt&signature_type=x509&offer_scheme=eu_eaa
```

**Pre-authorized · no tx-code**

```
http://localhost:3000/vci/offer?flow=pre_authorized_code&tx_code_required=false&credential_type=ETSIRfc001PidVcSdJwt&credential_format=sd-jwt&signature_type=x509&offer_scheme=eu_eaa
```

**Authorization code · HAIP / X509 SAN DNS client**

```
http://localhost:3000/vci/offer?flow=authorization_code&credential_type=ETSIRfc001PidVcSdJwt&credential_format=sd-jwt&signature_type=x509&offer_scheme=eu_eaa
```

**Authorization code · default offer scheme (`openid-credential-offer://`)**

**NOTE:** Implementation variant only. Do **not** treat `signature_type=jwk`, `kid-jwk`, `did-web`, or `did:jwk` as APTITUDE RFC001 conformance cases. RFC001 targets OpenID4VCI v1.0 with HAIP v1.0 and ETSI TS 119 472-3 alignment, where the deployed conformance baseline is X.509-backed (`signature_type=x509`) with ETSI issuer metadata, `x5c`, `issuer_info`, wallet attestation handling, and `eu-eaa-offer://` support. JWK/KID-JWK/DID variants may remain useful for implementation or interoperability experiments, but they are intentionally excluded from the RFC001 HAIP/ETSI test matrix.

```
http://localhost:3000/vci/offer?flow=authorization_code&credential_type=ETSIRfc001PidVcSdJwt&signature_type=jwk
```

**Stable issuance session**

```
http://localhost:3000/vci/offer?session_id=demo-001&flow=pre_authorized_code&credential_type=ETSIRfc001PidVcSdJwt&signature_type=x509&offer_scheme=eu_eaa
```

**Dynamic credential request (authorization-code path)**

```
http://localhost:3000/vci/offer?flow=authorization_code&credential_type=ETSIRfc001PidVcSdJwt&signature_type=x509&issuance_mode=dynamic&offer_scheme=eu_eaa
```

---

### `GET /vci/offer` — parameter reference

Returns **`qr`**, **`deepLink`**, **`sessionId`**.

| Query parameter | Role | Allowed / default |
|-----------------|------|-------------------|
| **`session_id`** or **`sessionId`** | Session id | **`session_id`** first, then **`sessionId`**, else new UUID. |
| **`flow`** | Grant | **`authorization_code`** (default), **`pre_authorized_code`**. |
| **`tx_code_required`** | Pre-auth tx-code | Exact **`true`** → **`/credential-offer-tx-code/:id`**; else **`/credential-offer-no-code/:id`**. |
| **`credential_type`** / **`credentialType`** / **`type`** | Config id | Must exist in **`credential_configurations_supported`** (`data/issuer-config.json`). |
| **`credential_format`** | Informational | **`sd-jwt`** (default), **`mso_mdoc`**. |
| **`signature_type`** | Issuer + client scheme | **`x509`**, **`jwk`**, **`kid-jwk`**, **`did-web`**, **`did:jwk`**, … |
| **`issuance_mode`** / **`issuanceMode`** | Auth-code shape | **`standard`**, **`dynamic`**, **`deferred`** (typo **`defered`** accepted). |
| **`isDynamic`**, **`dynamic_credential_request`** | Overrides | Boolean / **`true`** for dynamic. |
| **`offer_scheme`** / **`url_scheme`** | Offer deep link | **`standard`**, **`haip`**, **`eu_eaa`**, … (see `resolveCredentialOfferUrlScheme`). |

### `offer_scheme` / `url_scheme` values

| Input | Result |
|--------|--------|
| **`standard`**, **`openid`**, **`openid_credential_offer`**, **`openid-credential-offer://`** | OID4VCI default offer URI |
| **`haip`**, **`haip://`** | HAIP |
| **`eu_eaa`**, **`eu-eaa`**, **`eaa`**, **`eu-eaa-offer://`** | **`eu-eaa-offer://`** |
| Unknown / empty | Standard **`openid-credential-offer://`** |

---

## 3. Legacy — authorization-code SD-JWT offers

```
http://localhost:3000/offer-code-sd-jwt?credentialType=ETSIRfc001PidVcSdJwt&signatureType=x509&client_id_scheme=x509_san_dns&offer_scheme=eu_eaa
```

Also:

- `http://localhost:3000/offer-code-sd-jwt-dynamic` — forced dynamic issuance.
- `http://localhost:3000/offer-code-defered` — forced deferred issuance.

| Query parameter | Notes |
|-----------------|--------|
| **`sessionId`**, **`credentialType`**, **`type`**, **`signatureType`**, **`client_id_scheme`** | Session + credential + signing + PAR client scheme. |
| **`issuance_mode`**, **`dynamic_credential_request`**, … | Same as **`resolveCodeFlowOfferIssuanceOptions`**. |
| **`offer_scheme`**, **`url_scheme`** | Same as VCI. |

---

## 4. Legacy — pre-authorized offers

```
http://localhost:3000/offer-no-code?credentialType=ETSIRfc001PidVcSdJwt&signatureType=x509&offer_scheme=eu_eaa
```

```
http://localhost:3000/offer-tx-code?credentialType=ETSIRfc001PidVcSdJwt&signatureType=x509&offer_scheme=eu_eaa
```

**`POST /offer-no-code`** — JSON body must pass **`isValidCredentialPayload`**; query params can mirror the GET variants.

---

## 5. Curl equivalents (VP)

```bash
curl -sS -G "http://localhost:3000/vp/request" \
  --data-urlencode "profile=dcql" \
  --data-urlencode "credential_profile=pid" \
  --data-urlencode "client_id_scheme=x509_hash" \
  --data-urlencode "request_uri_method=post" \
  --data-urlencode "response_mode=direct_post.jwt" \
  --data-urlencode "scheme=openid4vp"
```

---

## Related docs

- [RFC001 — How to initiate VCI test cases](./rfc001-vci-test-case-initiation.md)
- [VP verification wallet matrix](./vp-verification-wallet-matrix.md)
