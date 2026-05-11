# ETSI TS 119 472-2 — EAAP / PID presentations to relying parties

Analysis of **ETSI TS 119 472-2 V1.2.1 (2026-03)** — *Electronic Signatures and Trust Infrastructures (ESI); Profiles for Electronic Attestation of Attributes; Part 2: Profiles for EAA/PID Presentations to Relying Party*.

**Normative source:** [ts_11947202v010201p.pdf](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf)

This document summarises what the TS defines for **Electronic Attestation of Attributes Presentations (EAAP)** and **RP→wallet→RP** protocols, then maps that to **verifier-side** (and related wallet-test) code in this repository, with explicit **gaps** where behaviour is not aligned with the strict ETSI structures.

---

## 1. Scope (clause 1)

The TS specifies:

1. **Three EAAP realisations** matching EAA formats from ETSI TS 119 472-1 [5]:
   - **SD-JWT VC EAAP** (clause 4.1);
   - **ISO/IEC-mdoc EAAP** (clause 4.2);
   - **JSON-LD W3C VC EAAP** (Annex A normative).

   **X509-AC EAAP** is noted for a **future** version (informative Annex B only in v1.2.1).

2. **Two presentation protocols**:
   - **ISO/IEC-mdoc profile** (clause 5) — non-API-mediated only, built on **ISO/IEC 18013-5** [10]; `DeviceRequest` / `DeviceResponse` style flows.
   - **OpenID4VC-HAIP profile** (clause 6) — builds on **OpenID4VC-HAIP** [11] + **OpenID4VP** [7]:
     - **Non-API mediated**: HAIP §5.1-style redirects; JAR/`request_uri`; etc.
     - **API-mediated**: HAIP §5.2-style (optional for wallet and RP per §6.2); extra privacy constraints in §6.5.2.

---

## 2. EAAP data shapes (clauses 4.1–4.2, Annex A)

### 2.1 SD-JWT VC EAAP (clause 4.1)

| ID | Requirement (paraphrased) |
| --- | --- |
| **EAAP-SD-JWT VC-01** | If the EAA includes **`cnf`**, the EAAP **shall** be **SD‑JWT+KB** (RFC 9901 SD-JWT). |
| **EAAP-SD-JWT VC-02** | If the EAA has **no `cnf`**, the EAAP **shall** be plain SD-JWT VC EAAP (no KB-JWT). |
| **EAAP-SD-JWT VC-03** | Serialization: compact or flattened JSON per SD-JWT. |
| **EAAP-SD-JWT VC-04** | **KB-JWT** (when present) **shall** be signed by the **EAA subject** (holder). |

*Verifier impact:* When the wallet returns `dc+sd-jwt` VP tokens, the relying party validates **KB-JWT**, **`nonce`**, **`sd_hash`**, etc., per OpenID4VP + HAIP. This is implemented primarily under ```routes/verify/verifierRoutes.js``` (response handling) and exercised by the wallet harness in ```wallet-client/src/lib/presentation.js```.

### 2.2 ISO/IEC-mdoc EAAP (clause 4.2)

Normative ties to **ISO/IEC 18013-5** `DeviceResponse` / `Document`: successful documents are EAAPs; `issuerSigned` carries issuer-signed disclosures; **`deviceSigned`** may carry extra attributes only if the **EAA/PID provider** explicitly allowed them.

*Verifier impact:* For **native** ISO 18013-5 device retrieval (clause 5), the RP builds signed **DeviceRequest** objects. This repository’s **mdoc** path is predominantly **OpenID4VP** with `mso_mdoc` in **DCQL**, not a full standalone ISO 18013-5 verifier (`readerAuth`, CBOR `requestInfo`, etc.). See §8.5 below.

### 2.3 JSON-LD W3C VC EAAP (Annex A)

JOSE-secured JSON-LD VPs with **`verifiableCredential`** arrays, **`EnvelopedVerifiableCredential`**, **`data:`** URIs with `application/vc+jwt` or `application/vc+sd-jwt`, etc.

*Verifier impact:* Not a primary format in the current Node verifier; HAIP/DCQL paths focus on **SD-JWT** / **mdoc**.

---

## 3. ISO/IEC-mdoc profile — protocol (clause 5)

**Support (§5.2):** Wallets, PID/Attestation providers, wallet providers, and RPs **shall not** use **server** retrieval from ISO 18013-5 for PID/attestation presentation. Wallet and RP **shall** meet §5.3.

**EAAP request (§5.3.2)** — summarized:

- Every `docRequests[]` element **shall** have **`readerAuth`** (COSE Sign1).
- **`readerAuth`** **shall** use the RP **access certificate** key; **`x5chain`** holds leaf + chain to (excluding) trust anchor.
- **`ItemsRequest`** **shall** have non-empty **`requestInfo`** with CDDL `RequestInfo` / **`EUWrpRegistrarInfo`** (Registrar fields per ETSI TS 119 475 [14]), optional **`euWrprc`** (RP registration certificate as CBOR byte string).

**EAAP response (§5.3.3):** Wallet unit **shall** produce `DeviceResponse` per [10].

*This repository:* There is **no** dedicated implementation that constructs **ISO 18013-5** `DeviceRequest` with **`readerAuth`**, `euWrpRegistrarInfo`, and CBOR **`requestInfo`** as specified here. Mdoc presentation is handled via **OpenID4VP** + **DCQL** (```routes/verify/mdlRoutes.js```, ```utils/routeUtils.js``` session/URL helpers). Treat **clause 5** as **out of scope** for a strict ISO profile in this codebase unless you add a separate 18013-5 module.

---

## 4. OpenID4VC-HAIP profile (clause 6)

### 4.1 Support (§6.2)

- Wallet **shall** implement **§6.3 + §6.4** (non-API mediated).
- Wallet **may** implement **§6.5** (API-mediated); wallet **shall** support **cross-device only** via API-mediated mechanism.
- RP **shall** implement **§6.3 + §6.4**; RP **may** implement **§6.5**.

### 4.2 General (§6.3.1)

Mandatory requirements from **HAIP** §5 (intro), §5.3, §7, §8 apply unless this TS overrides them.

### 4.3 Authorisation request — common (§6.3.2)

**Client identifier**

| ID | Requirement |
| --- | --- |
| **OIDFVP-HAIP-COMMON-REQ-01** | Authorisation request **shall** use **`x509_hash`** client identifier prefix. |

**Request object (JAR) body — `verifier_info`**

The RO body **shall** contain **`verifier_info`**. Registrar data and optional registration certificate **shall** follow the **array** structure defined in OpenID4VP [7] as profiled here:

- One element with **`format`**: **`registrar_dataset`**, **`data`**: JSON object with **`identifier`**, **`srvDescription`**, **`registryURI`**, **`intendedUseIdentifier`**, **`purpose`**, **`policyURI`**, optional **`credential`**, all as referenced into **ETSI TS 119 475** [14].
- If the RP has a **registration certificate**, another element with **`format`**: **`registration_cert`**, **`data`**: **base64url** of the serialized RP registration certificate.
- Elements **shall not** contain **`credential_ids`**.
- **OIDFVP-HAIP-COMMON-REQ-RO-17:** **Authority Key Identifier** **shall** use the **ETSI Trusted Lists** mechanism (**`etsi_tl`** type) [12].

**Request object — other**

| ID | Requirement |
| --- | --- |
| **OIDFVP-HAIP-COMMON-REQ-RO-18–21** | RO **shall** contain **`client_metadata`** with **`jwks`**; keys **shall** include **`kid`** and **`use`**; **`kid`** **shall** uniquely identify a key. |
| **OIDFVP-HAIP-COMMON-REQ-RO-22** | RO body **shall** contain **`aud`**. |
| **OIDFVP-HAIP-COMMON-REQ-RO-23** | RO **shall** be **signed** by the RP private key matching the **RP access certificate**. |

**Response (§6.3.3)**

| ID | Requirement |
| --- | --- |
| **OIDFVP-HAIP-COMMON-RESP-01** | The EUDI Wallet **shall** **encrypt** the authorisation response. |

(Encryption algorithms and RP behaviour follow OpenID4VP / HAIP; RPs **support** the enc algebras advertised.)

### 4.4 Non-API mediated — redirects (§6.4)

| ID | Requirement |
| --- | --- |
| **OIDFVP-HAIP-REDIRECTS-01–02** | Mandatory vs optional rules from **HAIP §5.1**. |
| **OIDFVP-HAIP-REDIRECTS-03** | Wallet **shall** support custom scheme **`eu-eaap://`** for its `authorization_endpoint`. |
| **OIDFVP-HAIP-REDIRECTS-04** | Authorisation request **shall** include **`request_uri`** and **shall not** include the inline RO (by-value). |
| **OIDFVP-HAIP-REDIRECTS-RO-01–02** | JWS protected header **shall** include **`x5c`**: leaf RP access cert first, chain up to (excluding) trust anchor. |
| **OIDFVP-HAIP-REDIRECTS-RO-03** | JWS protected header **shall** include **`iat`**. |

### 4.5 API-mediated (§6.5)

**§6.5.1:** HAIP §5.2 mandatory/optional rules; wallet **shall not** support **`openid4vp-1-unsigned`** exchange value.

**§6.5.2** adds privacy and CTAP-oriented rules for mediation (disclose credential **types** only by default, user toggle, uninstall behaviours, CTAP 2.2 hybrid for cross-device where available, etc.). **Largely wallet/OS/browser** obligations, not this Node service.

### 4.6 Security (§6.6)

Clause 14 security considerations of **OpenID4VP** [7] apply.

---

## 5. Annexes C and D — DCQL `format` for special EAA types

| Annex | ID | Requirement |
| --- | --- | --- |
| **C.2** | **OIDFVP-HAIP-JSON_LD_EAA-GEN-REQ-01** | For JSON-LD W3C-VC EAAP (Annex A), **`dcql_query`** credential **`format`** **shall** be **`vp+jwt`**. |
| **D.2** | **X509_AC_EAA-GEN-REQ-01** | For X509-AC EAAP (Annex B, informative), **`format`** **shall** be **`x509_attr`**. |

---

## 6. Implementation in this repository (`rfc-issuer-v1`)

This project implements a **relying party (verifier)** for **OpenID4VP / HAIP-style** presentations rather than a full **ISO/IEC 18013-5 clause 5** device-retrieval stack.

### 6.1 Request object (JAR), `request_uri`, PAR-style issuance of VP request

| Topic | Location |
| --- | --- |
| Build signed JAR (`typ: oauth-authz-req+jwt`), `x5c`, `dcql_query`, `client_metadata`, `aud`, `response_uri`, `verifier_info` merge | ```272:540:utils/cryptoUtils.js``` — `buildVpRequestJWT`; ```87:102:utils/cryptoUtils.js``` — `attachRuntimeVerifierInfo`. |
| **x509_hash** client_id vs leaf cert | ```499:540:utils/cryptoUtils.js``` — branch for `x509_hash:` enforces hash of leaf DER. |
| Orchestration per session | ```1937:2039:utils/routeUtils.js``` — `processVPRequest` calls `buildVpRequestJWT` with session DCQL, response mode, `verifier_info`, `jar_alg`. |
| POST/GET **request_uri** handlers | ```vpStandardRoutes.js```, ```x509Routes.js```, ```mdlRoutes.js```, ```didRoutes.js```, etc. — each calls `processVPRequest`. Example: ```345:389:routes/verify/vpStandardRoutes.js``` (did:web request URI POST). |

### 6.2 `verifier_info` and registrar fields (vs OIDFVP-HAIP-COMMON-REQ-RO-*)

| Topic | Location |
| --- | --- |
| Static RP registration fields (verifier_id, service description, registrar URI, intended use, purpose, privacy policy) | ```1:8:data/verifier-info.json```; loaded via `loadVerifierInfo()` in ```routeUtils.js``` (see ```518``` area for merge helpers). |
| Runtime attachment of **registration_certificate** (base64 DER strings from active signing chain) | ```87:102:utils/cryptoUtils.js``` — `attachRuntimeVerifierInfo` sets **`registration_certificate`** to cert chain array. |
| Tests expecting flat **`verifier_info` + `registration_certificate`** on the JWT payload | ```259:301:tests/presentationDefinition.test.js```. |

**Gap — ETSI array + `format`/`data`:** ETSI **requires** `verifier_info` as an **array of objects** with **`format`** `registrar_dataset` / `registration_cert` and **`data`** per OpenID4VP. This codebase uses a **single JSON object** (RFC002-style field names like `verifier_id`, `rp_registrar_uri`, …) plus **`registration_certificate`** as an array of base64 certs — **not** the TS-mandated `registrar_dataset` / `registration_cert` element shape. Wallets consuming strict ETSI layout may need adapters.

**Gap — RO-17 (`etsi_tl`):** No code was found that sets Authority Key Identifier / trusted list **`etsi_tl`** on the RP certificate profile for this TS.

### 6.3 `client_metadata` / JWKS (`kid`, `use`)

| Topic | Location |
| --- | --- |
| Encryption (and related) JWKS in verifier client metadata | ```23:35:data/verifier-config.json```; passed through `loadVerifierClientMetadataForRequests` → ```255:260:utils/routeUtils.js```. |
| Merged JWKS for **/.well-known/openid-verifier-metadata** | ```231:249:utils/routeUtils.js``` — `buildOpenIdVerifierMetadataDocument` merges encryption keys with public signing keys (```182:222:utils/routeUtils.js```). |

### 6.4 **`aud`**, **`iat`**, JWS header

| Topic | Location |
| --- | --- |
| **`aud`** on RO body | ```340:366:utils/cryptoUtils.js``` — payload includes `aud` (forced to `https://self-issued.me/v2` for non–dc_api modes). |
| **`iat` / `exp` on RO body** | ```377:378:utils/cryptoUtils.js``` — set on **payload**. |
| **`iat` in JWS protected header** | *Not set in protected header in `buildVpRequestJWT`* — **potential gap** under **OIDFVP-HAIP-REDIRECTS-RO-03** (payload carries `iat`; spec calls for protected-header `iat`). |

### 6.5 Encrypted authorisation responses (`OIDFVP-HAIP-COMMON-RESP-01`)

Wallet-side encryption is exercised by **wallet-client**; verifier decrypts on **`direct_post.jwt`** / **`dc_api.jwt`** paths in ```routes/verify/verifierRoutes.js``` (see RFC002 review references). **`direct_post`** (unencrypted) remains configurable where profiles allow.

### 6.6 **`eu-eaap://`**, **`request_uri`**, **`mdoc-openid4vp://`**

| Topic | Location |
| --- | --- |
| Same-device schemes **`eu-eaap`** vs **`openid4vp`** | ```378:391:utils/routeUtils.js``` — `resolvePidVpInvocationScheme`; ```2076:2091:utils/routeUtils.js``` — `createOpenID4VPRequestUrl`. |
| Tests for **eu-eaap** | ```296:339:tests/routeUtils.test.js```. |
| **mdoc-openid4vp** for ISO mdoc track | ```354:367:utils/routeUtils.js``` — `resolveMdlVpInvocationScheme`; ```wallet-client/src/lib/presentation.js``` accepts **`mdoc-openid4vp:`** deep links. |

### 6.7 Wallet request verification (client-side of EAAP request)

| Topic | Location |
| --- | --- |
| Verify JAR signature, **`x509_hash`** vs **`x5c`**, parse **`verifier_info`** | ```564:699:wallet-client/src/lib/presentation.js``` — `verifyAuthorizationRequestJwt`, `parseVerifierInfo`. |

### 6.8 DCQL annexes C / D (`vp+jwt`, `x509_attr`)

| Topic | Notes |
| --- | --- |
| **Annex C (`vp+jwt`)** | No verifier DCQL fixture requires **`format: "vp+jwt"`** for JSON-LD Annex A EAAP; PID flows use **`dc+sd-jwt`** (see ```264:271:tests/presentationDefinition.test.js```). **Gap** if strict Annex C conformance is required. |
| **Annex D (`x509_attr`)** | **`x509_attr`** appears in **issuance** metadata and credential generation (```76:84:data/issuer-config.json```, ```745:746:utils/credGenerationUtils.js```), not as a primary **presentation** DCQL format in verifier routes. **Gap** for X509-AC **presentation** until Annex B/VP path exists. |

### 6.9 ISO/IEC-mdoc profile (clause 5) vs this repo

| Topic | Notes |
| --- | --- |
| **`readerAuth`**, **`requestInfo`**, **`EUWrpRegistrarInfo`**, CBOR **DeviceRequest** | **Not implemented** in the Node verifier surface reviewed. |
| OpenID4VP **mso_mdoc** DCQL | Implemented via ```routes/verify/mdlRoutes.js``` + ```processVPRequest```; **response validation** is largely **structural** (```utils/mdlVerification.js```) — see **RFC002 verifier review** for cryptographic gaps (`IssuerAuth`, `DeviceAuth`, `SessionTranscript`). |

---

## 7. Cross-reference: RFC002 verifier review

Detailed verifier gaps ( **`state`** on all `direct_post.jwt` branches, legacy routes, metadata publication, mdoc crypto, etc.) are tracked in ```reports/rfc002-verifier-compliance-review.md```. Treat that report as the **issue backlog**; this document adds the **ETSI TS 119 472-2** requirement vocabulary and the **472-2-specific** deltas (**`verifier_info`** shape, **RO header `iat`**, **`etsi_tl`**, **Annex C/D** DCQL, **clause 5** ISO profile).

---

## 8. Normative references cited in the TS (traceability)

- **ETSI TS 119 472-1** [5], **ETSI TS 119 475** [14], **ETSI TS 119 612** [12]  
- **OpenID4VP** [7], **OpenID4VC-HAIP** [11], **RFC 9101 (JAR)** [6]  
- **SD-JWT (RFC 9901)** [2], **VC Data Model v2**, **VC-JOSE-COSE** [3]  
- **ISO/IEC 18013-5** [10] (mdoc profile)

---

*Prepared from the published ETSI PDF (March 2026) and the `rfc-issuer-v1` tree. For authoritative interpretation, use the ETSI deliverable and any later revisions.*
