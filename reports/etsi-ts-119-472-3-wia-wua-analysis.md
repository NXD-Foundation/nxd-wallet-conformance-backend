# ETSI TS 119 472-3 — WIA and WUA at Issuance Endpoints

Analysis of **ETSI TS 119 472-3 V1.1.1 (2026-03)** — *Electronic Signatures and Trust Infrastructures (ESI); Profiles for Electronic Attestation of Attributes; Part 3: Profiles for issuance of EAA or PID*.

**Normative source:** [ts_11947203v010101p.pdf](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf)

This note summarises **what the wallet must send** and **what the PID/EAA Provider (issuer) must check** for **Wallet Instance Attestation (WIA)** and **Wallet Unit Attestation (WUA)**. In the protocol, the issuer does not typically “pull” these in a separate HTTP call; it **receives** them on defined requests and **verifies** them before proceeding.

---

## 1. Definitions (clause 3.1)

**Wallet Instance Attestation (WIA)**  
JWT signed by the Wallet Provider attesting the integrity of the wallet application. It lets PID/EAA Providers restrict their endpoints to wallet applications whose integrity is assured by Wallet Providers. Contents are specified in **EUDI Wallet TS03** (informative reference [i.2] in the TS).

**Wallet Unit Attestation (WUA)**  
JWT signed by the Wallet Provider describing wallet unit components (or enabling authentication/validation of those components). It lets PID/EAA Providers ensure PID/EAA are cryptographically bound to keys that are protected appropriately (e.g. in a WSCD with sufficient attack resistance) and supports revocation when a Wallet Provider revokes a wallet unit. Contents are specified in **EUDI Wallet TS03**.

---

## 2. Where WIA and WUA appear (scope, clause 1)

The specification states that it defines, among other items:

| # | Transport |
|---|-----------|
| 5 | Sending the **WIA** to the **Pushed Authorisation Endpoint** and the **Token Endpoint**. |
| 6 | Sending the **WUA** to the **Credential Endpoint**. |
| 7–9 | Proof of possession of keys bound to the WUA and to the PID/EAA, and co-binding to the same WSCA/WSCD (see credential request / proof mechanisms). |

**Pre-Authorised Code Flow:** Requirements for **clause 4.4** (Pushed Authorisation Request) apply only to issuers that implement the **Authorisation Code Flow** (clause 4.4.1). Issuers using **only** pre-authorised code would not use PAR; **Token** and **Credential** rules still apply to those flows when the wallet hits those endpoints.

---

## 3. WIA — Pushed Authorisation Request (PAR)

### 3.1 Wallet obligations (clause 4.4.2)

- **AUTH-REQ-4.4.2-01:** The Pushed Authorisation Request **shall** include the WIA as an **OAuth-Client-Attestation** parameter, as in **OpenID4VCI** Appendix E and **IETF draft-ietf-oauth-attestation-based-client-auth-07**.
- **AUTH-REQ-4.4.2-02:** The PAR **shall** include a **proof-of-possession** of the public key in the **`cnf`** claim (same normative references).

*Informative note in the TS:* WIAs are expected to have a TTL under 24 hours.

### 3.2 Issuer processing / checks (clause 4.4.3)

When the PID/EAA Provider receives a WIA (and PoP where present):

| Requirement ID | Check |
|----------------|--------|
| **AUTH-REQ-PROC-4.4.3-01** | Verify the **JWT signature** on the WIA using the **Wallet Provider’s public key** from the **Trusted List of Wallet Providers**. |
| **AUTH-REQ-PROC-4.4.3-02** | Verify the WIA has **not expired**. |
| **AUTH-REQ-PROC-4.4.3-03** | If a PoP is present with the WIA, verify the PoP **signature** under the **public key in the `cnf` claim** of the WIA. |

---

## 4. WIA — Token Request

### 4.1 Wallet obligations (clause 4.5.1)

- **TOKEN-REQ-4.5.1-01:** The Token Request **shall** include the WIA as **OAuth-Client-Attestation** (same references as PAR).
- **TOKEN-REQ-4.5.1-02:** The Token Request **shall** include **proof-of-possession** of the `cnf` public key (same references).

### 4.2 Issuer processing / checks (clause 4.5.2)

| Requirement ID | Check |
|----------------|--------|
| **TOKEN-REQ-PROC-4.5.2-01** | Same as PAR: verify WIA JWT signature with Wallet Provider key from **Trusted List of Wallet Providers**. |
| **TOKEN-REQ-PROC-4.5.2-02** | Verify WIA **not expired**. |
| **TOKEN-REQ-PROC-4.5.2-03** | If WIA includes PoP, verify PoP under **`cnf`** public key. |

**TOKEN-REQ-PROC-4.5.2-04** adds that **refresh tokens** for credential refresh **may** be supported (with security caveats in an informative note); this is not a WIA check but affects token endpoint behaviour.

---

## 5. WUA — Credential Request

WUA is **not** sent as OAuth-Client-Attestation on the credential endpoint in the same way as WIA on PAR/token. It is carried inside the **`proofs`** parameter when the PID/EAA is **cryptographically bound to the device** (clause 4.6.1.1).

### 5.1 Common shape (clause 4.6.1.1)

- **CRED-REQ-4.6.1.1-01:** If the PID/EAA is device-bound, the Credential Request **shall** include **`proofs`**.
- **CRED-REQ-4.6.1.1-02:** **`proofs`** **shall** contain either **`jwt`** or **`attestation`**.

Two mechanisms:

- **`proofs.jwt`** — proves possession of the private key(s) for the key(s) the credential(s) will bind to, and carries WUA in the JWS header.
- **`proofs.attestation`** — carries WUA without proving possession of those private keys in the same step.

---

### 5.2 Mechanism A: `proofs.jwt` (clause 4.6.1.2)

**Wallet shall:**

| ID | Requirement |
|----|-------------|
| CRED-REQ-4.6.1.2-01 | The **`jwt`** array **shall** have **exactly one** element. |
| CRED-REQ-4.6.1.2-02 | That element **shall** include a **`nonce`** in the JWT body from the issuer’s **Nonce Endpoint**. |
| CRED-REQ-4.6.1.2-03 | The element **shall** include **`key_attestation`** in the **protected header**. |
| CRED-REQ-4.6.1.2-04 | **`key_attestation`** **shall** be the **WUA** (JWT signed by the Wallet Provider). |
| CRED-REQ-4.6.1.2-05 | WUA **shall** be a key attestation JWT per **OpenID4VCI** clause D.1. |
| CRED-REQ-4.6.1.2-06 | **`attested_keys`** inside **`key_attestation`** **shall** contain **one or more** public keys owned by the wallet unit. |
| CRED-REQ-4.6.1.2-07 | The **`jwt`** proof **shall** be signed by the wallet unit with the **private key** matching the **first** public key in **`attested_keys`**. |

*Interpretation:* The wallet proves it holds the private key for the **first** attested key, while the WUA (wallet-provider-signed) attests the set of keys; the issuer can issue one credential per attested key as in processing rules below.

**Issuer shall verify (clause 4.6.2.1):**

| ID | Check |
|----|--------|
| **CRED-REQ-PROC-4.6.2.1-01** | Verify **`key_attestation`** (the WUA) signature under the Wallet Provider’s public key from the **Trusted List for Wallet Providers**. |
| **CRED-REQ-PROC-4.6.2.1-02** | Verify the **`jwt`** proof signature under the **first** public key in **`attested_keys`** inside **`key_attestation`**. |
| **CRED-REQ-PROC-4.6.2.1-03** | Verify **`nonce`** in the JWT body is a **valid** value from the issuer’s Nonce endpoint. |
| **CRED-REQ-PROC-4.6.2.1-04** | **Generate** as many PID/EAA as there are entries in **`attested_keys`**. |
| **CRED-REQ-PROC-4.6.2.1-05** | Each PID/EAA **shall** bind to **one** of the keys in **`attested_keys`**. |
| **CRED-REQ-PROC-4.6.2.1-06** | **No two** PID/EAA **shall** bind to the **same** public key. |

---

### 5.3 Mechanism B: `proofs.attestation` (clause 4.6.1.3)

**Wallet shall:**

| ID | Requirement |
|----|-------------|
| CRED-REQ-4.6.1.3-01 | **`attestation`** array **shall** contain **only one** element. |
| CRED-REQ-4.6.1.3-02 | That element **shall** include **`nonce`** from the Nonce Endpoint. |
| CRED-REQ-4.6.1.3-03 | The element **shall** **be** the **WUA** (informative note: this does **not** prove possession of the private keys for the attested public keys). |

**Issuer shall verify (clause 4.6.2.2):**

| ID | Check |
|----|--------|
| **CRED-REQ-PROC-4.6.2.2-01** | Verify the WUA (**`attestation`** element) signature under the Wallet Provider’s key from the **Trusted List for Wallet Providers**. |
| **CRED-REQ-PROC-4.6.2.2-02** | Generate as many PID/EAA as **`attested_keys`** entries in the WUA. |
| **CRED-REQ-PROC-4.6.2.2-03** | Each credential binds to one distinct key from **`attested_keys`**. |
| **CRED-REQ-PROC-4.6.2.2-04** | No two credentials bound to the same public key. |

---

## 6. Endpoints where WIA/WUA do **not** appear in this TS

- **Authorisation Endpoint (browser redirect):** The scope (clause 1) mentions sending **formats** of requested PID/EAA to the authorisation and credential endpoints; it does **not** list sending WIA to the authorisation endpoint in v1.1.1. Earlier draft change history in the PDF notes removal of “Ephemeral WIA” from the authorisation and token endpoints in favour of the PAR/token transport now specified.
- **Notification Request (clause 4.7):** **NOT-REQ-4.7-01** only covers notification counts per `notification_id`; no WIA/WUA checks are defined there in this part.

---

## 7. Implementation takeaway (normative target)

For a PID/EAA Provider implementing this TS:

1. **Trusted List:** WIA and WUA verification both depend on resolving and trusting **Wallet Provider** signing keys from the **Trusted List of Wallet Providers** (wording: “Trusted List of Wallet Providers” vs “Trusted List for Wallet Providers” appears in different clauses but denotes the same conceptual trust anchor set).
2. **Consistency:** WIA is required at **both** PAR and **Token** (for the authorisation code profile that uses PAR), with the same logical checks each time.
3. **Credential issuance:** WUA is mandatory in the credential request path for device-bound credentials, with **stricter** assurance when using **`proofs.jwt`** (PoP + WUA) than **`proofs.attestation`** (WUA only).
4. **Multi-key issuance:** With multiple keys in **`attested_keys`**, the issuer issues **one** PID/EAA per key, each bound to a **different** key.

---

## 8. Implementation in this repository (`rfc-issuer-v1`)

This section maps **ETSI TS 119 472-3**-style behaviour to **issuer-side** code in this project. References are to the **issuer** service (Node routes and `utils/`); a small **`wallet-client/`** tree exists for interop testing and builds WIA/WUA-shaped JWTs for PAR, token, and credential calls.

### 8.1 Carrier conventions vs the PDF

The PDF cites **OpenID4VCI Appendix E** and the **OAuth attestation draft** for carrying the WIA on PAR and token. This codebase treats the **WIA JWT** primarily as an OAuth **`client_assertion`** with **`client_assertion_type`** `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, extracted by `extractWIAFromTokenRequest()` (it does not parse the WIA only from the `OAuth-Client-Attestation` header). It **also** requires **`OAuth-Client-Attestation`** and **`OAuth-Client-Attestation-PoP`** headers and binds them to the WIA `cnf` claim via `assertWiaCnfMatchesClientAttestation()` in `utils/oauthClientAttestation.js`. That aligns with HAIP / OID4VCI test patterns used in the repo (RFC001 §7.3–7.4 wording in code comments).

### 8.2 WIA — PAR (clause 4.4)

| Topic | Where it lives |
| --- | --- |
| PAR route, order of checks | ```620:764:routes/issue/codeFlowSdJwtRoutes.js``` — client attestation verification, then mandatory `client_assertion` WIA, `validateWIA`, mandatory attestation headers, `assertWiaCnfMatchesClientAttestation`. |
| Extract WIA from body | ```2732:2739:utils/routeUtils.js``` — `extractWIAFromTokenRequest`. |
| WIA structure, expiry, TTL ≤ 24h, `cnf`, signature | ```2425:2597:utils/routeUtils.js``` — `validateWIA`. |
| WIA JWS verification key + signature | ```2334:2392:utils/routeUtils.js``` — `resolveWiaVerificationJwk`, `verifyWiaJwtSignature` (`wallet_instance_attestation_jwks` or header `jwk` / `x5c`; **not** ETSI WP Trusted List — see comment on `resolveWiaVerificationJwk`). |
| OAuth client attestation + PoP | ```305:376:utils/oauthClientAttestation.js``` — `validateOAuthClientAttestationFromRequest`; attestation JWT verified when **`data/oauth-config.json`** `client_attestation_trusted_jwks` is non-empty; PoP verified with `verifyClientAttestationPopJwt` against attestation **`cnf.jwk`**. After `assertWiaCnfMatchesClientAttestation`, that `cnf` matches WIA `cnf` (ETSI-style PoP under the WIA instance key). |
| `cnf` consistency WIA ↔ header attestation | ```221:281:utils/oauthClientAttestation.js``` — `assertWiaCnfMatchesClientAttestation`. |

**Gap vs ETSI AUTH-REQ-PROC-4.4.3-01:** Wallet Provider keys are **not** resolved from the **Trusted List of Wallet Providers**. Logging explicitly notes “no WP trust list” after a successful WIA verify. Trust is configuration-driven (`wallet_instance_attestation_jwks` / header material as implemented in `verifyWiaJwtSignature`).

### 8.3 WIA — Token endpoint (clause 4.5)

| Topic | Where it lives |
| --- | --- |
| Token route — WIA required for token exchange | ```1211:1303:routes/issue/sharedIssuanceFlows.js``` — same pattern as PAR: `extractWIAFromTokenRequest`, `validateWIA`, `validateOAuthClientAttestationFromRequest`, `assertWiaCnfMatchesClientAttestation`. |
| Shared validation utilities | Same `utils/routeUtils.js` and `utils/oauthClientAttestation.js` as §8.2. |

**Note:** WIA is enforced **before** grant-type branching (`code` vs `pre-authorized_code`), so **all** token requests in this path must present WIA + headers, not only authorisation-code grants.

### 8.4 WUA — Credential endpoint (clause 4.6)

| Topic | Where it lives |
| --- | --- |
| When `proofs.jwt` must carry WUA (`key_attestation`) | ```2754:2761:utils/routeUtils.js``` — `credentialConfigRequiresJwtProofKeyAttestation` (metadata flag or EUDI PID `vct` + format). |
| Extract WUA from `proofs.attestation` / `proofs.jwt` header | ```2770:2805:utils/routeUtils.js``` — `extractWUAFromCredentialRequest`. |
| WUA JWT validation (claims, signature, stub trust) | ```2612:2717:utils/routeUtils.js``` — `validateWUA`; ```2405:2410:utils/routeUtils.js``` — `isWuaWalletProviderTrustedByPolicy` **stub always `true`**; revocation **TODO** in comments. |
| **`proofs.attestation` chain** (verify WUA, `attested_keys`, nonce elsewhere) | ```214:243:utils/keyAttestationProof.js``` — `verifyKeyAttestationProofChain`; ```68:71:utils/keyAttestationProof.js``` — `isKeyAttestationTrustedByIssuer` **stub always `true`**. Verification key from **`key_attestation_jwks`** or dev `header.jwk`. |
| **Device-bound `proofs.jwt`:** require `key_attestation`, strict `validateWUA`, proof key = `attested_keys[0]`, verify proof JWS | ```1831:1884:routes/issue/sharedIssuanceFlows.js``` — after session nonce checks; multi-key `cnf` list via `dedupeAttestedKeysToCnfList`. |
| **Optional** WUA path (non-device-bound): validate if present, **do not fail** if missing or invalid | ```1701:1733:routes/issue/sharedIssuanceFlows.js``` — logs warnings and continues when WUA is absent or `validateWUA` fails (contrast with strict branch above). |

**Gaps vs ETSI CRED-REQ-PROC-4.6.2.x:**

- **Trusted List** for Wallet Provider `iss` is **not** enforced (`isWuaWalletProviderTrustedByPolicy` / `isKeyAttestationTrustedByIssuer` stubs).
- For configurations **not** covered by `credentialConfigRequiresJwtProofKeyAttestation`, a WUA may be **ignored** even when invalid (see continuation path above). ETSI expects WUA whenever issuance is device-bound per §4.6; the repo ties strict behaviour to RFC001 / PID profile rules above.

### 8.5 Wallet-side helpers (testing / demos)

| Topic | Where it lives |
| --- | --- |
| Build `OAuth-Client-Attestation` headers + `client_assertion`, WUA for proofs | ```143:197:wallet-client/src/lib/walletProviderIdentity.js``` — `resolveAttestationForEndpoint`, `buildWalletUnitAttestationJwt`. |

### 8.6 Tests touching WIA / WUA

- **`tests/sharedIssuanceFlows.test.js`** — PAR/token WIA negatives, `key_attestation`, client attestation binding.
- **`tests/metadataDiscovery.test.js`** — PAR/token with WIA fixtures.
- **`tests/keyAttestationProof.test.js`** — `proofs.attestation` / JWKS resolution.
- **`tests/wuaValidation.test.js`** — `isWuaWalletProviderTrustedByPolicy` stub behaviour.

---

## 9. References cited by the TS (for traceability)

- **OpenID4VCI** — Appendix E (OAuth Client Attestation), Nonce endpoint, credential request / `proofs`, Annex D key attestation.
- **IETF draft-ietf-oauth-attestation-based-client-auth-07** — Attestation-based client authentication (used alongside OpenID4VCI for WIA transport).
- **EUDI Wallet TS03** [i.2] — WIA and WUA contents (informative in 119 472-3 but normative for payload semantics).

---

*Document prepared from the published ETSI PDF text (March 2026). For authoritative interpretation, use the ETSI deliverable and any later revisions.*
