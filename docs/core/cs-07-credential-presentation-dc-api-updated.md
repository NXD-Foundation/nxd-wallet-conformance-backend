# WE BUILD - Pre-flight Conformance Specification: Credential Presentation and Issuance via the Digital Credentials API

Version 0.2 / Pre-flight Draft
Date: 17 July 2026

**Authors**: WP4 Architecture

* Leif Johansson <leifj@siros.org>

Table Of Contents

- [1. Introduction](#1-introduction)
- [2. Scope](#2-scope)
- [3. Normative Language](#3-normative-language)
- [4. Roles and Components](#4-roles-and-components)
- [5. Protocol Overview](#5-protocol-overview)
- [6. High-level Flows](#6-high-level-flows)
  - [6.1 Same-device Presentation via DC API](#61-same-device-presentation-via-dc-api)
  - [6.2 Cross-device Presentation via Platform-mediated Transport](#62-cross-device-presentation-via-platform-mediated-transport)
  - [6.3 Credential Issuance via DC API](#63-credential-issuance-via-dc-api)
- [7. Normative Requirements](#7-normative-requirements)
  - [7.1 Wallet Unit Requirements](#71-wallet-unit-requirements)
  - [7.2 Verifier Requirements](#72-verifier-requirements)
  - [7.3 Issuer Requirements](#73-issuer-requirements)
- [8. Conformance](#8-conformance)
- [References](#references)

# 1. Introduction

This document is a **pre-flight conformance specification** as defined in the [Pre-flight CS ADR](../adr/pre-flight-CS.md). It is intended to enable early testing of credential presentation and issuance using the W3C Digital Credentials API (DC API) [1] within the WE BUILD ecosystem. The goal is to gather implementation experience and testing feedback that will inform a future full conformance specification.

The Digital Credentials API provides a browser-native mechanism for verifiers to request credential presentations from wallet units and for issuers to initiate credential issuance to wallet units. For same-device flows, this removes the need for custom protocol schemes (such as `openid4vp://`). For cross-device flows, the platform can connect the verifier's browser to a wallet on another device, with the browser mediating the interaction. The exact cross-device transport is platform-specific and is not prescribed by this specification. Both modes integrate credential exchange into the browser's security model.

This specification complements **CS-002 (Credential Presentation)** [2] and **CS-001 (Credential Issuance)** by defining how the same OpenID4VP and OpenID4VCI protocols operate when the browser's DC API serves as the invocation and transport layer, rather than custom URL schemes or redirect flows.

# 2. Scope

This specification defines the conformance expectations for credential presentation and issuance using the Digital Credentials API:

* **In scope:**
  * Same-device web presentation flows using `navigator.credentials.get()` with the `digital` credential type
  * Same-device web issuance flows using `navigator.credentials.create()` with the `digital` credential type
  * Cross-device presentation flows mediated by the user agent and platform
  * Integration of OpenID4VP request/response with the DC API transport
  * Integration of OID4VCI credential offers with the DC API transport
  * Verifier-side and issuer-side JavaScript API usage
  * Wallet unit request processing and response handling via the DC API

* **Out of scope:**
  * Cross-device presentation flows via QR code scanning without browser mediation (covered by CS-002 §6.2)
  * Proximity-based presentation (e.g. ISO 18013-5 / BLE)
  * Detailed trust evaluation and trust list resolution (covered by other WE BUILD specifications)
  * Platform-specific wallet registration, browser extensions, polyfills, and fallback-library design

# 3. Normative Language

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

> **Note:** As a pre-flight specification, the normative requirements herein are preliminary and subject to revision based on testing feedback.

# 4. Roles and Components

| Role | Description |
|------|-------------|
| **Wallet Unit (WU)** | An application or credential manager acting on behalf of the Holder and made available by the user agent or platform to handle the applicable DC API protocol. The mechanism by which it becomes available is platform-specific. |
| **Holder** | The person controlling the Wallet Unit. |
| **Verifier (Relying Party)** | A web application that requests credential presentations via the DC API. |
| **Issuer** | A web application that initiates credential issuance to a wallet unit via the DC API. |
| **User Agent (Browser)** | The browser mediating the DC API interaction between the Verifier/Issuer and the Wallet Unit. |

# 5. Protocol Overview

The Digital Credentials API [1] extends the W3C Credential Management API [3] to support digital identity credentials. A verifier calls `navigator.credentials.get()` with a `digital` options object containing an OpenID4VP presentation request. An issuer calls `navigator.credentials.create()` with a `digital` options object containing an OID4VCI credential offer. In both cases, the browser mediates the interaction:

1. The verifier constructs an OpenID4VP request object and passes it to the DC API.
2. The browser or platform identifies wallet units or credential managers capable of fulfilling the request.
3. The browser presents a wallet selection UI to the user (if multiple wallets are available).
4. The selected wallet unit receives the request, processes it, obtains holder consent, and returns the presentation response.
5. The browser delivers the response back to the verifier's JavaScript context.

This flow retains the credential-query and response-validation semantics from CS-002 while applying the DC API-specific adaptations defined by OpenID4VP Appendix A, including the request envelope, response modes, origin binding, and response delivery mechanism.

The key specification governing this interaction is the **W3C Digital Credentials API** Working Draft dated 15 July 2026 [1]. This conformance specification intentionally does not prescribe browser-specific availability, wallet-registration mechanisms, polyfills, or fallback-library architecture.

# 6. High-level Flows

## 6.1 Same-device Presentation via DC API

This flow describes how a verifier web application requests a credential presentation from a wallet unit using the Digital Credentials API.

### 6.1.1 Verifier Constructs Presentation Request

The verifier constructs a signed OpenID4VP Authorization Request as specified in CS-002 §6.1.1 and OpenID4VP Appendix A. Parameters that are not defined for the DC API, such as `state`, MUST NOT be relied upon for response correlation. The request is signed using JWS Compact Serialization and carried in the DC API envelope described in §6.1.2.

### 6.1.2 DC API Invocation

The verifier invokes the DC API:

```javascript
const credential = await navigator.credentials.get({
  digital: {
    requests: [{
      protocol: "openid4vp-v1-signed",
      data: {
        request: signedOpenid4vpRequest
      }
    }]
  }
});
```

The `protocol` field MUST be set to `"openid4vp-v1-signed"` (see §7.2 VP-DC-02). The `data` field MUST be a JSON object whose `request` member contains the signed OpenID4VP Authorization Request in JWS Compact Serialization. The signed request payload MUST set `response_type` to `vp_token`, `response_mode` to `dc_api.jwt`, and MUST include a non-empty `expected_origins` array containing the origin from which the DC API call is made (see §7.2 VP-DC-07 and VP-DC-08).

### 6.1.3 Browser Mediation

The browser:
1. Identifies wallet units or credential managers available for the `"openid4vp-v1-signed"` protocol.
2. Presents a selection UI to the user if multiple wallets are available.
3. Forwards the request to the selected wallet unit.

### 6.1.4 Wallet Processing and Holder Consent

The wallet unit:
1. Extracts the signed Request Object from the `request` member of the DC API `data` object.
2. Parses and validates the OpenID4VP request as specified in CS-002 §6.1.3.
3. Validates that the calling origin supplied by the user agent matches at least one value in `expected_origins`; otherwise, it returns an error.
4. Identifies matching credentials.
5. Presents a consent screen to the holder, showing the requested attributes and the verifier's identity.
6. Upon consent, generates the verifiable presentation with selective disclosure as appropriate.

### 6.1.5 Response Delivery

The wallet unit returns the OpenID4VP response via the DC API. The browser delivers it to the verifier's JavaScript context as the resolved value of the `navigator.credentials.get()` promise. The resolved value is a `DigitalCredential` object whose `protocol` attribute identifies the selected protocol. Its `data` attribute contains the OpenID4VP Authorization Response parameters. When `response_mode=dc_api.jwt`, `data.response` contains the encrypted JWT that encapsulates the Authorization Response. A wallet-generated protocol error is returned as `data.error`; such a protocol error still fulfils the DC API promise and therefore MUST be handled separately from API-level promise rejection.

### 6.1.6 Verifier Validation

The verifier validates the presentation response as specified in CS-002 §6.1.7 and OpenID4VP Appendix A, including:
- Decrypting and validating the encrypted Authorization Response when `response_mode=dc_api.jwt`
- Signature and proof verification
- Validation of response audience binding against `origin:<verifier-origin>`, rather than against the OpenID4VP `client_id`, where the credential format or proof uses an audience value
- Credential status checks
- Trust chain validation

## 6.2 Cross-device Presentation via Platform-mediated Transport

The DC API supports platform-mediated cross-device presentation. The particular transport and proximity mechanism are selected by the user agent or platform and are outside the scope of this specification; deployments commonly use CTAP-based mechanisms. This is architecturally distinct from the direct QR-based cross-device flow in CS-002 §6.2 because the verifier invokes the same DC API call and the browser or platform mediates the interaction with the remote wallet.

### 6.2.1 Verifier Constructs Presentation Request

The verifier constructs the OpenID4VP authorization request identically to §6.1.1. No changes to the request format are required for cross-device operation.

### 6.2.2 DC API Invocation and Platform Mediation

The verifier invokes the DC API exactly as in §6.1.2. The user agent or platform may offer a wallet on another device and is responsible for establishing an appropriate secure, proximity-aware channel. The verifier MUST NOT depend on a particular QR, BLE, CTAP, or tunnel implementation and receives no transport-specific protocol surface through the DC API.

### 6.2.3 Remote Wallet Processing

The remote wallet unit:
1. Receives the OpenID4VP request through the platform-mediated cross-device channel.
2. Validates and processes the request as specified in §6.1.4.
3. Returns the OpenID4VP response through the platform-mediated channel.

### 6.2.4 Response Delivery

The browser receives the response through the platform-mediated channel and delivers it to the verifier's JavaScript context as the resolved value of `navigator.credentials.get()`. From the verifier's perspective, the API request and response shape are the same as for a same-device response.

### 6.2.5 Verifier Validation

The verifier validates the response identically to §6.1.6.

## 6.3 Credential Issuance via DC API

The DC API supports credential issuance through `navigator.credentials.create()` [1] §7.4–7.6. The issuer's web page initiates the flow; the browser mediates wallet selection; the wallet then completes the OID4VCI exchange directly with the issuer's endpoints.

### 6.3.1 Issuer Constructs Credential Offer

The issuer constructs an OID4VCI credential offer as specified in CS-001. The offer is encoded as a JSON object suitable for the DC API.

### 6.3.2 DC API Invocation

The issuer invokes the DC API:

```javascript
const result = await navigator.credentials.create({
  digital: {
    requests: [{
      protocol: "openid4vci-v1",
      data: credentialOffer
    }]
  }
});
```

The `protocol` field MUST be set to `"openid4vci-v1"`. The `data` field contains the OID4VCI credential offer object.

### 6.3.3 Browser Mediation

The browser:
1. Identifies wallet units or credential managers available for the `"openid4vci-v1"` protocol.
2. Presents a wallet selection UI to the user.
3. Forwards the credential offer to the selected wallet unit.

### 6.3.4 Wallet Processing

The wallet unit:
1. Receives the credential offer via the DC API.
2. Initiates the standard OID4VCI flow with the issuer's endpoints (authorization, token, credential).
3. Stores the issued credential.
4. Returns a confirmation response via the DC API.

The DC API's role ends once the offer is delivered to the wallet. The remainder of the OID4VCI flow (authorization, token exchange, credential retrieval) proceeds as specified in CS-001, independent of the DC API.

### 6.3.5 Response Delivery

The wallet unit returns a response via the DC API. The browser delivers it to the issuer's JavaScript context as the resolved value of `navigator.credentials.create()`.

> **Pre-flight limitation:** The W3C Digital Credentials API Working Draft lists `"openid4vci-v1"` as an issuance protocol identifier, but the OpenID4VCI-to-DC-API integration is not yet normatively defined in OpenID4VCI 1.0. Accordingly, §6.3 and §7.3 are provisional WE BUILD conventions and require validation through implementation feedback before they can be treated as stable cross-vendor interoperability requirements.

# 7. Normative Requirements

## 7.1 Wallet Unit Requirements

| ID | Requirement | Reference |
|----|-------------|-----------|
| WU-DC-01 | The WU MUST be available to the user agent or platform as a credential manager capable of handling the `"openid4vp-v1-signed"` protocol. This requirement does not prescribe a platform registration or integration mechanism. | [1] §5 |
| WU-DC-02 | The WU MUST accept OpenID4VP authorization requests received via the DC API. | [1], [4] |
| WU-DC-03 | The WU MUST return OpenID4VP authorization responses via the DC API response mechanism. | [1], [4] |
| WU-DC-04 | The WU MUST support the same credential formats and selective disclosure mechanisms as required by CS-002 §7.1. | [2] |
| WU-DC-05 | The WU SHOULD support both DC API and `openid4vp://` invocation to ensure backward compatibility. | [2], [4] |
| WU-DC-06 | The WU SHOULD support cross-device presentation when the user agent or platform makes the WU available through a secure platform-mediated channel. No specific cross-device transport is mandated. | [1] §10.3 |
| WU-DC-07 | The WU SHOULD be available to the user agent or platform as a credential manager capable of handling the `"openid4vci-v1"` protocol, where issuance support is implemented. This requirement does not prescribe a platform registration or integration mechanism. | [1] §5 |
| WU-DC-08 | As a provisional WE BUILD convention, the WU MUST, upon receiving a credential offer via the DC API, initiate the standard OID4VCI flow with the issuer's endpoints as specified in CS-001. | [5] |
| WU-DC-09 | For a signed OpenID4VP request received via the DC API, the WU MUST compare the calling origin supplied by the user agent with the values in `expected_origins`. If no value matches, the WU MUST reject the request and SHOULD return an `invalid_request` error. | [4] Appendix A.2 |
| WU-DC-10 | When a response proof or credential-format-specific binding uses an audience value, the WU MUST bind the response to the verifier Origin, represented as `origin:<verifier-origin>`, and MUST NOT use the OpenID4VP `client_id` as that audience. | [4] Appendix A.4 |

## 7.2 Verifier Requirements

| ID | Requirement | Reference |
|----|-------------|-----------|
| VP-DC-01 | The Verifier MUST use `navigator.credentials.get()` with the `digital` options member when the DC API is available. | [1] §7.1 |
| VP-DC-02 | The Verifier MUST set the `protocol` field to `"openid4vp-v1-signed"` and MUST place the JWS Compact Serialization of the signed Authorization Request in the `request` member of the DC API `data` object. | [1] §5, [4] Appendix A.3.2.1 |
| VP-DC-03 | The Verifier MUST construct a valid OpenID4VP Authorization Request as specified in CS-002 §7.2 and OpenID4VP Appendix A. Where the DC API profile differs from a redirect-based flow, OpenID4VP Appendix A takes precedence. | [2], [4] Appendix A |
| VP-DC-04 | The Verifier SHOULD implement fallback to `openid4vp://` custom URL scheme or cross-device flow when the DC API is not available. | [2] |
| VP-DC-05 | The Verifier MUST call the DC API from a [secure context](https://w3c.github.io/webappsec-secure-contexts/) and in response to a user activation event. | [1] §8.1 |
| VP-DC-06 | The Verifier SHOULD support cross-device presentation through the same DC API invocation where the user agent or platform provides it. The Verifier MUST NOT require a specific cross-device transport. | [1] §10.3 |
| VP-DC-07 | The Verifier MUST set `response_type` to `vp_token` and `response_mode` to `dc_api.jwt` in the signed OpenID4VP Authorization Request. | [4] Appendix A.2, §8.3 |
| VP-DC-08 | The Verifier MUST include a non-empty `expected_origins` array in every signed OpenID4VP request sent through the DC API. The array MUST contain the origin from which the DC API call is made. | [4] Appendix A.2 |
| VP-DC-09 | The Verifier MUST validate any response audience binding against `origin:<verifier-origin>`, rather than against the OpenID4VP `client_id`, where the returned credential format or proof contains an audience value. | [4] Appendix A.4 |
| VP-DC-10 | The Verifier MUST process wallet-generated protocol errors returned in `DigitalCredential.data.error` independently from DC API promise rejection. | [4] Appendix A.4 |

## 7.3 Issuer Requirements

| ID | Requirement | Reference |
|----|-------------|----------|
| IS-DC-01 | The Issuer MUST use `navigator.credentials.create()` with the `digital` options member to initiate credential issuance when the DC API is available. | [1] §7.4 |
| IS-DC-02 | The Issuer MUST set the `protocol` field to `"openid4vci-v1"` in the DC API issuance request. | [1] §7.8.3 |
| IS-DC-03 | As a provisional WE BUILD convention, the Issuer MUST construct a valid OID4VCI credential offer as specified in CS-001 and pass that offer as the request `data` for the `"openid4vci-v1"` protocol. | [5] |
| IS-DC-04 | The Issuer MUST call the DC API from a [secure context](https://w3c.github.io/webappsec-secure-contexts/) and in response to a user activation event. | [1] §8.3 |
| IS-DC-05 | The Issuer SHOULD implement fallback to direct OID4VCI credential offer delivery (e.g. via QR code or deep link) when the DC API is not available. | [5] |

# 8. Conformance

A **Verifier** conforms to this specification if it satisfies all requirements in §7.2.

An **Issuer** conforms to this specification if it satisfies all requirements in §7.3.

A **Wallet Unit** conforms to this specification if it satisfies all requirements in §7.1.

Conformance testing for this pre-flight specification will be defined as part of the feedback process described in the [Pre-flight CS ADR](../adr/pre-flight-CS.md). Implementers are encouraged to report their testing experience to inform the development of a full conformance specification.

# References

| # | Reference |
|---|-----------|
| [1] | W3C, "Digital Credentials", W3C Working Draft, 15 July 2026, https://www.w3.org/TR/2026/WD-digital-credentials-20260715/ |
| [2] | WE BUILD, "Conformance Specification: Credential Presentation v1.1 (CS-002)", 2026 |
| [3] | W3C, "Credential Management Level 1", W3C Recommendation, https://www.w3.org/TR/credential-management-1/ |
| [4] | OpenID Foundation, "OpenID for Verifiable Presentations (OpenID4VP) 1.0", https://openid.net/specs/openid-4-verifiable-presentations-1_0.html |
| [5] | OpenID Foundation, "OpenID for Verifiable Credential Issuance (OID4VCI) 1.0", https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html |
