# CS-03 Verifier Flow Summary

This document summarizes the CS-03 remote signing flow as implemented in this verifier, including:

- how to generate a signing request
- the difference between inline and out-of-band (OOB) response delivery
- what the wallet is expected to return
- how `documentWithSignature` differs from `signatureObject`
- which parts are verifier responsibilities vs wallet responsibilities

## Overview

The verifier supports CS-03 style remote signing by generating an OpenID4VP request that contains:

- a `dcql_query` requesting a CSC X.509 signing credential
- a `transaction_data` entry containing a base64url-encoded CSC `qesRequest`

The signing credential requested by this verifier is:

- credential id: `signing-cert-01`
- format: `https://cloudsignatureconsortium.org/2025/x509`

The `qesRequest` references a PDF document hosted by the verifier at:

- `GET /x509/cs03-document`

## How To Generate A Signing Request

### Inline mode

Generate a CS-03 VP request:

```http
GET /x509/generateVPRequestDCQL?cs03=1
```

This creates a VP request where the wallet is expected to return the signing result inline in `vp_token`.

### OOB mode

Generate a CS-03 VP request with out-of-band callback delivery:

```http
GET /x509/generateVPRequestDCQL?cs03=1&cs03_oob=1
```

This creates a VP request where the `qesRequest` includes a `responseURI`, and the wallet is expected to POST the signed output to that callback endpoint.

## Inline Flow

### Steps

1. The RP/verifier generates a VP request:

```http
GET /x509/generateVPRequestDCQL?cs03=1
```

2. The wallet resolves the OpenID4VP request.

3. The wallet reads `transaction_data[0]`, base64url-decodes it, and obtains the CSC `qesRequest`.

4. The wallet downloads the document to be signed:

```http
GET /x509/cs03-document
```

5. The user approves the signing operation in the wallet.

6. The wallet completes the OpenID4VP response by POSTing to:

```http
POST /direct_post/:sessionId
```

7. In inline mode, the wallet returns the signing output directly inside `vp_token`.

### Inline `vp_token` shape

Example using `documentWithSignature`:

```json
{
  "signing-cert-01": {
    "qes": {
      "documentWithSignature": ["...base64..."]
    }
  }
}
```

Example using `signatureObject`:

```json
{
  "signing-cert-01": {
    "qes": {
      "signatureObject": ["...base64..."]
    }
  }
}
```

### Verifier behavior

In inline mode, the verifier expects:

- `vp_token` to be a JSON object
- the expected credential id to be present: `signing-cert-01`
- the credential response to contain `qes`
- `qes` to contain exactly one of:
  - `documentWithSignature`
  - `signatureObject`

The verifier rejects:

- unexpected credential ids
- missing expected credential ids
- empty credential responses in inline mode
- `qes` objects that contain both `documentWithSignature` and `signatureObject`

## OOB Flow

OOB means the signed artifact is delivered separately using `responseURI`, rather than being carried inline in `vp_token`.

### Steps

1. The RP/verifier generates a VP request:

```http
GET /x509/generateVPRequestDCQL?cs03=1&cs03_oob=1
```

2. The verifier includes a callback URL in:

- `qesRequest.signatureRequests[0].responseURI`

3. The wallet resolves the OpenID4VP request.

4. The wallet decodes `transaction_data[0]` and reads the `qesRequest`.

5. The wallet downloads the document:

```http
GET /x509/cs03-document
```

6. The user approves the signing operation.

7. The wallet sends the actual signed output to:

```http
POST /x509/qes-callback/:sessionId?callback_token=...
```

8. The wallet also completes the OpenID4VP response:

```http
POST /direct_post/:sessionId
```

9. In OOB mode, the wallet is expected to return an empty credential response in `vp_token` for the signing credential.

### OOB `vp_token` shape

```json
{
  "signing-cert-01": {}
}
```

### OOB callback body

Example:

```json
{
  "documentWithSignature": ["...base64..."]
}
```

or

```json
{
  "signatureObject": ["...base64..."]
}
```

### Verifier behavior

For OOB mode, the verifier:

- generates a per-session callback token
- embeds that token in the `responseURI`
- accepts callback delivery only when:
  - the session is marked CS-03
  - the session is marked OOB
  - the callback token matches
- validates the callback body shape before storing it

For the corresponding `direct_post`, the verifier expects:

- the expected credential id to be present
- the credential response to be empty: `{}`

The verifier rejects:

- inline `qes` data in OOB mode
- non-empty credential responses in OOB mode
- callbacks for sessions not configured for CS-03 OOB
- callbacks with invalid or missing callback token

## What Makes A Request OOB

Only this query parameter:

```http
cs03_oob=1
```

Without `cs03_oob=1`, the wallet must return the signing result inline in `vp_token`.

With `cs03_oob=1`, the verifier generates:

- a `responseURI`
- a callback token
- OOB session state

## `documentWithSignature` vs `signatureObject`

These are two different ways for the wallet to return the signing result.

### `documentWithSignature`

This means the wallet returns the final signed document.

For example:

- the original PDF, already signed as a PAdES-style document

This is the most natural output when the RP wants the final signed file.

Practical meaning:

- "Here is the completed signed PDF/document."

### `signatureObject`

This means the wallet returns signature material only, not the final signed document.

This is more typical when:

- the signing backend returns signature data only
- another component is expected to assemble the final artifact

Practical meaning:

- "Here is the signature data, not the final packaged signed document."

### Important note

The verifier accepts either:

- `documentWithSignature`
- `signatureObject`

but not both at once.

## Is The Wallet Free To Choose PAdES vs CAdES

Not in the general sense.

The current verifier request strongly indicates a PDF/PAdES-style flow because it asks for:

- `signature_format: "P"`
- a PDF document
- `conformance_level: "AdES-B-B"`

So the request is driving the intended signing profile.

What the wallet may still choose is the response representation:

- return the final signed document as `documentWithSignature`
- return signature material as `signatureObject`

So the distinction is:

- signing profile: driven by the request
- response packaging: often chosen by the wallet/backend unless the profile constrains it more tightly

## Expected Happy Path For This Verifier

For the current sample flow:

- the input document is a PDF
- the request uses `signature_format: "P"`

That makes `documentWithSignature` the most natural expected result.

The verifier still accepts `signatureObject` for interoperability, but the request is clearly aimed at the `P` path.

## Verifier-Side Safety Validation For OOB

The verifier now enforces that the generated `responseURI` host must match:

- the verifier `SERVER_URL` host
- the `x509_san_dns:<host>` client_id host

This is a verifier-side safeguard so the verifier does not generate unsafe OOB requests.

This does not replace wallet-side validation. A wallet unit should still verify that the `responseURI` is controlled by the authenticated RP according to its own conformance rules.

## Verifier Tests Added

The verifier test suite includes CS-03 unit tests for:

- `responseURI` placement under `signatureRequests[0]`
- valid inline response handling
- invalid credential id rejection
- missing `qes` rejection in inline mode
- empty credential response acceptance only for OOB mode
- invalid inline payload rejection in OOB mode
- callback payload validation
- `responseURI` host alignment with:
  - `SERVER_URL`
  - `x509_san_dns` client_id

These are verifier tests. They validate:

- what the verifier generates
- what the verifier accepts
- what the verifier rejects

They are not wallet conformance tests.
