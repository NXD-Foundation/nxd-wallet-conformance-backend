# CS-07 DC API issuer implementation

Status: implemented as a pre-flight reference flow; native wallet interoperability remains unverified.

The issuer prepares a normal OpenID4VCI offer and presents its JSON object through `navigator.credentials.create()` with protocol `openid4vci-v1`. The wallet then uses the existing metadata, authorization, token, proof, credential and notification routes. Browser completion does not itself establish that the issuer issued a credential or that the wallet stored it.

## Current implementation

- `POST /vci/dc-api/offer` prepares one of three configured PID scenarios: pre-authorized, pre-authorized with transaction code, or authorization code. It returns the offer, DC API request descriptor, same-session deep-link/QR fallback, expiry, and a separate high-entropy status capability.
- Optional `credentials` selects one to sixteen unique, advertised SD-JWT configurations and supplies a JSON claims object for each. Preparation bounds the request and payload size, rejects issuer-owned claims, and persists per-configuration payloads before returning the offer. Configurations requiring issuer attestation and trust policy continue through the standard checks. Caller payloads for mdoc are rejected.
- `GET /vci/dc-api/offer/:id` returns the stored-selection equivalent offer used by the QR/deep-link fallback. `GET /vci/dc-api/session/:id` requires the bearer capability and exposes issuance progress without claim values.
- The shared credential route restricts DC API sessions to the configurations selected in the offer. It marks each successfully issued configuration in the session; wallet notification state is recorded separately.
- `createDcApiIssuerClient()` separates offer preparation from the user-activated browser call, reports support as supported/unsupported/unknown, keeps the status capability private, validates the descriptor and provides status reads. `/issuance` demonstrates browser invocation and the fallback.
- Offer preparation fails when the session cannot be confirmed in Redis. The issuer origin and explicitly configured demo origins are enforced for browser requests. DC API request/response bodies and status authorization headers are redacted from general HTTP logs.

Example preparation:

```json
{
  "scenario": "pid-pre-authorized",
  "credentials": [
    {
      "credential_configuration_id": "VerifiablePortableDocumentA2SDJWT",
      "payload": { "booking_reference": "REF-123", "hotel_name": "Example Hotel" }
    }
  ]
}
```

Use `prepare()` before the user action and call `create(prepared, { signal })` directly from the click handler. Then use `getStatus(prepared)` to read server-observed progress. The implementation does not add a native wallet provider to `wallet-client`; that client remains useful for exercising the issuer’s ordinary OID4VCI endpoints.

## Interoperability and remaining scope

The current W3C Digital Credentials draft lists `openid4vci-v1` but still marks the OpenID4VCI API integration as “Coming Soon.” Automated browser stubs establish adapter behavior only. Record browser/OS/wallet versions, provider registration, request and response shapes, and promise timing before claiming native support.

Multiple configurations may be placed in one offer and requested individually through ordinary credential requests. This does not add a batch credential endpoint or multi-proof flow. Deferred issuance, mdoc caller payloads, cross-device acceptance, and native provider registration remain follow-up work. Any profile or wire-shape discrepancy must be resolved against the normative CS-07 and OpenID4VCI documents before changing the implementation.
