# Plan: select the CS-02 invocation scheme in request generation

Status: implemented in the reference backend working tree, 12 October 2026.
The steps below retain the implementation scope and regression requirements.
Confirm the deployed build before running catalogue cases.

## API contract

Add optional query parameter `invocation_scheme` to CS-02 URI-based VP generation endpoints. Accepted values are exactly `openid4vp`, `eu-eaap`, and `haip-vp`, without `:` or `://`. When omitted, default to `openid4vp`. Reject empty, repeated, non-string, or unsupported values with HTTP 400 and `error: "invalid_request"`; do not silently replace an invalid value with the default.

The selected scheme controls **both** the primary `deepLink` and the contents of `qr`. A test caller supplies one scheme and receives the request/QR it should show to the wallet. No client-side selection or QR re-encoding is required.

Example:

```http
GET /x509/generateVPRequestDCQL?sessionId=<uuid>&response_mode=direct_post.jwt&invocation_scheme=eu-eaap
```

Trust cases additionally pass `trustFramework=true`. Response:

```json
{
  "sessionId": "<uuid>",
  "qr": "data:image/PNG;base64,<QR encoding the eu-eaap deepLink>",
  "deepLink": "eu-eaap://?request_uri=...&client_id=...&request_uri_method=post"
}
```

The existing `deepLinks` map may remain as a backward-compatible supplemental field. It is no longer the selection mechanism and is not required by the new suite cases. Existing clients omitting the parameter continue receiving an OpenID4VP link and QR.

## Implementation scope

1. Add a shared resolver/validator adjacent to `CS02_INVOCATION_SCHEMES` / `buildCs02InvocationRequestUrl` in `utils/cs02VerifierRequest.js`. Distinguish omission from an invalid supplied value. Validate route input before storing a session or signing a JAR.
2. Pass `req.query.invocation_scheme` through URI-based generation handlers, including `routes/verify/x509Routes.js`, `mdlRoutes.js`, and `vpStandardRoutes.js`. Apply the same selection to TS-12 URI-based generation (`ts12PaymentRoutes.js`, query/body), and remaining URI route families that call `generateVPRequest`. For TS-12, reject conflicting body/query values; accept a single valid supplied value. Keep the parameter name consistent.
3. Add `invocationScheme` to `generateVPRequest` inputs and thread it through `createOpenID4VPRequestUrl` to the existing shared URI builder. Build `vpRequest` with the selected scheme, then generate its QR from that exact string. Return it as `deepLink`.
4. Preserve empty authority, request URI, hash identity, query encoding, advertised GET/POST retrieval, session bindings, signing policy, and response mode. Selection is a URI transport change; it does not change the JAR's identity or CS-03 signing rules.
5. Handle validation errors as HTTP 400 at route boundaries rather than generic 500 responses. Use a consistent `invalid_request` body and useful description.
6. In compatibility mode, existing legacy OpenID4VP behavior may remain for omitted/default `openid4vp`. An explicit `eu-eaap`/`haip-vp` selection must emit the selected empty-authority scheme rather than being overridden by `openid4vp://present`. Preserve CS-03 SAN DNS/plaintext behavior and do not enable legacy authorities on the new schemes.
7. CS-07 DC API endpoints must not use this parameter to construct custom invocation URIs. Reject a supplied `invocation_scheme` as inapplicable with HTTP 400; retain browser request descriptors and origin bindings.
8. Update `docs/knowledge.md`, `docs/vp-verification-wallet-matrix.md`, and the test-suite handoff to describe the implemented behavior.

## Regression coverage

- Shared validation: omitted default, three valid values, empty/unknown/repeated/invalid-type values.
- Route generation for all three selections: HTTP 200; `deepLink` scheme matches input; decode QR and assert exact equality with `deepLink`. Use meaningful QR decoding, not only a non-empty image assertion.
- GET and POST invocation query preservation and successful JAR retrieval with the published hash; POST wallet nonce remains bound.
- Omitted parameter retains default OpenID4VP behavior and existing response shape.
- Invalid selection returns 400 and does not leave an active stored session.
- Trust-enabled generation retains policy and selected scheme.
- Explicit alternate selection works in compatibility mode; legacy OpenID4VP behavior remains separately covered.
- CS-03 identity/response mode and DC API transport are unchanged; DC API rejects the inapplicable parameter.

Run the new tests and nearest generation/signing/wallet suites. The suite handoff depends on this backend API being available in the deployed reference verifier. Generator and Java service refactoring remains a separate sprint; current Java `getcredentialrequestallparams` can already forward the query parameter.
