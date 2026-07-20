# CS-07 verifier API integration

The verifier backend exposes JSON endpoints for an RP application. The RP must
run the Digital Credentials API call in its own secure origin; the verifier does
not host the RP page or provide a browser script route.

## Configuration

Set `DC_API_CONFIG_PATH` if the deployment does not use the default
`data/dc-api-config.json`. Add the RP origin and the profiles it may request:

```json
{
  "default_profile": "pid-basic",
  "profiles": {
    "pid-basic": {
      "workflow": "presentation",
      "dcql_query": {
        "credentials": [
          {
            "id": "cmwallet",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eu.europa.ec.eudi:pid:1"] }
          }
        ]
      }
    }
  },
  "relying_parties": {
    "https://rp.example": { "profiles": ["pid-basic"] }
  }
}
```

Configuration is validated at verifier startup. Origins are canonical HTTPS
origins and are matched exactly. The checked-in configuration intentionally
authorizes no RP origins.

## Request lifecycle

The RP sends `POST /vp/dc-api/request` with the selected profile identifier and
the browser-generated `Origin` header. The response contains a signed request
descriptor, a response endpoint, a status endpoint, and an expiry timestamp.
The signed request uses `openid4vp-v1-signed`, `response_mode=dc_api.jwt`, and
`expected_origins` bound to the RP origin.

The RP posts only the returned `DigitalCredential`'s `protocol` and `data` to
`POST /vp/dc-api/response/:sessionId`. The same RP origin is required. Wallet
protocol errors are accepted as a fulfilled DC API result and are recorded as a
failed session; browser promise rejection is handled by the RP adapter.

Poll `GET /vp/dc-api/session/:sessionId` from the same origin for the sanitized
`pending`, `success`, or `failed` result. Request tokens, JWEs, decrypted VP
tokens, and claims are not returned by this endpoint.

The reusable browser-side adapter is documented in
`clients/dc-api/README.md` and implemented in `clients/dc-api/rp-client.js`.
