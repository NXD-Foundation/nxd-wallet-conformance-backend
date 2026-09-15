# CS-07 verifier API integration

The verifier backend exposes JSON endpoints for an RP application. The RP must
run the Digital Credentials API call in its own secure origin; the verifier does
not host the RP page or provide a browser script route.

## Configuration

Set `DC_API_CONFIG_PATH` if the deployment does not use the default
`data/dc-api-config.json`. Add the RP origin and the profiles it may request
in JSON, or for ephemeral origins (e.g. ngrok) set environment variables at
verifier startup:

```bash
DC_API_RP_ORIGINS=https://rp.example,https://rp2.example npm run dev
# optional; defaults to default_profile (pid-basic)
DC_API_RP_PROFILES=pid-basic,qualified-signing,ts12-dpc,ts12-dpc-pid,ts12-iban,ts12-iban-pid,ts12-user,ts12-user-pid,ts12-payment
```

`DC_API_RP_ORIGINS` and `DC_API_RP_PROFILES` both accept multiple values as
comma-separated strings or as a JSON array of strings (quote the JSON in the
shell). Every listed origin is authorized for the same profile list. A JSON
`relying_parties` map can give different origins different profiles.

Checked-in CS-07 profile identifiers:

| Profile | Workflow | Requested credentials |
| --- | --- | --- |
| `pid-basic` | presentation | PID `urn:eu.europa.ec.eudi:pid:1` |
| `qualified-signing` | cs03-inline-signing | CSC X.509 signing certificate |
| `ts12-dpc` | ts12-payment | DPC `https://webuildconsortium.eu/sca/sca-card-dpc/1.0` |
| `ts12-dpc-pid` | ts12-payment | DPC plus PID |
| `ts12-iban` | ts12-payment | IBAN `https://webuildconsortium.eu/sca/sca-iban/1.0` |
| `ts12-iban-pid` | ts12-payment | IBAN plus PID |
| `ts12-user` | ts12-payment | User `https://webuildconsortium.eu/sca/sca-user/1.0` |
| `ts12-user-pid` | ts12-payment | User plus PID |
| `ts12-payment` | ts12-payment | Alias of `ts12-dpc` |

JSON example:

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
The request may also include an optional caller-supplied `sessionId` (1–128
characters using letters, digits, `.`, `_`, `:` or `-`). If omitted, the
verifier generates a UUID. The chosen value is returned as `sessionId` and is
used consistently by the response and status endpoints.
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
