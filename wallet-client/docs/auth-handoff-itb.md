# ITB Browser Auth Handoff (Headless Wallet)

This document describes how the wallet-client supports ITB+ authorization-code
issuance when login, consent, or MFA must run in the tester's browser while the
headless wallet remains the OAuth client.

## Flow

1. ITB calls `POST /session` with `deepLink`, `sessionId`, and `authHandoff: true`
   (or sets `WALLET_AUTH_HANDOFF=true`).
2. Wallet performs metadata discovery and PAR, persists PKCE/state, and returns:

```json
{
  "sessionId": "s1",
  "status": "AUTHORIZATION_REQUIRED",
  "authorizationUrl": "https://as.example/authorize?client_id=...&request_uri=...",
  "expiresAt": "2026-09-17T12:00:00.000Z"
}
```

3. ITB displays `authorizationUrl` for the tester to open in a browser tab.
4. After login/consent/MFA, the authorization server redirects to
   `{WALLET_OAUTH_REDIRECT_URI}` or `{WALLET_PROVIDER_URL}/oauth/callback` with
   `code` and `state`.
5. Wallet validates and consumes the pending transaction once, exchanges the code
   using the stored PKCE verifier, requests the credential, and updates the test
   session to `ok` or `failed`.
6. ITB polls `GET /session-status/:sessionId` until a terminal status is reached.

## Configuration

| Variable | Purpose |
| --- | --- |
| `WALLET_AUTH_HANDOFF` | Default-on for `/session` when `true` |
| `WALLET_OAUTH_REDIRECT_URI` | Explicit HTTPS callback (preferred when set) |
| `WALLET_PROVIDER_URL` | Public HTTPS base; callback defaults to `{base}/oauth/callback` |
| `WALLET_AUTH_HANDOFF_TTL` | Pending auth Redis TTL (seconds) |

Handoff requires an absolute **HTTPS** callback reachable from the tester's
browser. `localhost` callbacks are not suitable for remote ITB testers.

## API surface

| Endpoint | Role |
| --- | --- |
| `POST /session` | Start issuance; may return `AUTHORIZATION_REQUIRED` |
| `GET /oauth/callback` | Browser redirect target; HTML landing page |
| `GET /session-status/:sessionId` | Poll terminal `ok` / `failed` |
| `GET /logs/:sessionId` | Protocol diagnostics (codes redacted in form logs) |

## Out of scope

- Dynamic `openid4vp://?request_uri=…` identity proofing during authorization
  (separate wallet gap; see [VCI authorization-code matrix](../../docs/vci-authorization-code-wallet-matrix.md)).
- ITB scriptlet/TDL changes (upstream ITB orchestration).

## Implementation

- [`src/lib/authorizationCodeIssuance.js`](../src/lib/authorizationCodeIssuance.js) — `prepareAuthorization`, `completeAuthorization`
- [`src/lib/authHandoffConfig.js`](../src/lib/authHandoffConfig.js) — env and redirect URI resolution
- [`src/lib/authHandoffStore.js`](../src/lib/authHandoffStore.js) — Redis pending state and callback HTML
