# ITB Browser Auth Handoff (Headless Wallet)

The wallet-client can run ITB+ authorization-code issuance while login, consent, or MFA happens in the tester's browser. The headless wallet stays the OAuth client. Handoff is opt-in. The default `/session` path still fetches `/authorize` and expects the authorization code on the first redirect.

Both modes use the same HTTPS `redirect_uri`: `WALLET_OAUTH_REDIRECT_URI`, or `${WALLET_PROVIDER_URL}/oauth/callback` when the explicit callback is unset. Custom schemes, fragments, and URL credentials are rejected before authorization starts.

## Handoff flow

1. ITB calls `POST /session` with `deepLink`, `sessionId`, and `authHandoff: true` (or the service is started with `WALLET_AUTH_HANDOFF=true`).
2. The wallet performs metadata discovery and PAR, persists PKCE and `state`, and does not call `/authorize`. It returns:

```json
{
  "sessionId": "s1",
  "status": "AUTHORIZATION_REQUIRED",
  "authorizationUrl": "https://as.example/authorize?client_id=...&request_uri=...",
  "expiresAt": "2026-09-17T12:00:00.000Z"
}
```

3. The same session is stored for polling. `GET /session-status/:sessionId` returns `authorizationUrl` while the status is `AUTHORIZATION_REQUIRED`.
4. ITB displays `authorizationUrl` for the tester to open in a browser tab.
5. After login, consent, or MFA, the authorization server redirects to the configured HTTPS callback with `code` and `state`.
6. `GET /oauth/callback` validates and consumes the pending transaction once, exchanges the code with the stored PKCE verifier, requests the credential, and updates the test session to `ok` or `failed`.
7. ITB polls `GET /session-status/:sessionId` until that terminal status.

The callback must be reachable from the tester's browser. A `localhost` callback is not suitable for a remote ITB tester. The reverse proxy must forward `/oauth/callback` to this service.

## Default path

When handoff is off, `POST /session` still uses the HTTPS `redirect_uri`, then fetches `/authorize` with redirects disabled. It treats the first `Location` as the authorization response and requires that URL to carry the wallet's `state` and a `code`.

That path completes issuers that redirect straight back with the authorization code. It does not follow an intermediate login page, submit credentials, or keep a browser session. A `Location` such as `/login` fails the session with `invalid_state: authorization response state mismatch` because that URL is not the authorization response. The callback endpoint does not need to be reachable for this path, because the wallet reads the redirect header and does not navigate to it.

Issuers that authenticate the user before issuing the code need the handoff flow above.

## Configuration

| Variable | Purpose |
| --- | --- |
| `WALLET_AUTH_HANDOFF` | When `true` or `1`, `/session` uses handoff unless the body sets `authHandoff: false` |
| `WALLET_OAUTH_REDIRECT_URI` | Explicit HTTPS callback, used for both modes |
| `WALLET_PROVIDER_URL` | Public HTTPS base; callback defaults to `{base}/oauth/callback` |
| `WALLET_AUTH_HANDOFF_TTL` | Pending authorization TTL in seconds, capped by PAR `expires_in` when present (default 600) |

A request body `authHandoff: true` or `authHandoff: false` overrides the environment variable for that call.

## API surface

| Endpoint | Role |
| --- | --- |
| `POST /session` | Start issuance. Handoff returns `AUTHORIZATION_REQUIRED` and `authorizationUrl` |
| `GET /session-status/:sessionId` | Poll the session, including `authorizationUrl` while authorization is pending, then `ok` or `failed` |
| `GET /oauth/callback` | Browser redirect target. Returns an HTML landing page |
| `GET /logs/:sessionId` | Protocol diagnostics |

## Out of scope

- Changing ITB scriptlets or TDL so a test opens `authorizationUrl`. The wallet publishes the URL; the test runner has to display it.
- Dynamic `openid4vp://` identity proofing during authorization.

## Implementation

- [`src/lib/authorizationCodeIssuance.js`](../src/lib/authorizationCodeIssuance.js) — `prepareAuthorization`, `completeAuthorization`
- [`src/lib/authHandoffConfig.js`](../src/lib/authHandoffConfig.js) — environment flag and redirect URI checks
- [`src/lib/authHandoffStore.js`](../src/lib/authHandoffStore.js) — Redis pending state and callback HTML
- [`src/server.js`](../src/server.js) — `POST /session`, `GET /session-status/:sessionId`, `GET /oauth/callback`
