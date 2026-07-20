# CS-07 Verifier API and RP Adapter Implementation Plan

Status: Phases 1–2 implemented; route-boundary coverage, shared response dispatch, and cryptographic encrypted-flow evidence added
Target: WE BUILD CS-07 v0.2, constrained by `docs/knowledge.md`
Scope: verifier backend plus a reusable RP-side browser adapter

## 1. Architecture decision

This repository is the verifier backend. It must not own an HTML page or invoke
`navigator.credentials.get()` on behalf of an RP. An RP page calls the backend
to obtain a signed request, invokes the Digital Credentials API in its own
origin, and posts the resulting `DigitalCredential` back to the backend.

CS-07 compliance is therefore split across two deliverables:

- the backend creates and verifies the OpenID4VP/DC API exchange;
- a standalone, dependency-free browser ESM module performs the RP-side API
  invocation and response forwarding.

The browser module is package-ready but is not published to npm in this phase.
It must not generate or sign VP requests; it only fetches a signed request from
the verifier and submits the browser result.

## 2. Verifier backend changes

### 2.1 Remove RP UI from the verifier

Remove the verifier-hosted `GET /vp/dc-api` HTML page and
`GET /vp/dc-api/browser.js`. Remove the embedded browser script and its DOM,
page-CSP, and button handling from `routes/verify`.

Retain only the protocol API endpoints:

- `POST /vp/dc-api/request`
- `POST /vp/dc-api/response/:sessionId`
- `GET /vp/dc-api/session/:sessionId`
- route-local `OPTIONS` handling for approved RP origins

The backend must return JSON descriptors, never HTML, QR codes, deep links, or
executable JavaScript on the DC API request endpoint.

### 2.2 Profile and RP-origin configuration

Add a verifier-owned JSON configuration, defaulting to
`data/dc-api-config.json` and overridable with `DC_API_CONFIG_PATH`:

```json
{
  "default_profile": "pid-basic",
  "profiles": {
    "pid-basic": {
      "workflow": "presentation",
      "dcql_query": { "credentials": [] }
    },
    "qualified-signing": {
      "workflow": "cs03-inline-signing",
      "dcql_query": { "credentials": [] }
    }
  },
  "relying_parties": {
    "https://rp.example": {
      "profiles": ["pid-basic", "qualified-signing"]
    }
  }
}
```

Profile IDs describe the RP use case, not protocol names such as `cs03`.
Normal new presentation profiles are added by configuration only. Specialized
workflows may have a named internal handler and remain explicitly allowlisted.

Validate the configuration at startup: canonical HTTPS origins, unique profile
IDs, valid DCQL objects, known workflows, a valid default profile, and valid
origin-to-profile references. HTTP is allowed only for loopback development
origins when `DC_API_ALLOW_HTTP=true`.

For every request, derive the RP origin from the HTTP `Origin` header, require
an exact configured match, and authorize the selected profile for that origin.
Never accept `expected_origins`, `rpOrigin`, DCQL, transaction data, or a client
selected session ID from JSON. Apply exact-origin CORS with `Vary: Origin` and
no credentials. Store the immutable session origin and
`expected_audience = origin:<rp-origin>`.

### 2.3 Request endpoint contract

`POST /vp/dc-api/request` accepts only a profile identifier:

```json
{ "profile": "pid-basic" }
```

The server generates the session ID, loads DCQL and workflow configuration,
and returns:

```json
{
  "sessionId": "...",
  "expiresAt": 1784300000,
  "request": {
    "protocol": "openid4vp-v1-signed",
    "data": { "request": "<compact-signed-JAR>" }
  },
  "responseEndpoint": "https://verifier.example/vp/dc-api/response/...",
  "statusEndpoint": "https://verifier.example/vp/dc-api/session/..."
}
```

The signed request must contain `response_type=vp_token`,
`response_mode=dc_api.jwt`, a non-empty `expected_origins` containing the RP
origin, the configured DCQL, a fresh nonce, and the existing CS-02 signing and
encryption metadata. It must omit redirect-only `state`, `response_uri`, and
redirect-flow audience claims.

Persist nonce, profile, RP origin, expected audience, DCQL, workflow, protocol,
creation/expiry timestamps, encryption-key information, and pending status
before returning the descriptor. Reject invalid configuration or persistence
failure before exposing a signed request.

### 2.4 Response and status endpoints

`POST /vp/dc-api/response/:sessionId` must:

- require the same HTTP origin recorded in the session;
- enforce pending, unexpired, single-use state;
- accept only the serialized `{ protocol, data }` envelope;
- distinguish fulfilled `data.error` wallet protocol errors from malformed or
  rejected browser calls;
- decrypt and strictly parse the `dc_api.jwt` response;
- enforce DCQL IDs and cardinalities;
- dispatch SD-JWT, mdoc, and configured specialized workflows through existing
  verification helpers;
- validate proof audiences as `origin:<rp-origin>`;
- preserve nonce, holder-key, signature, `sd_hash`, transaction-data, replay,
  and structural checks;
- persist only a sanitized success/failure receipt.

Never log or persist the JAR, JWE, decrypted `vp_token`, raw credentials, or
disclosed claims unless an existing specialized workflow explicitly requires a
result artifact. Redact DC API bodies in the global HTTP logger before logging.

`GET /vp/dc-api/session/:sessionId` must enforce the same origin binding and
return only status, profile, expiry, sanitized errors, verified credential IDs,
and a verification summary. It must never return request tokens, keys, JWE,
decrypted presentations, or claims.

Rename origin helpers/session fields where needed so the stored origin clearly
means the RP page origin, not `CONFIG.SERVER_URL`.

## 3. Standalone RP browser adapter

Create `clients/dc-api/rp-client.js` as a dependency-free ESM module, with a
README and a minimal browser integration example. Do not serve it from the
verifier and do not make it perform work automatically.

Public API:

```js
import { createDcApiVerifierClient } from "./rp-client.js";

const client = createDcApiVerifierClient({
  verifierBaseUrl: "https://verifier.example"
});

const prepared = await client.prepare({ profile: "pid-basic" });
button.addEventListener("click", () => client.present(prepared));
```

Required behavior:

- `isSupported()` checks secure context, `navigator.credentials.get`, and
  `DigitalCredential.userAgentAllowsProtocol("openid4vp-v1-signed")`.
- `prepare()` fetches and validates the signed descriptor but never invokes the
  DC API.
- `present()` invokes `navigator.credentials.get()` before its first `await`,
  then posts only `protocol` and `data` to the supplied response endpoint.
- Support `AbortSignal`, local single-use protection, and stable categories for
  unsupported API, insecure context, cancellation, permission/user activation,
  browser security, wallet protocol error, verifier rejection, and network
  failure.
- Do not log credential data, auto-run on page load, manipulate the DOM, or
  embed a verifier secret.
- Expose unsupported status so the RP can use its existing CS-02 fallback. Do
  not silently fall back after cancellation or wallet errors.

## 4. Tests and documentation

Add focused suites for:

- profile/configuration validation and origin-to-profile authorization;
- request descriptor claims, headers, CS-07 response mode, expected origins,
  omitted redirect fields, and stored session facts;
- CORS, origin mismatch, malformed envelopes, wallet errors, JWE/DCQL errors,
  expiry, replay, single-use, and sanitized status responses;
- SD-JWT, mdoc, specialized workflow, and origin-bound proof regression;
- adapter feature detection, user-activation timing, abort, double-submit,
  browser rejection categories, wallet error forwarding, and no-DOM operation;
- one complete encrypted SD-JWT flow and one mdoc structural flow.

Update `npm run test:cs07`, `docs/knowledge.md`, and this plan with the final
backend-versus-adapter requirement coverage. Preserve existing redirect/direct-
post CS-02 and CS-03 behavior.

## 5. Assumptions

- Multiple external RP origins are supported through an explicit allowlist.
- Origin-to-profile authorization is the access-control boundary; no browser
  secret is embedded in the adapter.
- Profile changes require verifier restart.
- The adapter is shared as source ESM now and can later be wrapped/published
  as an npm package without changing its public API.
- Automatic fallback generation is not added to the verifier API; each RP
  chooses and configures its existing fallback flow.
- Trust-framework decisions and credential data-model/rulebook validation remain
  outside this phase, as required by `docs/knowledge.md`.
