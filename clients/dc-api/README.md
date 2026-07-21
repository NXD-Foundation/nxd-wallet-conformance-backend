# CS-07 RP Digital Credentials API adapter

This dependency-free ESM module is for the RP page that calls the verifier
backend. It fetches a verifier-generated signed request, invokes
`navigator.credentials.get()` from a user-activation handler, and forwards the
serialized `DigitalCredential` to the verifier. It does not create or sign a
VP request.

Call `prepare()` before the user action, then call `present()` directly from the
button/click handler. Configure the RP origin in the verifier's CS-07 profile
configuration and use the existing OpenID4VP fallback when `isSupported()` is
false.

```html
<button id="present" type="button">Present credential</button>
<script type="module">
  import { createDcApiVerifierClient } from "/path/to/rp-client.js";

  const client = createDcApiVerifierClient({
    verifierBaseUrl: "https://verifier.example"
  });
  const button = document.querySelector("#present");
  const prepared = await client.prepare({ profile: "pid-basic" });

  button.addEventListener("click", async () => {
    try {
      const result = await client.present(prepared);
      console.log("Verifier result", result.status);
    } catch (error) {
      console.error(error.code, error.message);
    }
  });
</script>
```

The RP may provide its own correlation identifier when preparing a request:

```js
const prepared = await client.prepare({
  profile: "pid-basic",
  sessionId: "booking-12345"
});
```

The verifier accepts 1–128 safe path characters (`A-Z`, `a-z`, digits, `.`,
`_`, `:`, `-`). If omitted, it generates a UUID.

## Local phone demo

A fake RP page lives at `demo/index.html`. Serve it with the zero-dependency
static server (default port **4173**, not the verifier’s 3000):

```bash
npm run dc-api:demo
# or: DC_API_DEMO_PORT=4173 node clients/dc-api/serve.js
```

Then tunnel that port separately:

```bash
ngrok http 4173
```

1. Authorize the **RP** ngrok HTTPS origin on the verifier and restart it.
   For local ngrok URLs, set `DC_API_RP_ORIGINS` (comma-separated) when starting
   the verifier; optional `DC_API_RP_PROFILES` defaults to `pid-basic`:
   ```bash
   DC_API_RP_ORIGINS=https://rp-xxxx.ngrok-free.app npm run dev
   ```
   Stable origins can stay in `data/dc-api-config.json` → `relying_parties`.
2. Open the RP ngrok URL on your phone (`/` redirects to the demo).
3. Paste your **verifier** ngrok base URL into the form (or use
   `?verifier=https://…&profile=pid-basic`).
4. Tap **Present credential** (user activation is required for DC API).
