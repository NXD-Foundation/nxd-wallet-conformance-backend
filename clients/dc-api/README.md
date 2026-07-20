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

1. Add the **RP** ngrok HTTPS origin to `data/dc-api-config.json` →
   `relying_parties` (e.g. `"https://rp-xxxx.ngrok-free.app": { "profiles": ["pid-basic"] }`) and restart the verifier.
2. Open the RP ngrok URL on your phone (`/` redirects to the demo).
3. Paste your **verifier** ngrok base URL into the form (or use
   `?verifier=https://…&profile=pid-basic`).
4. Tap **Present credential** (user activation is required for DC API).
