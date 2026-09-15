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

For a CS-12 SCA payment presentation, pass one of `ts12-dpc`, `ts12-iban`,
or `ts12-user` (one SCA attestation) or the matching `*-pid` profile (that
attestation plus the default PID `urn:eu.europa.ec.eudi:pid:1`) and a
`payment` object. The adapter flattens those fields onto the request body
(`amount`, `currency`, payee, `transaction_id`):

```js
const prepared = await client.prepare({
  profile: "ts12-dpc",
  payment: {
    amount: "12.34",
    currency: "EUR",
    merchant: "Demo Merchant",
    payee_id: "merchant-001",
    transaction_id: "tx-12345",
  },
});
```

## Local phone demo

A fake RP page lives at `demo/index.html`. Serve it with the zero-dependency
static server (default port **4173**, not the verifier’s 3000):

```bash
npm run dc-api:demo
# or: DC_API_DEMO_PORT=4173 node clients/dc-api/serve.js
```

The issuer-side pre-flight page is available at `/issuance`. It prepares an
OID4VCI offer and invokes `navigator.credentials.create()` with
`openid4vci-v1` when the browser supports it. The page also shows the
equivalent QR/deep-link fallback. Browser handoff does not prove that a wallet
stored the credential; inspect the returned session status and normal issuer
flow.

When the page is served by the separate static demo server, point its Issuer
URL field at the issuer and allow the demo origin on the issuer, for example:

```bash
DC_API_ISSUER_ORIGINS=https://demo.example node server.js
```

Then tunnel that port separately:

```bash
ngrok http 4173
```

1. Authorize the **RP** origin on the verifier and restart it.
   For a single ngrok tunnel (verifier + demo page), set `DC_API_RP_ORIGINS` to
   that verifier HTTPS origin and open `/payment` or `/demo` on it:
   ```bash
   DC_API_RP_ORIGINS=https://verifier-xxxx.ngrok-free.app \
     DC_API_RP_PROFILES=pid-basic,qualified-signing,ts12-dpc,ts12-dpc-pid,ts12-iban,ts12-iban-pid,ts12-user,ts12-user-pid,ts12-payment npm run dev
   ```
   For a **separate** RP origin, serve `npm run dc-api:demo`, tunnel port 4173,
   and authorize *that* HTTPS origin instead.
   Stable origins can stay in `data/dc-api-config.json` → `relying_parties`.
2. Open `/payment` (SCA payment) or `/demo` (PID) on the authorized origin.
3. If the page is not on the verifier, paste your **verifier** ngrok base URL
   into the form (or use `?verifier=https://…`).
4. Tap **Present credential** or **Authorize payment** (user activation is
   required for DC API).
