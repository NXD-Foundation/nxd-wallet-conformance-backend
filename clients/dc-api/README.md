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
