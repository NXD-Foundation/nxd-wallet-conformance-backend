# wallet-client

## Wallet Provider identity (testing only)

This client uses **self-signed** attestation JWTs for development against the RFC issuer. **Do not use this key handling in production**—real deployments must use externally issued Wallet Provider and Wallet Instance material from a trusted source.

### Keys

- **Device / proof / DPoP key** — default file `data/device-key.json` (override with CLI `--key` or `WALLET_DEVICE_KEY_PATH`). Used only for DPoP, OpenID4VCI proof JWTs, OpenID4VP key-binding, and presentation flows. Persists after first run; delete the file to mint a new device key.
- **Wallet Provider key** — default file `data/wallet-provider-key.json` (override with `WALLET_PROVIDER_KEY_PATH`). A **separate** P-256 key used only for:
  - OAuth Client Attestation (`OAuth-Client-Attestation` / `client_assertion` at the token endpoint and PAR): `typ: oauth-client-attestation+jwt`
  - OAuth Client Attestation PoP (`OAuth-Client-Attestation-PoP`)
  - Wallet Unit Attestation (WUA in the proof JWT `key_attestation` header): `typ: key-attestation+jwt`

The file is created on first use if missing. Rotate it independently of the device key. (If you previously used `walletprovider/ec-p256-es256.json`, copy or rename it to `data/wallet-provider-key.json`.)

### Identifiers

- **`iss`** on attestation JWTs is **`WALLET_PROVIDER_ID`** (env), or `wallet_provider_id` from `data/wallet-provider.json` (path override: `WALLET_PROVIDER_CONFIG`), or else a **`did:jwk`** derived from the Wallet Provider **public** key (default).
- **`sub`** on OAuth client attestation and WUA is a stable **wallet instance id** per install: `WALLET_INSTANCE_ID` (env), else Redis key `wallet:instance_id`, else `walletprovider/instance-id.txt`.

### External attestation (hook)

Set **`WALLET_USE_EXTERNAL_ATTESTATION=1`** and supply JWT strings to bypass self-signing for integration testing:

- `WALLET_EXTERNAL_CLIENT_ASSERTION` — jwt-bearer body at token/PAR  
- `WALLET_EXTERNAL_OAUTH_ATTESTATION` — `OAuth-Client-Attestation` header  
- `WALLET_EXTERNAL_OAUTH_POP` — `OAuth-Client-Attestation-PoP` header  
- `WALLET_EXTERNAL_WUA` — WUA in the proof `key_attestation` header  

If all three OAuth-related vars are set for token/PAR, self-signing for that exchange is skipped. If `WALLET_EXTERNAL_WUA` is set, WUA self-signing is skipped.
