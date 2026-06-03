# wallet-client

## Wallet Provider identity (testing only)

This client uses **self-signed** attestation JWTs for development against the RFC issuer. **Do not use this key handling in production**—real deployments must use externally issued Wallet Provider and Wallet Instance material from a trusted source.

### Keys

- **Device / proof / DPoP key** — default file `data/device-key.json` (override with CLI `--key` or `WALLET_DEVICE_KEY_PATH`). Used only for DPoP, OpenID4VCI proof JWTs, OpenID4VP key-binding, and presentation flows. Persists after first run; delete the file to mint a new device key.
- **Wallet Provider key** — default file `data/wallet-provider-key.json` (override with `WALLET_PROVIDER_KEY_PATH`). A **separate** P-256 key used only for:
  - **WIA** (Wallet Instance Attestation) at PAR and Token: headers `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP` only (`typ: oauth-client-attestation+jwt` / `oauth-client-attestation-pop+jwt`). The client validates WIA `aud`, PoP `aud` (authorization server issuer), and `client_id` = WIA `sub` locally before each request (`wiaParTokenValidation.js`).
  - **WUA** (Wallet Unit Attestation) at Credential: `proofs.jwt` `key_attestation` or `proofs.attestation` (`typ: key-attestation+jwt`). Before dispatch, `wuaCredentialBinding.js` checks one proof/WUA, `attested_keys[0]` = proof signing key, and stable multi-key order.

The file is created on first use if missing. Rotate it independently of the device key. (If you previously used `walletprovider/ec-p256-es256.json`, copy or rename it to `data/wallet-provider-key.json`.)

### Identifiers

- **`iss`** on attestation JWTs is **`WALLET_PROVIDER_ID`** (env), or `wallet_provider_id` from `data/wallet-provider.json` (path override: `WALLET_PROVIDER_CONFIG`), or else a **`did:jwk`** derived from the Wallet Provider **public** key (default).
- **`sub`** on WIA and WUA is a stable **wallet instance id** per install: `WALLET_INSTANCE_ID` (env), else Redis key `wallet:instance_id`, else `walletprovider/instance-id.txt`. The same value is used as OAuth **`client_id`** on PAR and Token (`resolveWalletInstanceClientId`).
- **`scope`** on PAR/Token is taken from issuer metadata `credential_configurations_supported[<id>].scope` when present, else from the credential offer grant, else the configuration id (`scopeResolution.js`).

### External attestation (hook)

Set **`WALLET_USE_EXTERNAL_ATTESTATION=1`** and supply JWT strings to bypass self-signing for integration testing:

- `WALLET_EXTERNAL_OAUTH_ATTESTATION` — pre-minted WIA (`OAuth-Client-Attestation` header)  
- `WALLET_EXTERNAL_CLIENT_ASSERTION` — deprecated alias for `WALLET_EXTERNAL_OAUTH_ATTESTATION`  
- `WALLET_EXTERNAL_OAUTH_POP` — WIA PoP (`OAuth-Client-Attestation-PoP` header)  
- `WALLET_EXTERNAL_WUA` — pre-minted WUA for Credential proofs  

If all three WIA-related vars are set for token/PAR, self-signing for that exchange is skipped. If `WALLET_EXTERNAL_WUA` is set, WUA self-signing is skipped.
