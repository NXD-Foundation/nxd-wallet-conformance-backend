# wallet-client

## Wallet Provider identity (testing only)

This client uses **self-signed** attestation JWTs for development against the RFC issuer. **Do not use this key handling in production**—real deployments must use externally issued Wallet Provider and Wallet Instance material from a trusted source.

### Keys

- **Device / proof / DPoP key** — default file `data/device-key.json` (override with CLI `--key` or `WALLET_DEVICE_KEY_PATH`). Used only for DPoP, OpenID4VCI proof JWTs, OpenID4VP key-binding, and presentation flows. Persists after first run; delete the file to mint a new device key.
- **Wallet Provider key** — default file `data/wallet-provider-key.json` (override with `WALLET_PROVIDER_KEY_PATH`). A **separate** P-256 key used only for:
  - Signs **WIA** (Wallet Instance Attestation) at PAR and Token. The device key referenced in WIA `cnf.jwk` signs the PoP and DPoP proofs. Headers `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP` only (`typ: oauth-client-attestation+jwt` / `oauth-client-attestation-pop+jwt`). The client validates WIA `aud`, PoP `aud` (authorization server issuer), and `client_id` = WIA `sub` locally before each request (`wiaParTokenValidation.js`).
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


## OAuth callback for headless authorization-code tests

Configure the exact HTTPS callback registered for the wallet client at the authorization server:

```bash
export WALLET_OAUTH_REDIRECT_URI=https://your-wallet-domain/oauth/callback
```

This setting applies to both `/session` and `/issue-codeflow`, including blocking tests. Alternatively, `WALLET_PROVIDER_URL=https://your-wallet-domain` supplies the callback `${WALLET_PROVIDER_URL}/oauth/callback`. Explicit callback configuration takes precedence. Missing configuration, custom schemes, fragments, and URL credentials are rejected before authorization.

The selected callback string is retained unchanged through PAR, authorization, token exchange, and resumed handoff. Register that exact string in Keycloak; do not configure `openid4vp://` as the OAuth callback. OpenID4VP presentation links remain independent.

Blocking headless tests intercept the authorization response's redirect header and extract `code` and `state` without navigating to the callback, so they do not require a reachable callback endpoint. With `WALLET_AUTH_HANDOFF=true`, a browser follows the redirect and the callback must be reachable. Existing deployments that relied on a custom-scheme default must set the callback or provider URL before running authorization-code tests.

Issuers that redirect `/authorize` to a login page need that handoff. The session poll then carries `authorizationUrl` until the callback finishes. See [docs/auth-handoff-itb.md](./docs/auth-handoff-itb.md).

## DPoP nonce handling

The wallet captures `DPoP-Nonce` from successful responses and explicit nonce challenges. It retries AS HTTP 400 JSON `use_dpop_nonce` errors and resource-server HTTP 401 DPoP authentication challenges, including empty-body responses. Each retry creates a fresh signed DPoP proof using the original binding key, method, URI, and access-token hash. It permits at most two nonce retries and five sends per logical request when combined with attestation or provider-key rotation retries.

Nonce state belongs to the issuance transaction and confirmation key. AS and resource-server nonces remain separate even on the same origin; authorization handoff retains the binding and nonce state. The Nonce Endpoint's resource nonce is used at the Credential Endpoint independently of its JSON `c_nonce`. DPoP retries preserve the credential request body, credential proof/key attestation, and credential `c_nonce`. A fresh `c_nonce` is obtained from the Nonce Endpoint before credential proof construction, including when a legacy token response also contains `c_nonce`.

Nonce negotiation applies to PAR, token, nonce, credential, deferred credential, and DPoP-protected notification requests. Missing nonce headers, exhausted retries, and missing binding keys fail explicitly. Unrelated authentication failures are not retried, and the wallet does not downgrade a DPoP-bound request to Bearer.

### Credential key-attestation policy

In the default `compatibility` profile, JWT credential proofs include
`key_attestation` only when the selected credential configuration advertises
`proof_types_supported.jwt.key_attestations_required`. An empty object (`{}`)
still requires attestation. `webuild-cs01` retains the RFC001 mandatory
attestation policy even when that metadata field is absent. The `attestation`
proof type always carries key attestation directly.

Generated key attestations use an ES256 signing certificate chain in `x5c`,
without an embedded `jwk` header. Configure both `WALLET_WUA_SIGNING_KEY_PATH`
(PKCS#8 PEM private key) and `WALLET_WUA_SIGNING_CERT_PATH` (PEM chain, signing
certificate first), and mount these files into the service container. Incomplete,
missing, or mismatched signing material fails before the credential request.
When neither is configured, the existing local development certificate and key
are used. These fixtures do not establish trust with an external issuer: deploy
material whose chain that issuer accepts. External WUA tokens must also carry
`x5c` and verify under its first certificate; `jwk`-only WUA tokens are rejected.
