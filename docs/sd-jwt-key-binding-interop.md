# SD-JWT Key Binding Interop Fixes

This note captures the fixes for the WE BUILD Issuer VP 1.0 interoperability issue where the wallet-client presented a credential with a Key Binding JWT signed by a different key than the one in the credential `cnf.jwk`.

## Scope

The changes cover:

1. Wallet-client presentation key selection
2. Local verifier validation for SD-JWT key binding

## Symptom

In `Test case 002: WE BUILD Issuer VP 1.0`, the received SD-JWT presentation had:

- a credential containing `cnf.jwk`
- a KB-JWT whose protected header `jwk` was a different holder key

That means the presentation proved possession of a key, but not the key the issuer bound into the credential during issuance.

## Root Cause

The wallet-client stored issuance key-binding material with the credential, but the presentation flow did not consistently reuse it.

During presentation, `wallet-client/src/lib/presentation.js` loaded key material from the device key file (`wallet-client/data/device-key.json` by default) and used that key to sign the KB-JWT. If the device key differed from the issuance key bound in `cnf.jwk`, the KB-JWT signer key diverged from the credential.

On the `aptitude` branch, multi-credential (DCQL) flows also need the key from the **picked** wallet entry (`pickedEntry.keyBinding`), not only top-level `stored.keyBinding`.

## Wallet Fix

The wallet-client now resolves presentation key material using this priority:

1. `pickedEntry.keyBinding` (DCQL / multi-entry presentations on `aptitude`)
2. `stored.keyBinding` (single stored credential)
3. request `keyPath` / default device key file
4. generated fallback key

For normal issued credentials, the first applicable option is used, so the KB-JWT is signed with the same key that the issuer bound into `cnf.jwk`.

Files:

- `wallet-client/src/lib/presentation.js`
- `wallet-client/src/lib/presentationKeyBinding.js`
- `wallet-client/test/presentationKeyBinding.test.js`

## Verifier Fix

The local verifier now validates SD-JWT key binding in addition to the existing nonce and audience checks, and it rejects presentations when the KB-JWT cannot be associated with a presented SD-JWT.

For SD-JWT presentations with a KB-JWT, it verifies:

- KB-JWT `nonce` matches the VP request nonce
- KB-JWT `aud` matches verifier `client_id`
- KB-JWT `sd_hash` matches the presented SD-JWT
- KB-JWT signature verifies with the public key in the credential `cnf.jwk`

Optional `jwk` in the KB-JWT protected header is not required; verification uses `cnf.jwk` from the issuer-signed SD-JWT per SD-JWT VC / RFC 9901.

On `aptitude`, failures are returned via `sendVerifierRfc002Error` with `VErr.FAILED_VALIDATION` or `VErr.MISSING_REQUIRED_PROOF` as appropriate.

Files:

- `routes/verify/verifierRoutes.js`
- `utils/sdJwtKeyBinding.js`
- `tests/sdJwtKeyBinding.test.js`

## Expected Failure

If a wallet presents an SD-JWT whose KB-JWT is signed with a different key than the credential `cnf.jwk`, the local verifier now rejects it with a message such as:

`Key Binding JWT signature does not verify with credential cnf.jwk`

Other key-binding failures return more specific errors, for example a missing `cnf.jwk` or an invalid KB-JWT signature.

## Validation

Run the focused tests directly with Mocha:

```bash
npx mocha tests/sdJwtKeyBinding.test.js wallet-client/test/presentationKeyBinding.test.js
```

Syntax checks:

```bash
node --check utils/sdJwtKeyBinding.js
node --check tests/sdJwtKeyBinding.test.js
node --check routes/verify/verifierRoutes.js
node --check wallet-client/src/lib/presentationKeyBinding.js
```
