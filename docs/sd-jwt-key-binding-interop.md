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

During presentation, `wallet-client/src/lib/presentation.js` generated or loaded key material from `keyPath` and used that key to sign the KB-JWT. If `keyPath` was omitted, changed between test case 001 and 002, or otherwise differed from the issuance key, the KB-JWT signer key diverged from the credential `cnf.jwk`.

## Wallet Fix

The wallet-client now resolves presentation key material using this priority:

1. `stored.keyBinding.privateJwk` / `stored.keyBinding.publicJwk`
2. request `keyPath`
3. generated fallback key

For normal issued credentials, the first option is used, so the KB-JWT is signed with the same key that the issuer bound into `cnf.jwk`.

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
- KB-JWT signature verifies with the public JWK in the KB-JWT protected header
- KB-JWT protected header `jwk` matches the credential `cnf.jwk`

Files:

- `routes/verify/verifierRoutes.js`
- `utils/sdJwtKeyBinding.js`
- `tests/sdJwtKeyBinding.test.js`

## Expected Failure

If a wallet presents an SD-JWT whose KB-JWT is signed with a different key than the credential `cnf.jwk`, the local verifier now rejects it with:

`invalid_key_binding_jwt`

and an error indicating:

`Key Binding JWT signer key does not match credential cnf.jwk`

Other key-binding failures now return more specific errors, for example a missing `cnf.jwk`, a missing header `jwk`, or an invalid KB-JWT signature.

## Validation

Run the focused tests directly with Mocha:

```bash
npx mocha tests/sdJwtKeyBinding.test.js wallet-client/test/presentationKeyBinding.test.js
```

Validation in this environment also included:

```bash
node --check utils/sdJwtKeyBinding.js
node --check tests/sdJwtKeyBinding.test.js
node --check routes/verify/verifierRoutes.js
```
