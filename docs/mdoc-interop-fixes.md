# mdoc Interop Fixes

This note captures two mdoc interoperability bugs fixed in this branch so they can be checked and ported to other branches consistently.

## Scope

The fixes cover:

1. Issuer metadata for PID `mso_mdoc`
2. Wallet-client mdoc presentation for OpenID4VP / HAIP

## Bug 1: PID `mso_mdoc` Issuer Metadata

### Symptom

Wallets rejected the issuer metadata for credential configuration id:

`urn:eu.europa.ec.eudi:pid:1:mso_mdoc`

The advertised `credential_metadata.claims[].path` values did not follow mdoc claims path rules.

### Root Cause

The metadata endpoint serves `data/issuer-config.json` directly, and the PID mdoc entry still used an older grouped shape:

- namespace group path: `["urn:eu.europa.ec.eudi:pid:1"]`
- nested child claim paths: `["given_name"]`

### Required Behavior

For `mso_mdoc`, issuer metadata `claims` must be an array of claims description objects, and each mdoc path must contain at least:

- namespace
- element identifier

Example:

```json
{
  "path": ["urn:eu.europa.ec.eudi:pid:1", "given_name"]
}
```

The PID mdoc `doctype` must be the document identifier:

`urn:eu.europa.ec.eudi:pid:1`

not the format-suffixed configuration id.

### Files Changed

- [data/issuer-config.json](/home/ni/code/js/rfc-issuer-v1/data/issuer-config.json:1276)
- [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:1014)
- [tests/metadataDiscovery.test.js](/home/ni/code/js/rfc-issuer-v1/tests/metadataDiscovery.test.js:2490)

### Validation

```bash
npm test -- tests/metadataDiscovery.test.js tests/routeUtils.test.js
```

## Bug 2: Wallet-Client mdoc Presentation

### Symptom

Verifiers reported that the wallet-client submitted an invalid mdoc presentation because:

- `deviceSigned` was missing
- the payload effectively behaved like an `issuerSigned` wrapper, not a proper OpenID4VP mdoc `DeviceResponse`
- verifier parsing / verification failed

### Root Cause

The wallet-client was constructing an ad hoc `DeviceResponse` wrapper around `issuerSigned` but explicitly omitted `deviceSigned` / `deviceAuth`.

### Required Behavior

For mdoc presentation in OpenID4VP / HAIP:

- `vp_token` must be a base64url-encoded `DeviceResponse`
- the `DeviceResponse` must include `deviceSigned.deviceAuth`
- `deviceAuth` must be bound to the OpenID4VP session transcript
- issuer-provided `issuerSigned` content, including `issuerAuth` chain metadata, must remain intact

### Fix Implemented

The wallet-client now builds a real signed mdoc `DeviceResponse` using `@animo-id/mdoc`.

### Files Changed

- [wallet-client/src/lib/presentation.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/presentation.js:1248)
- [wallet-client/utils/mdlVerification.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/utils/mdlVerification.js:314)
- [wallet-client/utils/mdocContext.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/utils/mdocContext.js:1)
- [wallet-client/package.json](/home/ni/code/js/rfc-issuer-v1/wallet-client/package.json:9)
- [tests/walletClientMdocPresentation.test.js](/home/ni/code/js/rfc-issuer-v1/tests/walletClientMdocPresentation.test.js:1)

### Validation

```bash
npx mocha tests/walletClientMdocPresentation.test.js
npm test
```
