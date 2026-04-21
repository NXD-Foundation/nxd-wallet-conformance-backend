# mdoc Interop Fixes

This note captures two mdoc interoperability bugs fixed in this branch so they can be checked and ported to other branches consistently.

## Scope

The fixes cover:

1. Issuer metadata for PID `mso_mdoc`
2. Wallet-client mdoc presentation for OpenID4VP / HAIP

---

## Bug 1: PID `mso_mdoc` Issuer Metadata

### Symptom

Wallets rejected the issuer metadata for credential configuration id:

`urn:eu.europa.ec.eudi:pid:1:mso_mdoc`

The advertised `credential_metadata.claims[].path` values did not follow mdoc claims path rules.

### Root Cause

The metadata endpoint serves `data/issuer-config.json` directly, and the PID mdoc entry still used an older grouped shape:

- namespace group path: `["urn:eu.europa.ec.eudi:pid:1"]`
- nested child claim paths: `["given_name"]`

That shape does not match the current OpenID4VCI 1.0 mdoc claims description format.

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

Also, the PID mdoc `doctype` must be the document identifier:

`urn:eu.europa.ec.eudi:pid:1`

and not the format-suffixed configuration id:

`urn:eu.europa.ec.eudi:pid:1:mso_mdoc`

### Files Changed

- [data/issuer-config.json](/home/ni/code/js/rfc-issuer-v1/data/issuer-config.json:1223)
- [utils/routeUtils.js](/home/ni/code/js/rfc-issuer-v1/utils/routeUtils.js:476)
- [tests/metadataDiscovery.test.js](/home/ni/code/js/rfc-issuer-v1/tests/metadataDiscovery.test.js:2265)

### Validation

```bash
npm test -- tests/metadataDiscovery.test.js tests/routeUtils.test.js
```

---

## Bug 2: Wallet-Client mdoc Presentation

### Symptom

Verifiers reported that the wallet-client submitted an invalid mdoc presentation because:

- `deviceSigned` was missing
- the payload effectively behaved like an `issuerSigned` wrapper, not a proper OpenID4VP mdoc `DeviceResponse`
- verifier parsing / verification failed

Some reports also mentioned missing `issuerAuth` issuer certificate chain metadata (`x5chain` / `x5c`).

### Root Cause

The wallet-client was constructing an ad hoc `DeviceResponse` wrapper around `issuerSigned` but explicitly omitted `deviceSigned` / `deviceAuth`.

That is not sufficient for an OpenID4VP mdoc presentation, where the mdoc `vp_token` must be a real `DeviceResponse` bound to the OpenID4VP `SessionTranscript`.

### Required Behavior

For mdoc presentation in OpenID4VP / HAIP:

- `vp_token` must be a base64url-encoded `DeviceResponse`
- the `DeviceResponse` must include `deviceSigned.deviceAuth`
- `deviceAuth` must be bound to the OpenID4VP session transcript
- issuer-provided `issuerSigned` content, including `issuerAuth` chain metadata, must remain intact

### Fix Implemented

The wallet-client now builds a real signed mdoc `DeviceResponse` using `@animo-id/mdoc`:

- passes `clientId`, `responseUri`, verifier `nonce`, `presentationDefinition`, and the wallet device private key into mdoc presentation building
- derives the OpenID4VP session transcript
- signs `deviceSigned.deviceAuth` with the wallet device key
- preserves `issuerSigned` / `issuerAuth` content, including `x5chain` when present

### Files Changed

- [wallet-client/src/lib/presentation.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/src/lib/presentation.js:863)
- [wallet-client/utils/mdlVerification.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/utils/mdlVerification.js:314)
- [wallet-client/utils/mdocContext.js](/home/ni/code/js/rfc-issuer-v1/wallet-client/utils/mdocContext.js:1)
- [wallet-client/package.json](/home/ni/code/js/rfc-issuer-v1/wallet-client/package.json:9)
- [tests/walletClientMdocPresentation.test.js](/home/ni/code/js/rfc-issuer-v1/tests/walletClientMdocPresentation.test.js:1)

### Important Note on `x5chain`

The wallet-side defect was clearly the missing `deviceSigned` / `deviceAuth`.

For `issuerAuth` chain metadata:

- local verification showed the wallet decode / re-encode path preserves COSE header key `33` (`x5chain`) when it is present in the issued credential
- a regression test now asserts that the built presentation still contains `issuerAuth` `x5chain`

So if another branch still loses chain metadata, check both:

- issuer-side mdoc issuance
- wallet-side storage / transformation

### Validation

```bash
npx mocha tests/walletClientMdocPresentation.test.js
npm test
```

---

## Porting Checklist For Another Branch

When checking another branch, verify all of the following.

### Issuer Metadata

- PID mdoc claims are flat two-segment paths:
  `["urn:eu.europa.ec.eudi:pid:1", "<claim>"]`
- PID mdoc `doctype` is `urn:eu.europa.ec.eudi:pid:1`
- DCQL defaults use the same PID doctype

### Wallet Presentation

- mdoc `vp_token` is a real `DeviceResponse`
- `documents[0].deviceSigned.deviceAuth` exists
- mdoc presentation builder uses OpenID4VP request inputs:
  `client_id`, `response_uri`, verifier `nonce`
- `issuerSigned.issuerAuth` still contains `x5chain` if issuer included it

### Test Commands

```bash
npx mocha tests/walletClientMdocPresentation.test.js
npm test -- tests/metadataDiscovery.test.js tests/routeUtils.test.js
npm test
```

---

## Spec References

- OpenID4VCI 1.0:
  `mso_mdoc` issuer metadata and claims path rules
- OpenID4VP 1.0:
  mdoc `vp_token` is a base64url-encoded `DeviceResponse` and carries device authentication over the session transcript
- HAIP 1.0:
  mdoc presentations in OpenID4VP flows use `DeviceResponse`
