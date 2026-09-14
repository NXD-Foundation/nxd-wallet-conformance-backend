# CS-04 Key Attestation Interoperability Issue

## Status

Partially resolved. The KA JOSE `typ` and `certification` type discrepancies
are closed. `key_storage_status` remains an open CS-04 vs OpenID4VCI note.

## Resolved: KA JOSE `typ`

CS-04 Annex A.2 now cites `typ` as `key-attestation+jwt` from OpenID4VCI 1.0
Appendix D.1. The implementation emits and validates that hyphenated form on
both `proofs.jwt` (`key_attestation`) and `proofs.attestation`. The older
unhyphenated spelling `keyattestation+jwt` is rejected.

## Resolved: `certification` type

CS-04 §7.1.3 and Annex A.2 now normatively require KA `certification` as a
string URL linking to WSCD/keystore certification (OpenID4VCI 1.0 Appendix D.1),
not a JSON object. The wallet-client emits the Annex A.2 fixture URL; the
issuer rejects object-shaped `certification` with an explicit error. This
closes the Keycloak TC-003 `invalid_proof` / `Invalid attestation payload format`
interop failure reported against object-shaped values.

## Current WE BUILD decision

- CS-04 remains the governing WE BUILD profile.
- KA `certification` is a string URL on the wire.
- The KA JOSE type is `key-attestation+jwt` (OpenID4VCI 1.0 Appendix D.1 and
  CS-04 Annex A.2).
- `key_storage_status` remains mandatory under CS-04 even though it is not a
  core OpenID4VCI Appendix D field.
- The issuer-provided `c_nonce` is copied into the KA `nonce` claim as required
  for a JWT proof when the issuer supplies a nonce.
