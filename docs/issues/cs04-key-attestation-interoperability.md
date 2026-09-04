# CS-04 Key Attestation Interoperability Issue

## Status

Open clarification for the WE BUILD CS-04 profile. The KA JOSE `typ`
discrepancy is closed; `certification` type and `key_storage_status` remain.

## Discrepancies

The CS-04 KA example currently shows `certification` as an object containing
development or certification metadata. OpenID4VCI 1.0 Appendix D.1 defines
`certification` as a string URL. The CS-04 normative requirement requires a
`certification` claim but does not explicitly state the JSON type.

## Resolved: KA JOSE `typ`

CS-04 Annex A.2 now cites `typ` as `key-attestation+jwt` from OpenID4VCI 1.0
Appendix D.1. The implementation emits and validates that hyphenated form on
both `proofs.jwt` (`key_attestation`) and `proofs.attestation`. The older
unhyphenated spelling `keyattestation+jwt` is rejected.

## Current WE BUILD decision

- CS-04 remains the governing WE BUILD profile.
- The implementation retains the CS-04 example's certification object until
  the profile authors clarify whether that example is illustrative or
  normative.
- The KA JOSE type is `key-attestation+jwt` (OpenID4VCI 1.0 Appendix D.1 and
  CS-04 Annex A.2).
- `key_storage_status` remains mandatory under CS-04 even though it is not a
  core OpenID4VCI Appendix D field.
- The issuer-provided `c_nonce` is copied into the KA `nonce` claim as required
  for a JWT proof when the issuer supplies a nonce.

## Interoperability observation

Keycloak 26.x may reject the object-shaped `certification` value with
`invalid_proof` / `Invalid attestation payload format`. This is tracked as an
interoperability signal, not as authority to override CS-04. Once the CS-04
type is clarified, update the wire representation and example together.
