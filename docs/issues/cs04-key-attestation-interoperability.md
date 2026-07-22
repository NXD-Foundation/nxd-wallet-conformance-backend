# CS-04 Key Attestation Interoperability Issue

## Status

Open clarification for the WE BUILD CS-04 profile.

## Discrepancies

The CS-04 KA example currently shows `certification` as an object containing
development or certification metadata. OpenID4VCI 1.0 Appendix D.1 defines
`certification` as a string URL. The CS-04 normative requirement requires a
`certification` claim but does not explicitly state the JSON type.

The CS-04 example also uses `keyattestation+jwt`, while OpenID4VCI 1.0
requires the JOSE type `key-attestation+jwt`.

## Current WE BUILD decision

- CS-04 remains the governing WE BUILD profile.
- The implementation retains the CS-04 example's certification object until
  the profile authors clarify whether that example is illustrative or
  normative.
- The implementation uses `key-attestation+jwt`, which is the explicit
  OpenID4VCI wire requirement and is not changed to match the example typo.
- `key_storage_status` remains mandatory under CS-04 even though it is not a
  core OpenID4VCI Appendix D field.
- The issuer-provided `c_nonce` is copied into the KA `nonce` claim as required
  for a JWT proof when the issuer supplies a nonce.

## Interoperability observation

Keycloak 26.x may reject the object-shaped `certification` value with
`invalid_proof` / `Invalid attestation payload format`. This is tracked as an
interoperability signal, not as authority to override CS-04. Once the CS-04
type is clarified, update the wire representation and example together.
