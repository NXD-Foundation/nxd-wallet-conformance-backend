# APTITUDE issuer migration notes

## Purpose

This note records the issuer-side EUDI wallet interoperability changes made on
the current branch. It is the hand-off checklist when moving the work to the
APTITUDE branch. Normative requirements remain in [RFC001](./core/RFC001.md)
and the local OpenID4VCI reference.

## Changes to retain

1. **Stable signed issuer metadata identity.**
   The metadata route derives `credential_issuer` from `SERVER_URL`, matching
   the value in credential offers, rather than from the incoming Host header.
   Signed metadata is emitted as `openidvci-issuer-metadata+jwt` and signed
   with the configured issuer certificate in the JWS `x5c` header. This is
   required by RFC001 for the ETSI-aligned profile.

2. **Credential-request encryption discovery.**
   When credential-response encryption is advertised, issuer metadata also
   publishes `credential_request_encryption` with the current agreement JWK,
   `alg_values_supported: ["ECDH-ES"]`, supported content-encryption values,
   and `encryption_required: false`. `POST /credential` handles the matching
   compact-JWE request body in `sharedIssuanceFlows.js`.

3. **Room-key proof metadata.**
   `room_key_credential` advertises both `jwt` and `attestation` proof types,
   using ES256 and `key_attestations_required`. The endpoint implements both
   paths, so this declaration is not merely a wallet workaround.

4. **OID4VCI 1.0 metadata cleanup.**
   The outgoing metadata does not publish the removed
   `batch_credential_endpoint` parameter. Multi-credential issuance remains
   on the standard Credential Endpoint using the `proofs` request structure.

5. **OpenID4VCI key-attestation claims.**
   The direct `proofs.attestation` path accepts a valid OpenID4VCI Appendix D.1
   key-attestation JWT without `iss` or `eudi_wallet_info`. It still requires
   a verified signature/trust key, `typ=key-attestation+jwt`, a valid `iat`, a
   fresh nonce, and non-empty `attested_keys`. The stricter WUA checks remain
   the default for the existing WUA/header transport.

## Compatibility projection

The issuer-metadata route currently omits credential formats that the target
EUDI reference-wallet version does not parse. This is a compatibility
projection, not a statement that those configurations are unsupported by the
issuer. Before a strict RFC001/ETSI APTITUDE deployment, decide whether to
publish a separate wallet-targeted issuer identifier/metadata document instead
of filtering the general metadata endpoint. In particular, RFC001 requires
advertising `vc+jwt` and `x509_attr` whenever the issuer supports their
corresponding ETSI credential formats.

## Items requiring an explicit APTITUDE decision

- The current metadata omits `issuer_info`. Do not treat this as ETSI-profile
  conformance: RFC001 requires valid issuer-registration material in that
  parameter for an ETSI-aligned deployment. Restore it once valid registration
  material is available and accepted by the target Wallet.
- The current response-encryption configuration publishes `A256GCM`. RFC001's
  ETSI-aligned profile requires support for both `A128GCM` and `A256GCM`; add
  `A128GCM` only after the credential-response implementation is verified to
  encrypt with it.

## Verification after migration

Run:

```sh
npx mocha --exit tests/metadataDiscovery.test.js tests/keyAttestationProof.test.js
```

Then exercise an EUDI wallet flow through metadata discovery, token issuance,
an encrypted `POST /credential`, and a `proofs.attestation` credential request.
