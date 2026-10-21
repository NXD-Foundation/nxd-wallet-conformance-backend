# Directly listed WRPRC signer Key Usage

## Rules and implementation boundary

[RFC 5280 §4.2.1.3](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3)
defines Key Usage as a restriction on the public key. It mandates the extension
for keys used to verify certificates or CRLs; it does not mandate it for every
non-CA document-signing certificate. Absence and explicit prohibition are distinct.

[ETSI TS 119 475 V1.2.1 §5.2.1–5.2.2](https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf)
requires the WRPRC provider signature, refers to its signature/seal certificate
published in the relevant trusted list, and specifies the `x5c` header. The
WRPRC clauses do not impose a blanket requirement for an explicit
`digitalSignature` Key Usage extension on a directly trusted signing key.
This consumer-side rule does not assert full certificate-issuance or JAdES
conformance of every sandbox token.

The resolver previously required that extension for every presented signer,
including an exact non-CA signing certificate directly listed in an authenticated
WRPRC-provider LoTE. This conflated missing usage with explicitly denied usage.
The correction is limited to `wrprc-provider` and applies only when:

- the exact presented leaf certificate is published by the authenticated list;
- the certificate is not a CA;
- the Key Usage extension is absent, rather than present without `digitalSignature`;
- certificate validity and the existing trust-list freshness/signature checks pass.

It does not accept unlisted signers or arbitrary descendants of a listed CA.
WRPAC validation retains its explicit digital-signature Key Usage requirement.
JWT signature, expiry, subject/service/intended-use bindings, entitlement,
registered scope, and registrar-dataset consistency remain enforced.

## Revalidate and activate retained tokens

```bash
node scripts/provisionRaidiamWrprc.js --activate-quarantined
```

This mode needs the public WRPAC and local registration records. It fetches the
configured authenticated trust lists, but does not request an OAuth token or call
registration/issuance APIs. It reuses the existing lock, backups, atomic writes,
and verification callback. Failed tokens stay unactivated; expired tokens do not
trigger replacement issuance. Original quarantine files are preserved as evidence.
The local registry status is retained; this mode does not perform a fresh registry
status lookup or change the pilot profile's existing revocation policy.

## Live evidence

On 21 October 2026, the pinned WE BUILD LoTL authenticated IDunion's WRPRC list at
<https://tl-api.dev.idunion.info/api/v1/DblnEVuf/etsi/tl.xml>.
It lists Raidiam Services Ltd for
`http://uri.etsi.org/19602/SvcType/WRPRC/Issuance`, including the exact certificate
that signed the 13 retained registrations:

- Subject: `C=GB, O=Raidiam Services Ltd, CN=EUDI Sandbox Registration Certificate Signer`
- SHA-256: `7d0be11ca864cee97de61624c34e353a31771588e2009c33da15b2f1258520a7`
- Non-CA signer; no extensions, including no Key Usage.

This is evidence from that run, not a permanent local trust pin. Runtime checks
continue to resolve and authenticate the configured trust lists.

All 13 retained tokens passed live trust, JWT signature/expiry, relying-party and
intended-use identity, Service Provider entitlement, registered scope and dataset
checks on that date. They were activated locally without registration or issuance
API calls. Existing quarantine files and manifest backups were preserved.
