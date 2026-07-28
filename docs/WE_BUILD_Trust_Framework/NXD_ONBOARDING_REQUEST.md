# NXD / WE BUILD pilot onboarding package

This package prepares the three roles implemented by this repository for WE
BUILD pilot onboarding. It is based on the WP4 onboarding model in
`wp4-trust-group`: providers are included in role-specific LoTEs; Relying
Parties are registered in a Registrar registry and receive certificates.

## Requested onboarding paths

| Local component | WP4 role and destination | Request to NXD / WP4 |
| --- | --- | --- |
| Credential issuer — PID configurations (`VerifiablePIDSDJWT`, `urn:eu.europa.ec.eudi:pid:1`) | PID Provider LoTE | Confirm whether UAegean is authorized to operate a PID Provider in this pilot. If yes, publish the existing issuer trust anchor and PID issuance service, or issue a replacement only if required. |
| Credential issuer — non-PID configurations (student ID, ferry pass, loyalty, photo ID, etc.) | Non-qualified EAA Provider LoTE, unless the issuer is a public body (PuB-EAA) or qualified provider (QEAA) | Confirm the legal classification of each credential family. Onboard a separate issuer service/certificate for every approved provider role. NXD's `nxd-eaa-providers-lote.json` is the relevant current non-qualified-EAA endpoint, subject to NXD confirming its supported onboarding path. |
| Verifier / RP (`UAegean WE BUILD Verifier`) | NXD/WE BUILD Registrar registry; not a LoTE entry | Register the RP and its intended uses; request a WRPAC for each RP instance. Request a WRPRC only if NXD issues registration certificates for the pilot. |
| Holder wallet (`wallet-client`) | Wallet Provider LoTE | Onboard the Wallet Provider and wallet solution, then publish the existing wallet-attestation trust anchor and status-list arrangement, or issue a replacement only if required. |

Do **not** request a generic LoTL entry for the verifier. The LoTL contains the
trusted-list pointers; it does not list Relying Parties. The WRPAC CA and, if
used, WRPRC provider are the entities listed in their respective LoTEs.

## Technical material to give NXD

### Common organization data

Fill these fields with the legal, rather than test-fixture, values:

```text
Legal name:
Trade/service name shown to users: UAegean WE BUILD
Legal identifier: EUID preferred; VAT or LEI if no EUID
Member State: Greece
Legal address:
Operational contact email:
Information / terms URI:
Privacy-policy URI:
Public-sector-body flag:
```

### Issuer request

Provide one record per provider role/service:

```text
Provider role: PID Provider | Non-qualified EAA Provider | PuB-EAA Provider | QEAA Provider
Credential family and identifiers (vct / doctype):
Credential format(s): dc+sd-jwt | mso_mdoc | jwt_vc_json
Issuance endpoint and issuer identifier:
Service-supply-point URI:
Existing issuer certificate chain/fingerprint: attached
New CSR: attached only if NXD requires a replacement certificate
Certificate-chain / CRL / AIA endpoints after issuance:
```

The current issuer configuration contains PID identifiers and several other
credential families. NXD must confirm which are actually authorized for the
pilot; code configuration alone does not establish a PID, qualified, public,
or EAA provider role.

### Relying Party request

```text
RP legal identity and identifiers: [common organization data]
RP display name: UAegean WE BUILD Verifier
Service description: WE BUILD pilot credential verification
Verifier/RP-instance URI(s):
OpenID4VP client_id(s):
Presentation response URI(s):
Requested credentials and claims, per intended use:
Purpose for each requested credential/claim:
Privacy-policy URI and supervisory authority/DPA:
Intermediary: none | [identifier, trade name, registry URI]
Existing verifier certificate chain/fingerprint: attached
WRPAC CSR: attached only if NXD requires a WRPAC replacement
WRPRC requested: yes | no
```

The repository currently evaluates a WRPAC only for `x509_san_*` verifier
client IDs. After issuance, configure the supplied WRPAC chain as the verifier
P12/chain and configure the optional WRPRC through `TRUST_WRPRC_CERT_PATH`.

### Wallet Provider request

```text
Wallet Provider legal identity: [common organization data]
Wallet solution name:
Solution type: EUDI Wallet for natural persons | European Business Wallet
Wallet solution URI:
Wallet-solution status-list URI:
Unique wallet-solution reference identifier (if assigned):
Conformity/certification evidence for the pilot:
Existing Wallet Provider / wallet-solution signing certificate chain/fingerprint: attached
New CSR: attached only if NXD requires a replacement certificate
Requested service: sign WIA and Key Attestation / WUA material
```

## Certificate requirements and current-repository gap

For this pilot, NXD may publish existing public certificates as the applicable
issuer, WRPAC, and Wallet Provider trust anchors. A new CSR is therefore not a
technical prerequisite. Provide the existing certificate/chain, fingerprint,
role, service endpoint, and status/revocation contact for every requested
entry. If NXD publishes a self-signed certificate, the signed LoTE becomes the
external authorization of that public key for the selected pilot role.

Separate keys per issuer, RP, and Wallet Provider role remain the recommended
future hardening, but are not a condition of pilot onboarding.

The current `x509EC/client_certificate.crt` has subject and issuer
`C=GR, ST=GR, O=UAegean, OU=UAegean, CN=uaegean.gr`; it is self-signed, has
SHA-256 fingerprint
`D5:C8:70:BA:94:A9:0E:87:41:FD:07:30:0B:DE:6C:83:1F:62:20:90:71:24:87:33:51:13:D8:9E:57:96:5F:10`,
and is currently used for verifier encryption, mdoc issuing, and wallet
attestation fixtures. It may be submitted as the **pilot** Wallet Provider
trust anchor if NXD explicitly publishes it in the Wallet Provider LoTE for
this wallet solution. Its self-signed status is then acceptable for the pilot;
the LoTE entry, not the self-signature, is the authorization decision.

Ask NXD to publish or, where desired, issue certificate chains with:

- `digitalSignature` key usage for issuer and Wallet Provider signing keys;
- the applicable WRPAC profile for the RP access certificate;
- full issuer chain, CRL distribution points, and AIA CA-issuer endpoint;
- the exact LoTE service type/status and service-supply point to publish; and
- rollover and revocation contact/procedure.

## Request message to NXD

> We are onboarding the UAegean WE BUILD pilot implementation. We need: (1)
> confirmation and onboarding of the credential issuer into the appropriate
> PID and/or EAA provider LoTEs; (2) RP registration, WRPAC issuance for each
> verifier instance, and confirmation whether a WRPRC is available; and (3)
> Wallet Provider/wallet-solution onboarding and publication of our existing
> certificate chain as the trust anchor for signing WIA and Key
> Attestation/WUA JWTs. Please provide the applicable
> application form/registry endpoint, accepted CSR profiles, required legal
> data, service-type identifiers, CRL/AIA/status-list expectations, and the
> exact resulting TL/registry publication URLs. We can provide new CSRs if
> required, but prefer the existing pilot certificates to be published.

## Post-approval integration checklist

1. Record the published certificate fingerprints, role, list URL, service
   status, and rollover/revocation contact. Keep private keys protected.
2. If NXD publishes the existing wallet certificate, configure the published
   certificate chain in wallet-client and retain the current key only for that
   Wallet Provider role. Replace it only if NXD issues a new chain.
3. Configure the verifier's published WRPAC chain and optional WRPRC; set an X.509 SAN
   client ID that matches the issued certificate.
4. Configure existing or replacement issuer signing chain(s) per approved
   provider role and make issuer identity/service endpoints match the LoTE entry.
5. Enable `trustFramework=true`, verify the published LoTL → NXD list →
   service chain, then perform issuance, presentation, WIA/KA, revocation, and
   rollover integration tests.
