# NXD submission artifacts — UAegean WE BUILD pilot

These files were generated against the live WE BUILD LoTL on 2026-07-28.
It currently references NXD only for:

- `EUPubEAAProvidersList` at
  `https://trustlist.nxd.foundation/trust-lists/nxd-eaa-providers-lote.json`;
- a QEAA national TSL at
  `https://trustlist.nxd.foundation/trust-lists/NXD-TL-QEAA.xml`.

It does **not** reference an NXD Wallet Provider or WRPAC Provider list.

## Files to send NXD

- `issuer-pub-eaa-entry.json`: insert this `TrustedEntitiesList` item into
  NXD's current EAA/PuB-EAA JSON LoTE if NXD confirms the pilot issuer is an
  EAA/PuB-EAA. The same certificate may be used in the pilot because NXD's
  signed list authorizes it for that role.
- `wallet-provider-entry.json`: insert this item only into a Wallet Provider
  LoTE (`EUWalletProvidersList`) that NXD publishes and WP4 then references
  from the LoTL. It must not be added to the EAA list.
- `verifier-rp-registration-request.json`: send this to NXD's Registrar/Access
  CA workflow. It is not a trusted-list entry: NXD must register the RP and
  associate/issue a WRPAC for the included verifier certificate.
- `verifier-rp-registration-ts5-template.json`: complete TS5-shaped pilot RP
  registration dataset based on the verifier's implemented PID (SD-JWT and
  mdoc), age-verification mdoc, and TS-12 payment-SCA requests. Each
  `credentials[]` item owns its `claims[]`, so multiple credential types cannot
  be confused. This is also where types and claims belong; no such fields are
  part of a LoTE entry.

## What belongs where

The issuer and wallet files are trusted-list (`LoTE`) entries. A LoTE authorizes
an entity/service by publishing its role, status and certificate. It does not
publish the verifier's intended credential types or requested claims.

The verifier's types, claims, purpose and privacy information belong in the RP
registry record/WRPRC. The WRPAC provider's CA trust material—not the verifier
leaf certificate—is what is eventually published in an `EUWRPACProvidersList`
LoTE.

The live WE BUILD LoTL has pointers to `EUWRPRCProvidersList` and
`EUWRPACProvidersList` LoTEs operated by IDunion and Raidiam. It does **not**
publish an RP Registrar API endpoint. A provider list authorizes an issuer of
WRPRCs/WRPACs; it is not itself a registry in which UAegean can create an RP
record. NXD must provide the actual Registrar API or intake workflow and assign
any registry-issued identifier and `registryURI`.

## Required NXD confirmations

1. Confirm whether the issuer is accepted as non-qualified EAA/PuB-EAA. PID
   issuance needs a PID Provider list instead; QEAA needs the QEAA workflow.
2. Confirm whether NXD will publish a Wallet Provider LoTE and submit its
   signed-list pointer to WP4, or direct the wallet submission to the existing
   Wallet Provider TLP.
3. Register the verifier as an RP, publish its registry record, and confirm
   whether its existing EUDI Wallet Reference Implementation certificate is
   accepted as the pilot WRPAC or requires a WRPAC issued by NXD's Access CA.

The two supplied certificates are public material only. Private keys are not
included and must never be sent to NXD.
