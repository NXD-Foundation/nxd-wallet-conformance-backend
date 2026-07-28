# Subject: WE BUILD pilot — UAegean issuer, wallet and verifier onboarding material

Hello NXD team,

Please find the attached onboarding material for the University of the Aegean
(UAegean) WE BUILD pilot.

## 1. Issuer — add to NXD's current PuB-EAA LoTE

Please add `issuer-pub-eaa-entry.json` as a `TrustedEntitiesList` item to the
signed JSON LoTE currently published at:

`https://trustlist.nxd.foundation/trust-lists/nxd-eaa-providers-lote.json`

The entry uses the existing UAegean pilot signing certificate. Its SHA-256
fingerprint is:

`D5:C8:70:BA:94:A9:0E:87:41:FD:07:30:0B:DE:6C:83:1F:62:20:90:71:24:87:33:51:13:D8:9E:57:96:5F:10`

Please confirm that PuB-EAA is the appropriate pilot issuer role for the
credential(s) we will issue. We will use the PID or QEAA onboarding route
instead if a credential is classified as PID or qualified EAA.

## 2. Holder wallet — publish a Wallet Provider LoTE first

Please create and publish an `EUWalletProvidersList` LoTE, add its signed
pointer to the WE BUILD LoTL, and then add `wallet-provider-entry.json` to that
list. The wallet entry must not be placed in the PuB-EAA list.

The wallet uses the same existing pilot certificate and its unique service ID
is `urn:webuild:wallet-solution:uaegean:wallet-client:pilot`.

## 3. Verifier — RP registration and WRPAC

Please process `verifier-rp-registration-request.json` and
`verifier-rp-registration-ts5-template.json` through the RP registry/Access-CA
workflow. The former contains the existing verifier certificate and full `x5c`
chain; the latter is the complete pilot RP dataset, with each credential type
bound to its own requested claims. Please provide the actual Registrar API or
intake format and assign the registry identifier and `registryURI`. Its leaf
SHA-256 fingerprint is:

`F0:18:EF:78:10:A6:8E:2A:32:5F:61:90:E7:8F:6C:2A:09:F2:B1:EC:54:B3:7F:66:78:22:D6:CB:88:EE:71:09`

Please confirm whether the existing EUDI Wallet Reference Implementation
certificate can be accepted as the pilot RP's WRPAC, or issue an NXD WRPAC for
it. A WRPAC is not a PuB-EAA list entry: the relevant Access-CA trust material
must be published through an `EUWRPACProvidersList` LoTE (or another WP4
recognized WRPAC trust path).

The registration request has fields that UAegean/NXD must agree before
publication: public-sector status, the actual credential type and claim paths,
and the privacy-policy URI. These fields are RP-registry/WRPRC information;
they are not fields of a trusted-list entry.

Only public certificates and their public chains are included. No private key
is included or should be sent.
