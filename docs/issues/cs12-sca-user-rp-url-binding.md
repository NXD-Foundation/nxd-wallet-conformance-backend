# Draft CS-12 issue: define SCA-User RP URL audience binding for Wallet Units

## Problem

The current SCA-User Rulebook sections 4.1 and 5.1 require the issuer-signed credential `aud` to contain the issuing bank's RP URL(s), for example `https://banking.bank.cz`. CS-02 v1.2 requires the request `client_id` to use `x509_hash`, identifying the verifier access certificate. These values have different semantics and cannot be compared directly.

CS-12 section 6.1 step 3 says the Wallet Unit checks `aud` to confirm that the request originates from the issuing ASPSP. Section 7.2(3) specifies issuance, and section 7.4(3) specifies RP enforcement. Section 7.3 does not describe an explicit Wallet Unit URL audience binding algorithm.

TS12 section 3.1 specifies request signature/certificate and embedded disclosure policy checks; section 3.6 addresses the KB-JWT audience. ETSI TS 119 472-2 specifies request authentication and registration certificate transport. ETSI TS 119 475 describes RP URLs, including a URL belonging to the RP in its informative certificate-content discussion, but we have not identified a normative SCA-User audience comparison rule. A support URL, privacy-policy URL or registrar URL must not automatically be treated as the bank's SCA audience.

## Requested clarification

Please specify:

1. Which authenticated request/certificate/registration field establishes the bank RP URL to compare with credential `aud`?
2. How is that field bound to the request signer, including where a WRPRC is unavailable?
3. What exact URL comparison rules apply (origin vs full URL, paths, trailing slashes, normalization and arrays)?
4. What must the Wallet Unit do if the binding is missing, ambiguous or mismatched?
5. How does the rule apply across redirects and DC API, and to intermediaries if permitted by the two-party model?
6. Please add an explicit Wallet Unit requirement in CS-12 section 7.3 and matching positive/negative examples.

Credential `aud`, KB-JWT `aud`, Request Object `aud` and DC API origin binding should be distinguished explicitly.

## Reference backend behavior and current limitation

The reference backend uses an explicitly configured `RP_URL` for SCA-User issuance and checks the presented, issuer-signed credential audience against the RP URL pinned in its payment session. This is the RP checking credentials addressed to its own service; it does not provide an independent wallet with an authenticated URL association.

Pending specification clarification, the reference wallet-client continues SCA-User presentation and records a warning in the wallet session logs that RP audience binding was not validated. It retains a TODO for implementing the authenticated URL binding. This is an explicit interoperability limitation: the verifier enforces the credential audience, while the wallet does not establish RP audience permission. No new request claim or local certificate-to-URL mapping is proposed.

## Sources

- https://github.com/webuild-consortium/webuild-attestation-rulebooks-catalog/tree/main/rulebooks/rb-sca-user
- https://github.com/webuild-consortium/wp4-architecture/blob/main/conformance-specs/cs-12-sca-payments.md
- https://github.com/webuild-consortium/wp4-architecture/blob/main/conformance-specs/cs-02-credential-presentation.md
- https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts12-electronic-payments-SCA-implementation-with-wallet.md
- https://www.etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf
- https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
