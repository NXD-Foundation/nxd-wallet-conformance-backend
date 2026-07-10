# OpenID4VP 1.0 And CS-02 Verifier Metadata Model

This note records the source material we should use when reasoning about
Verifier metadata in this repo.

## Downloaded Reference Material

- OpenID4VP 1.0 final: [docs/rfc/openid-4-verifiable-presentations-1_0.html](/home/ni/code/js/rfc-issuer-v1/docs/rfc/openid-4-verifiable-presentations-1_0.html)
- RFC 7591: [docs/rfc/rfc7591.txt](/home/ni/code/js/rfc-issuer-v1/docs/rfc/rfc7591.txt)
- Existing CS-02 local copy: [docs/core/cs-02-credential-presentation (1).md](/home/ni/code/js/rfc-issuer-v1/docs/core/cs-02-credential-presentation%20%281%29.md)

## Normative Baseline We Should Use

For OpenID4VP 1.0, Verifier metadata is modeled as OAuth client metadata.
The spec says: "To convey Verifier metadata, Client metadata defined in
Section 2 of RFC7591 is used." See OpenID4VP 1.0 Section 11 in
[openid-4-verifiable-presentations-1_0.html](/home/ni/code/js/rfc-issuer-v1/docs/rfc/openid-4-verifiable-presentations-1_0.html).

OpenID4VP 1.0 also says the metadata-delivery mechanism depends on the
Client Identifier Prefix. The Verifier can communicate a JSON object with its
metadata using the `client_metadata` parameter, and for pre-registered
clients the metadata can instead be obtained using RFC 7591 or out-of-band
mechanisms. See Section 5.9 in the same spec.

For the `redirect_uri` Client Identifier Prefix specifically, OpenID4VP 1.0
requires all Verifier metadata parameters to be passed using
`client_metadata`. That is important because it shows that request-carried
metadata is a first-class mechanism in VP v1.0, not an implementation hack.

RFC 7591 itself defines client metadata generically. It does not define a
single mandatory OpenID4VP Verifier discovery endpoint. It provides the data
model that OpenID4VP reuses for Verifier metadata.

## Practical Consequence For This Repo

For the CS-02 and CS-03 VP flows in this repo, the primary metadata surface
seen by the Wallet is the Authorization Request:

- inline `client_metadata`
- optionally `client_metadata_uri`
- plus any Client Identifier Prefix-specific trust inputs such as
  `verifier_attestation`, `x509_san_dns`, or DID-based rules

That means the same deployment can support both CS-02 and CS-03 safely if the
request builder passes the correct metadata projection for the specific flow.
We do not need one global Verifier metadata document to advertise both
profiles simultaneously to the Wallet for signed request-object flows.

## Public Metadata Endpoints In This Repo

This repo already exposes local Verifier metadata routes in
[routes/metadataroutes.js](/home/ni/code/js/rfc-issuer-v1/routes/metadataroutes.js):

- `/client-metadata`
- `/client-metadata/cs02`

These are useful implementation endpoints, but they should be treated as
profile-specific publication surfaces, not as proof that OpenID4VP 1.0
requires one universal Verifier metadata endpoint analogous to issuer
metadata discovery.

If we keep public metadata routes, they should follow this rule:

- broad route: may advertise deployment-wide capabilities for compatibility or CS-03
- strict CS-02 route: must advertise only strict CS-02-supported values
- request builders: must never feed the broad route or broad config directly into strict CS-02 request objects without filtering

## CS-02-Specific Interpretation

The local CS-02 copy includes an "8.4 Verifier Metadata Interface" section
that says Verifiers MUST publish metadata and Wallet Units retrieve it where
available. We should interpret that in a way that stays compatible with
OpenID4VP 1.0:

- CS-02 requires Verifier metadata to be available to the Wallet
- OpenID4VP 1.0 allows that metadata to be conveyed in the request itself or
  through other prefix-dependent mechanisms
- therefore, CS-02 support in the same deployment does not require one shared
  public metadata document for all VP profiles
- if public metadata is published, it must be profile-specific or filtered

## Implementation Rule For Ongoing Work

When implementing metadata consistency:

- keep [data/verifier-config.json](/home/ni/code/js/rfc-issuer-v1/data/verifier-config.json) as the broad source
- derive a strict CS-02 view for CS-02 requests and CS-02 publication routes
- derive a separate CS-03 or compatibility view for CS-03 requests and routes
- do not remove CS-03 capabilities from the deployment-wide source solely to
  satisfy CS-02
- do not let broad metadata leak into strict CS-02 request objects

## Source Pointers

- OpenID4VP 1.0 Section 5.1: `client_metadata` request parameter
- OpenID4VP 1.0 Section 5.9: Client Identifier Prefix and Verifier Metadata Management
- OpenID4VP 1.0 Section 8.3: encrypted response keys from client metadata
- OpenID4VP 1.0 Section 11: Verifier Metadata (Client Metadata)
- RFC 7591 Section 2: Client Metadata
