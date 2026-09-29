# CS-04 / CS-05 common issuer acceptance plan

Status: acceptance implementation snapshot updated 29 September 2026.

This replaces the acceptance design in the supplied
`we-build-cs04-cs05-issuer-implementation-plan.md`. The original remains unchanged.
Authority: published OpenID4VCI / OAuth specifications, then
[CS-05](core/cs-05-bwua-lifecycle%20%281%29.md) and
[CS-04](core/cs-04-wua-lifecycle.md), then current code.

## 1. Outcome and boundaries

Accept natural-person WIA + KA and business BWIA + SKA through the existing
issuer/authorization-server routes and shared cryptographic validators. A
business wallet can complete issuance and receive a credential bound to the
SKA key it proved possession of. Natural-person and compatibility flows retain
their existing behavior unless a stricter profile is explicitly requested.

This milestone covers acceptance at PAR, token, credential, and deferred
issuance boundaries. Include authorization-code and existing pre-authorized
flows; support for a grant is not a claim that the grant conforms to every
version of CS-01.

Deferred: discovery clients or services, offer push delivery, business registry
checks, new Wallet Provider Trust List integration, periodic attestation status
monitoring, credential cascade revocation, and a production business-wallet/HSM
implementation. Test fixtures emulate the business wallet. Describe the result
as CS-05 issuance acceptance with explicit trust and lifecycle gaps, not full
CS-05 conformance.

## 2. One transport, optional session profile

WIA and BWIA share `OAuth-Client-Attestation` and
`typ=oauth-client-attestation+jwt`. KA and SKA share the credential proof's
`key_attestation` header and `typ=key-attestation+jwt`. Do not add a second BWIA
header, endpoint, or retry-on-validation-failure path.

Add `walletAttestationProfile=auto|cs04|cs05` to issuer offer/session creation
requests (query parameter on GET, JSON property on POST). Omission means `auto`;
other values, including empty values, return `invalid_request`. This is a local
ITB control, not a new OpenID4VCI credential-offer field or wallet requirement.
Propagate it through standard, legacy, batch, and DC API session builders.
PAR/token/credential requests cannot overwrite the session's requested policy.
An existing session cannot be reconfigured through another offer request.

Use the canonical `sessionContext.walletAttestation` object with:
`requestedProfile`, `resolvedProfile`, `clientId`, `clientKeyThumbprint`,
`instanceAttestationDigest`, and optional `businessIdentity`.
Do not persist complete JWTs in this object. Preserve it across authorization
code exchange, access token association, and deferred polling.

Resolve the profile only after checking the instance attestation signature:

| Requested policy | Verified instance claims | Result |
| --- | --- | --- |
| auto | Neither `ebwoid_id` nor `legal_name` present | Existing individual-wallet validation |
| auto | Either business claim present | Require both non-empty strings, then CS-05 validation |
| cs04 | Any business claim present | Reject profile mismatch |
| cs04 | Neither business claim present | Existing CS-04 validation |
| cs05 | Both business claims valid | CS-05 validation |
| cs05 | Missing or invalid business claims | Reject; never fall back |

The claim-based discriminator is an ITB interoperability convention derived
from informative CS-05 Annex A, not a standardized universal wallet-type field.
Do not infer profile from wallet name, certificate subject text, credential
type, or discovery. A business wallet omitting both claims cannot be identified
as business in auto mode; explicit `cs05` is how a test requires that outcome.

Explicit profiles require instance and key attestations for the session.
Auto mode preserves existing attestation-required policy when none is supplied;
a supplied invalid attestation always rejects. Once auto resolves to CS-05,
all CS-05 requirements apply. A supplied BWIA cannot bypass them through a
credential-specific compatibility exception.

Lock profile, authenticated subject, client key, and BWIA identity at successful
PAR (or token for pre-authorized issuance). Require the same BWIA through the
business issuance session. A failed request does not change the locked profile.
Classify SKA using this session context; its wire format alone cannot identify
it as business or individual.

## 3. Acceptance checks and integration

Extend existing OAuth client-attestation, WUA claim/key-resolution, proof,
status-list, and session-context helpers. Keep parsing, signatures, claim
checks, and key matching shared; apply profile-specific rules via options.
Avoid separate CS-05 route implementations. Reuse current error translation
and distinguish attestation, proof, DPoP, and nonce failures in diagnostics.

### Instance attestation and Stage A

- Verify BWIA JOSE type, required `x5c` provider certificate chain, ES256/ES384/ES512 signature, public `cnf.jwk`, finite
  timestamps, `0 < exp-iat < 24 hours`, and unexpired `exp`. An `iat` more
  than 60 seconds in the future is logged as a warning, not rejected, because
  the profile does not fix a clock-skew limit. Require service name, version,
  certification information, and the two business identity strings.
- Verify client-attestation PoP with the BWIA `cnf` key, including type,
  allowed algorithm, AS audience, fresh `iat`, `jti`, and
  `PoP.iss == BWIA.sub == authenticated client_id`.
- Verify CS-05 status-list tokens only with the authenticated/configured
  Wallet Provider key, never by trusting a self-asserted status-token header key.
- At PAR bind the DPoP key to the BWIA key, accepting either `dpop_jkt` or a
  DPoP proof header (RFC 9449 §10); when both are sent they must match. At token require the DPoP key to match
  the BWIA key and the saved PAR binding, where PAR exists. Bind the access
  token to that thumbprint and the saved client identity.
- For CS-05 require a fresh AS nonce in token DPoP independently of the global
  optional nonce setting. Use the existing `use_dpop_nonce` / `DPoP-Nonce`
  challenge response and five-minute, single-use Redis nonce records bound to
  endpoint, client key, and session. Do not consume the grant on a challenge.
  Retried requests use fresh PoP and DPoP JWTs.
- Use atomic Redis replay records for business PoP/DPoP JTIs, retained through
  the accepted freshness window. Reserve the signed BWIA digest for one
  issuance session until its JWT expires; allow the same BWIA within that
  session, but reject another session's attempt. Status-list index is not an
  attestation identity.

### Key attestation and Stage B

- Verify SKA type and provider signature with the same allowed provider
  algorithms; require finite `iat`/`exp`, unexpired validity, and a token
  lifetime below 24 hours. This numeric SKA limit is the ITB interpretation
  of CS-05's short lifetime comparable to BWIA; document it as local policy.
- Require public attested keys, key-storage and authentication claims meeting
  the selected credential configuration, certification, and key-storage status.
  Preserve URL-string `certification` per OpenID4VCI and the existing validator.
  Document the conflicting object-shaped informative CS-05 example.
- Require JWT holder proofs for CS-05. Reject `proofs.attestation` in this
  profile because acceptance must prove possession of the SKA key. Preserve
  existing individual/compatibility support for that transport.
- Resolve each proof key through the existing supported key representations,
  match its public-key thumbprint against **any** verified SKA attested key,
  verify the proof, and bind the resulting credential to that exact key.
  Preserve the existing CS-04 first-key rule. Do not reject a key simply
  because it also equals the BWIA client key.
- Validate proof type, configured signing algorithm, issuer audience, freshness,
  `c_nonce`, and optional `iss` against the authenticated client ID. Preserve
  applicable KA/SKA nonce binding checks. At the credential endpoint validate
  DPoP `ath`, method, endpoint, freshness, replay, and access-token key binding.
- Until multi-proof issuance and nonce consumption are implemented end to end,
  reject CS-05 requests with more than one JWT proof. Do not silently process
  only element zero. Full batch issuance, duplicate proof/key checks, and atomic
  SKA-use reservation remain follow-up work. This issuer cannot enforce
  cross-issuer key reuse.
- Deferred issuance uses the validated profile/key evidence and preserves the
  original credential binding. Polling does not count as fresh SKA use or
  repeat proof consumption.

### Status and trust boundaries

- Before issuing, verify both BWIA `client_status` and SKA
  `key_storage_status` through the existing draft-20 consumer. Require VALID
  and at least 31 days of remaining maintenance on each reference, regardless
  of shorter metadata preferences. Reject missing, malformed, revoked, or
  unavailable status. Recheck BWIA status at token and before signing if the
  cached evidence is no longer fresh, including deferred completion.
- Require `x5c` in the CS-05 attestations as described by the profile. With
  trust-framework checking disabled, verify certificate/key syntax and JWT
  signatures through the existing resolver, with configured provider keys
  authoritative. Existing embedded-certificate test mode may remain usable;
  report provider trust as `not_evaluated`, never `trusted` on that basis.
- Preserve existing enabled trust enforcement; neither auto detection nor
  explicit CS-05 may disable it. New business-provider trust-role mapping and
  trust-list integration remain TODO. If existing enforced policy cannot
  establish trust, reject rather than bypass it.
- Retain normalized profile, identity, key thumbprints, status references,
  maintenance expirations, and validation outcomes in issuance diagnostics.
  Periodic checks after the session expires are explicitly outside this
  milestone; do not claim lifecycle coverage from issuance-time checks.

## 4. Implementation order and acceptance tests

1. Add profile parsing, session persistence, verified-claim classification,
   and profile-aware common claim validation.
2. Extend PAR/token continuity, mandatory business AS nonce, and atomic replay
   protection; cover authorization-code and pre-authorized flows.
3. Add SKA member-key selection and deferred evidence preservation. Extend
   existing WUA status checks; reject multi-proof CS-05 batches until the
   issuer can issue all corresponding credentials atomically.
4. Add business fixtures and a focused issuer test suite; update API examples,
   project knowledge, and the issuance coverage matrix with the exact gaps.

Required tests, at helper and protocol-route boundaries:

- Existing individual flows still pass with omitted profile and explicit CS-04.
- Auto and explicit CS-05 accept a signed BWIA/SKA fixture and issue a credential
  whose `cnf` matches the proven SKA key, including a non-first key.
- Missing BWIA under explicit CS-05, incomplete business claims, invalid BWIA
  signatures, conflicting profiles, and profile changes all reject without
  fallback. Identical JWT types never cause ambiguous transport selection.
- Wrong PoP issuer/audience, missing AS nonce, wrong/replayed nonce, mismatched
  DPoP keys or `ath`, cross-session BWIA reuse, and SKA reuse reject. Challenge
  retries work without consuming the grant; concurrent attempts cannot both win.
- Wrong proof `iss`/nonce/audience/signature and non-attested proof keys reject.
  Test proof arrays, duplicate keys, unsupported batches, and deferred polling.
- Expired/long-lived BWIA or SKA, insufficient maintenance, invalid status JWTs,
  revoked status, and unavailable status reject with distinguishable errors.
- Trust-disabled acceptance reports unevaluated trust; trust-enabled rejection
  cannot be bypassed by a profile parameter or business claims.

Use local signed fixtures and controlled fetch responses; no discovery service
or external HSM is needed. Run the new suite and nearest existing OAuth
attestation, WUA, proof-binding, token, credential, and deferred issuance suites.
Do not modify the reference holder into a business-wallet product in this phase.
