# Opt-in CS-18 draft trust validation

**Target:** CS-18 draft v0.1 at commit `7fbf20e1e446fe7642141746d44afad09e61df67`, PR #363. This is a draft target, not an adopted normative profile.

## Decisions

- Trust-enabled sessions default to `pilot`; callers may select `trustValidationMode: "cs18-draft"`. Mode is local request/session state and is not emitted in OpenID messages.
- The selected mode is stored in canonical wallet session trust policy and mirrored in the compatibility field. An active wallet trust session cannot switch modes.
- Availability continuation is represented as `trusted: false, accepted: true, state: "indeterminate"`; successful validation is trusted and accepted, and invalid evidence is rejected. Missing trust-list evidence is not an availability continuation.
- The current Raidiam registrations remain pilot-mode only because their directly listed signer certificate has no Key Usage. Strict mode requires explicit `digitalSignature`.
- WRPRCs in strict mode require `policy_id` containing `0.4.0.19475.3.1`, a finite numeric `iat` no more than 60 seconds in the future, and validate `exp` when supplied. Pilot retains its existing required-`exp` behavior.
- The test-bed availability policy is to continue only when certificate-status evidence is unavailable, stale, or not advertised, recording the result as unknown. Invalid signatures/authorisation and confirmed revocation remain rejection cases.

## Implemented foundation

- Request/session policy parsing validates the two mode values and requires trust enforcement for strict mode.
- Wallet session storage persists the mode and rejects changing it on a subsequent active-session write.
- WRPRC claim validation implements the strict policy/time rules; wallet presentation and pinned-registration validation use the stored mode.
- Trust resolver results in strict mode include explicit `accepted`; trust-list failures do not become accepted.
- Strict trust decisions record the validation mode, acceptance policy, check time, signing-certificate and presented-chain fingerprints, authenticated source list and revocation outcome.
- Strict path evaluation disables the pilot-only directly-listed signer Key Usage exception.
- Strict certificate paths are checked with PKI.js against only the authenticated service anchor and presented chain. The adapter checks validity, signature chaining, CA usage, name constraints, and recognized critical extensions; an additional path-length check covers the PKI.js gap.
- Strict service selection requires the CS-18 issuance service URI for PID, Wallet Provider, WRPAC, WRPRC, Pub-EAA and QEAA roles.
- Certificate revocation checks cover each returned non-anchor certificate in strict mode. An unavailable/not-advertised check is recorded as unknown and may continue. Pilot revocation behavior remains leaf-only.
- A bounded process-local snapshot cache coalesces loads, keys entries by profile pins/mode/role, refreshes before trust-list expiry and retains last-valid evidence only until its deadline.
- Wallet, issuer, and verifier trust gates consume accepted decisions where the strict result is produced.
- The Raidiam provisioning CLI accepts `--trust-validation-mode=pilot|cs18-draft`; pilot remains its default. No provisioning or activation was run.

## Remaining before this mode can be called complete

- OCSP retrieval/verification, CRL/OCSP caching and complete cryptographic-invalid versus availability classification.
- One shared strict Token Status List evaluator enforcing signer authority under all three CS-18 §7.6 relationships, EAA/QEAA same-certificate rules, cache authority rechecks, and parity across WRPRC, credentials, WIA/BWIA, and KA/SKA.
- Strict revocation-service selection, complete CS-18 list/status mappings, and critical trusted-list extension rejection.
- Immediate cached-authorization invalidation on authenticated pointer rotation (the current cache refreshes before expiry and at least every 24 hours).
- End-to-end regression coverage for OCSP, all status consumers, cache pointer rotation, continuation/refresh/deferred propagation, and focused issuance and presentation runs.

This document records the implementation state and acceptance boundary; do not use the `cs18-draft` selector for external interoperability until the remaining items are implemented and verified.

