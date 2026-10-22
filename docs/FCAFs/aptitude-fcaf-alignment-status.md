# APTITUDE Branch FCAF Alignment Status

## Purpose and basis

This is the Aptitude-branch counterpart to main's WE BUILD CS-02 FCAF
alignment material. It is derived from the main-branch applicability register,
but it is deliberately not a claim that this branch has main's FCAF coverage.
APTITUDE RFCs are profile deltas: base OpenID4VP, OpenID4VCI, HAIP, SD-JWT VC,
and ISO requirements remain authoritative unless an Aptitude RFC explicitly
changes them. See [knowledge.md](../knowledge.md).

The machine-readable status is
[aptitude-fcaf-applicability.json](./aptitude-fcaf-applicability.json).

For the row-by-row register, run:

```bash
git show main:docs/FCAFs/we-build-cs02-disposition-overrides.json \
  > /tmp/we-build-cs02-disposition-overrides.json
FCAF_MESSAGE_STRUCTURE_CATALOGUE_PATH=/path/to/fcaf-ms-specs-categorized.md \
FCAF_SECURITY_MECHANISMS_CATALOGUE_PATH=/path/to/fcaf-sm-specs-categorized.md \
FCAF_MAIN_OVERRIDES_PATH=/tmp/we-build-cs02-disposition-overrides.json \
  node scripts/aptitudeFcafAudit.js > /tmp/aptitude-fcaf-audit.json
```

When the catalogue files are stored together, use `FCAF_CATALOGUE_ROOT`
instead. The individual path variables are suitable for the upstream
message-structure and security-mechanisms directories.

The command emits one record for every one of the 301 explicit source rows,
including its ID, source description, disposition, concrete branch evidence
paths, and remaining gap. It preserves profile exclusions and marks a row
implemented only when branch-local runtime paths and focused automated test
evidence are both present. Structural-only trust, X.509, and revocation rows
are mapped to their relevant branch subsystems, while their unresolved trust
authority decisions remain explicit gaps.

## Ported baseline

Main records 301 explicit source rows (222 MessageStructure and 79
SecurityMechanisms). Its register classifies 192 as implemented, 38 as
structural-only, 70 as inapplicable to strict CS-02, and 1 as data-model
deferred. Those counts are **not imported as coverage claims** here: the
supporting main implementation has not been merged into this branch.

The generated branch audit reviews all 301 explicit rows. Its counts are
derived from the current branch at audit time, not copied from main. “Partial”
means the requirement appears applicable but branch-local enforcement or
focused evidence is incomplete.

The upstream catalogue also declares 236 MessageStructure requirements, while
only 222 explicit rows were extracted. The unresolved 14-row discrepancy
remains a catalogue issue and must not be filled with invented IDs.

## Current branch assessment

| FCAF area | Status | Evidence and limitation |
| --- | --- | --- |
| Message structure | Partial | Existing wallet DCQL selection, OpenID4VP routes, direct-post handling, and focused tests exist. Main's strict request/JAR and shared DCQL validators are absent. |
| Interaction and use cases | Partial | Presentation and issuance flows exist, including `direct_post` and `direct_post.jwt`; no imported CS-02 successful-flow matrix establishes the full profile. |
| RP integrity | Partial | Existing verifier routes and signing paths handle core request/response behavior. Main's reusable CS-02 request/response validation modules are absent. |
| Trust mechanisms | Structural-only / partial | Aptitude metadata signing and WIA/WUA/key-attestation plumbing exist. Configured trust-anchor, trusted-attester, and status authority decisions are not complete. |
| Device binding | Partial | SD-JWT key-binding helpers and tests exist. Attestation-proof issuance requires verified attestation material and binds the credential to the verified attested key(s); configured trusted-attester policy remains incomplete. |
| Session encryption | Partial | `direct_post.jwt` encryption metadata and decryption-key tests exist. Main's CS-02 session-key policy is not ported. |
| Shared encoding and cryptography | Partial | Existing JOSE/SD-JWT helpers are used, but main's shared CS-02 encoding helper and its focused tests are absent. |
| Data model | Out of scope | PID rulebook, mdoc PID attributes, and claim-value conformance remain outside this increment. |

## Important branch differences from main

The following main components are absent here and are the principal reason a
per-ID FCAF register cannot yet be claimed for this branch:

- `wallet-client/src/lib/cs02RequestValidation.js` and
  `wallet-client/src/lib/cs02DcqlValidation.js`;
- `utils/cs02DcqlCore.js`, `utils/cs02VerifierRequest.js`, and
  `utils/cs02VerifierResponse.js`;
- `utils/cs02TrustPolicy.js`, `utils/cs02StatusList.js`, and their tests;
- the CS-02 successful-flow matrix and the main per-ID disposition register.

Conversely, this branch contains Aptitude-specific issuer work that requires
separate evaluation from CS-02 presentation coverage: signed issuer metadata,
issuer signing material, WIA/WUA/key-attestation issuance paths, and Aptitude
credential metadata.

## Reporting rule

Until the listed main components are ported and each source ID is revalidated,
report this branch as **partial**. The generated audit is a conservative
per-ID evidence register, not a claim of equivalence with main. Do not copy
main's 192 implemented-row count into Aptitude reports.
