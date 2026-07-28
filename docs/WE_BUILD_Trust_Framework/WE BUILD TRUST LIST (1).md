# WE BUILD Trust Framework — ITB+ design and delivery plan

Status: working design document  
Scope: the ITB+ issuer, verifier and wallet test environment  
Last reviewed: 2026-07-27

## 1. Purpose and scope

This document defines how ITB+ will consume the WE BUILD WP4 trust
infrastructure and use it to make explainable trust decisions in test and
conformance flows. It is an overall design and sequencing document. Each
phase is deliberately expressed as a deliverable that can later be expanded
into its own implementation plan.

ITB+ is primarily a **consumer** of the WP4 trust infrastructure. It is not
currently intended to become a Trusted List Provider, maintain the ecosystem
LoTL, or replace participant onboarding and registration services.

The design covers:

- discovery and authenticated consumption of the WE BUILD LoTL;
- retrieval, signature, profile, freshness and status validation of referenced
LoTEs/Trusted Lists;
- resolution of trust anchors for a requested ecosystem role and credential;
- certificate, issuer and wallet-attestation trust decisions;
- cache, rollover, revocation and failure policy;
- evidence suitable for automated tests, reports and debugging; and
- a future local API so protocol services do not each implement trust-list
processing independently.

It does not make the current application trust-enforcing. The project
knowledge base records that trust-list enforcement is intentionally a
placeholder today: CS-02 trusted-authority handling is structural and
`trustAnchorsEnforced` is false until a trust registry is configured. This
plan is the path from that state to explicit, opt-in enforcement.

## 2. Design principles

1. **Authenticity precedes interpretation.** A URL, embedded certificate,
  `x5c`, or self-contained key is not a trust anchor until it is authorized by
   the configured bootstrap policy and the applicable signed list.
2. **Trust is scoped.** A provider can be trusted for one role, service type,
  credential type, VCT, `doctype`, or operation and not another.
3. **The decision is time-dependent.** Publication time, `nextUpdate`, service
  status, certificate validity, revocation and cache age all participate in
   the result.
4. **Pilot and production are different profiles.** The pilot uses WP4’s
  published LoTL and GitHub Pages workflow. Production is expected to use the
   Commission/Member State publication and OJEU/pivot trust-anchor model.
5. **One core, multiple adapters.** Parsing and trust resolution belong in a
  reusable library. Issuer, verifier, wallet and command-line integrations
   should supply context and consume a common decision/evidence model.
6. **Fail closed for security decisions.** A stale, unverifiable, malformed or
  ambiguous source may be retained for diagnostics, but must not silently
   produce a trusted result.



## 3. Current baseline



### 3.1 What WP4 currently provides

The checked-out WP4 repository describes a pilot in which the WP4 Trust
Infrastructure group acts as ecosystem authority and LoTL publisher. The
published artifacts are:

- JSON: [https://webuild-consortium.github.io/wp4-trust-group/list_of_trusted_lists.json](https://webuild-consortium.github.io/wp4-trust-group/list_of_trusted_lists.json)
- XML: [https://webuild-consortium.github.io/wp4-trust-group/list_of_trusted_lists.xml](https://webuild-consortium.github.io/wp4-trust-group/list_of_trusted_lists.xml)

The LoTL contains pointers to lists; it is not normally the list of every
provider. A pointer entry contains a URL, a TLP certificate (`trust_anchor`),
and optional operator metadata. The WP4 producer scans
`lotl/tl_entries/{tl_type}/`, generates both formats, signs them with JAdES and
XAdES, and publishes them through GitHub Pages.

WP4 currently recognizes these eight logical types:


| Type               | Intended source/profile                                     | ITB+ use                       |
| ------------------ | ----------------------------------------------------------- | ------------------------------ |
| `pid-provider`     | EU PID-provider LoTE                                        | PID issuer trust               |
| `wallet-provider`  | EU Wallet-provider LoTE                                     | WIA/KA issuer trust            |
| `wrpac-provider`   | EU WRPAC-provider LoTE                                      | Access-certificate trust       |
| `wrprc-provider`   | EU WRPRC-provider LoTE                                      | Registration-certificate trust |
| `pub-eaa-provider` | PuB-EAA LoTE, TS 119 602 Annex H/profile                    | Public-body EAA trust          |
| `eaa-provider`     | National non-qualified EAA LoTE, TS 119 602 Annex H/profile | Rulebook-defined EAA trust     |
| `qeaa-provider`    | National QTSP Trusted List, TS 119 612                      | QEAA trust                     |
| `ebwoid-provider`  | Registrars/registers LoTE                                   | Registry and entitlement trust |


The distinction between `qeaa-provider` and the Annex H LoTE types is
important: QEAA is a national TS 119 612 trusted list, not another Annex H
LoTE merely because it is stored under a similar folder name.

The pilot commonly centralizes PID, Wallet, WRPAC and WRPRC lists. External
TLP federation is demonstrated primarily by EAA and QEAA pointers, including
the NXD Foundation entries. This is a pilot operating model, not a permanent
restriction in the trust framework.

### 3.2 What this repository currently provides

The current Node.js repository implements OpenID4VCI, OpenID4VP, DC API,
WUA/KA compatibility and credential validation flows. It has useful structural
trust-policy hooks and tests, but it does not yet consume the WP4 LoTL or
enforce WP4 trust anchors. In particular:

- `docs/knowledge.md` is the orientation document and records the current
trust-enforcement limitation;
- `utils/cs02TrustPolicy.js` and the wallet equivalent validate policy shape,
but do not resolve a WP4 trust registry;
- `tests/cs02TrustPolicy.test.js` explicitly covers the current placeholder
behaviour; and
- current WUA and credential checks must not be described as WP4 trust-list
conformance until they use configured Wallet Provider/PID/EAA anchors and
status/revocation policy.

The WP4 checkout is also a development pilot rather than a stable production
fixture. Its current central-list URLs are under `tl-api.dev.idunion.info`,
and the checked-out IDunion participant certificates have validity ending in
April 2026. As of this document’s review date those fixtures cannot be used as
fresh production evidence without renewal. The plan therefore treats fixture
validity and source health as explicit acceptance criteria.

### 3.3 Important implementation caveats in WP4

The WP4 documentation describes CI checks for pointer schema, fetched-list
signature and ETSI profile validation, while also marking several per-type
schema checks as planned. The current code must therefore be treated as a
useful pilot producer/validator, not as sufficient evidence for ITB+ trust
decisions.

In particular, the current JSON validation path passes the downloaded payload
to the JAdES verifier but does not use the pointer’s `trust_anchor` argument
to establish the signer independently. ITB+ must validate the complete chain
itself and record which certificate/key matched the pointer. XML and JSON must
also be tested as separate format paths; “prefer JSON” is an implementation
choice in the WP4 helper, not a normative ITB+ decision.

### 3.5 JAdES JSON canonicalization

The published WE BUILD JAdES payloads are signed over the WP4 signer’s
canonical JSON representation of the unsigned payload. In practical terms,
the WP4 implementation recursively sorts object keys lexicographically,
emits compact JSON, and uses escaped non-ASCII characters before constructing
the JWS signing input. The `signature` member is added after that payload has
been signed.

This is a byte-level interoperability requirement, not merely a formatting
preference: two JSON documents can have the same meaning while differing in
key order, whitespace, or Unicode escaping, and those differences change the
JWS hash/signature input. Consumers must remove `signature`, reproduce the WP4
canonical bytes, and verify the original protected-header and signature values.
The Phase 1 verifier implements this rule and covers it with a unit test and
the live NXD integration test.

### 3.4 Local reference baseline

The local reference bundle is under
`[references/](references/README.md)`. The core format and consumption
standards are ETSI TS 119 602, TS 119 612 and TS 119 615, with RFC 5280 and
ETSI TS 119 312 supporting certificate and algorithm validation. ETSI TS
119 411-8, TS 119 475 and TS 119 472-1/-2/-3 are included because the trust
decision is ultimately applied to access certificates, relying-party
authorization, and EAA/PID issuance or presentation.

There are two TS 119 615 baselines in the bundle. WP4’s current implementation
profile cites V1.3.1, while ETSI published V1.4.1 in May 2026. V1.4.1 is the
current production review target; V1.3.1 remains the pilot compatibility target
until WP4 confirms a migration. TS 119 615 is specifically the procedure for
using/interpreting national TS 119 612 trusted lists. It must not be applied as
if it were the complete validation procedure for every WP4 TS 119 602 LoTE.

## 4. Target architecture

```text
                 configured WE BUILD trust profile
                    (LoTL URLs + bootstrap anchors)
                                  |
                                  v
                       Trust List Core Library
       fetch -> authenticate -> parse -> profile/status/freshness checks
                                  |
                    normalized snapshot + evidence
                                  |
                     Trust Resolution / Policy Engine
             role + artifact + operation + time + policy context
                                  |
       +------------------+-------+---------+------------------+
       |                  |                 |                  |
   issuer adapter    verifier adapter   wallet adapter   CLI/test adapter
```

The core library should be usable in-process first. A local Trust Resolver API
or sidecar can be added later without changing the decision semantics.

### 4.1 Trust source chain

```text
bootstrap policy for LoTL signer
        -> signed WE BUILD LoTL
        -> selected pointer for a logical type
        -> pointer-authorized TLP certificate/key
        -> signed LoTE or national TS 119 612 TL
        -> valid entity/service/status entry
        -> matching certificate, key, issuer or credential
```

The LoTL authenticates list discovery and the pointer relationship. The
referenced list establishes the listed provider/service and its status. A
successful LoTL signature alone never makes an arbitrary issuer trusted.

### 4.2 Trust decision input

The resolver must accept a structured request, not an ambiguous
`GET /isTrusted?entity=...` call. At minimum it needs:


| Field               | Examples                                                                  |
| ------------------- | ------------------------------------------------------------------------- |
| `framework`         | `webuild-wp4-pilot`                                                       |
| `role`              | `pid-provider`, `wallet-provider`, `wrpac-provider`, `qeaa-provider`      |
| `operation`         | verify PID, verify EAA, verify WIA, verify KA, verify access certificate  |
| `presentedIdentity` | issuer URL, EU entity identifier, SAN, certificate/key, DID or WUA issuer |
| `credentialContext` | VCT, `doctype`, credential configuration, attestation type                |
| `evaluationTime`    | explicit instant; default only when policy permits                        |
| `policy`            | accepted statuses, revocation requirement, stale-cache allowance          |


The result must include `trusted`, a stable reason code, matched list/entity/
service, effective status and validity times, source versions, and the
evidence needed to reproduce the decision. It must distinguish “not trusted”
from “trust could not be evaluated”.

## 5. Trust policy and failure model



### 5.1 Bootstrap and rollover

The LoTL URL is not sufficient. ITB+ requires an out-of-band bootstrap trust
anchor (certificate or pinned fingerprint) for the LoTL signer. The pilot
profile must document its distribution and rollover history. The production
profile must support the applicable OJEU/pivot mechanism and TS 119 615
procedures.

No implementation phase is complete until WP4 supplies:

- authoritative pilot LoTL signing certificate/fingerprint;
- signing algorithm and certificate profile;
- current and previous signer identifiers;
- rollover and emergency-revocation procedure; and
- an authoritative way to obtain the next bootstrap trust anchor.

For the pilot, the current published JAdES signer SHA-256 fingerprint is a
documented trust-on-first-use seed. It is pinned in the pilot profile and must
be replaced or augmented with current/next rollover pins. The embedded `x5c`
is document metadata, not an independent trust anchor; the only exception is
an explicitly enabled, high-severity test-only override.



### 5.2 Freshness, cache and availability

The policy must define refresh interval, maximum stale age, clock skew,
`thisUpdate`/`nextUpdate` handling, history retention, and behaviour when a
source is unreachable. A cached authenticated snapshot may support a
diagnostic or explicitly permitted offline mode, but stale data must be
visible in the result and never silently treated as current.

The test framework deliberately re-fetches authenticated LoTL/TL/CRL material
for each decision and retains decision evidence only for the session-log TTL;
it does not maintain a snapshot cache or historical store.

### 5.3 Status, certificate and revocation rules

The resolver must use only entries whose effective service/entity status is
valid under the selected profile. Suspension/cancellation maps to rejection
for new trust decisions. Certificate path validation, key matching and
certificate revocation (CRL/OCSP or the applicable ETSI mechanism) are
separate checks from list signature validation. Credential, WIA and KA
revocation/status-list checks remain separate protocol checks, but their result
must be combinable into one evidence record.

This implementation checks CRL distribution points when advertised and fails
closed for revoked, invalid, stale, or unavailable CRLs. OCSP is deferred.
Registrar registration data may supply approved credential types; when absent,
provider trust is allowed with explicit `scope-unverified` evidence pending a
future scope-enforcement review.

## 6. Delivery phases



### Phase 0 — Contract and fixture readiness — implemented

The initial Phase 0 implementation is now present in `data/trust/`,
`trust/`, and `tests/fixtures/trust/`. It provides the pilot profile,
normalized result/error vocabulary, synthetic signed fixtures, and fixture
manifest tests. The profile intentionally contains no live WP4 bootstrap
certificate; live strict trust remains disabled until WP4 supplies it.

**Objective:** remove ambiguities that would make a correct implementation
impossible.

**Work:**

1. Confirm the pilot LoTL URLs and designate JSON, XML, or both as normative
  for conformance decisions.
2. Confirm the ETSI version matrix: TS 119 602 V1.1.1, TS 119 612 V2.4.1,
  TS 119 615 V1.3.1 for pilot compatibility and V1.4.1 for production
   review, plus the applicable TS 119 312 cryptographic suite.
3. Obtain bootstrap and rollover material for the LoTL signer.
4. Obtain one current, signed fixture for every required list type, including
  valid, invalid, expired, withdrawn and key-rollover cases.
5. Agree the identifier-to-anchor matching rules for each role and artifact.
6. Agree status, history, revocation, cache and network-failure semantics.
7. Record whether onboarding/registry APIs are in scope; the initial consumer
  must depend only on published signed artifacts.

**Deliverables:** `webuild-wp4-pilot` profile; fixture manifest; open-questions
register; source-to-profile mapping; acceptance test catalogue.

**Exit criteria:** a reviewer can determine exactly which source, anchor,
format, status and time rules produce a trust decision.

### Phase 1 — Signed-list consumption proof — implemented

The initial Phase 1 implementation provides injectable fetching, JAdES JSON
and enveloped XMLDSig/XAdES verification, LoTL pointer traversal, TS 119 602/
TS 119 612 type separation, freshness checks, normalized snapshots, scoped
entity evaluation, CLI output, a local HTTP integration test, and an opt-in
live integration test that follows the published NXD EAA entry. Persistent
caching and issuer/verifier enforcement remain later-phase work.

**Objective:** prove the complete LoTL-to-provider chain independently of the
issuer and verifier routes.

**Work:**

1. Fetch and size-limit the selected LoTL over HTTPS.
2. Verify its JAdES/XAdES signature against the pinned bootstrap policy.
3. Validate its document type, sequence/version, dates, distribution points
  and pointer type.
4. Select referenced lists using the requested logical type and its versioned
  profile mapping.
5. Fetch and authenticate one central LoTE and one external EAA/QEAA list.
6. Apply TS 119 602 validation to LoTEs and TS 119 612 plus the selected TS
  119 615 procedure to national TSLs; do not conflate the paths.
7. Apply TS 119 312 algorithm policy and RFC 5280 certificate/path rules.
8. Extract normalized entities, services, anchors, statuses and validity data.
9. Emit deterministic decision evidence and negative reasons.

**Deliverables:** core library prototype; CLI; fixture-based tests; normalized
snapshot format; evidence JSON schema; fetch/cache diagnostics; version matrix.

**Exit criteria:** valid and invalid fixtures prove signature, profile, status,
freshness, pointer-anchor, and format-selection behaviour without relying on
GitHub CI as an assertion of trust. The live check is run explicitly with
`npm run test:trust:live`; it is not part of the default deterministic suite.

### Phase 2 — Explicit trust-resolution API

**Objective:** define and implement the policy-aware query boundary for
issuer, verifier and wallet components.

**Work:**

1. Implement the structured request and result model in §4.2.
2. Implement role-to-list and artifact-to-anchor resolution for the priority
  cases: Wallet Provider/WIA/KA, PID Provider/PID, EAA/QEAA, and WRPAC/WRPRC.
3. Support evaluation time, status, credential context and revocation policy,
  with separate policy branches for TS 119 602 LoTE and TS 119 612 TSL.
4. Return stable reason codes such as `BOOTSTRAP_UNTRUSTED`,
  `LIST_SIGNATURE_INVALID`, `ENTITY_NOT_LISTED`, `ENTITY_STATUS_INVALID`,
   `ANCHOR_MISMATCH`, `SOURCE_STALE`, and `REVOCATION_UNKNOWN`.
5. Expose the same implementation as an in-process API and a local HTTP/sidecar
  contract only if a process boundary is needed.

**Deliverables:** versioned resolver contract; library API; optional local API;
decision/evidence examples; threat model and operational configuration.

**Exit criteria:** the same fixture and request produce the same decision and
reason through CLI, library and API paths.

### Phase 3 — Integrate issuer and wallet issuance trust — implemented

The initial Phase 3 implementation now accepts `trustFramework=true` on the
issuer offer/session creation paths, verifier request-generation paths, and
wallet test session, storing the normalized `trustPolicy`. Opted-in issuance
sessions require WIA/KA material with an `x5c` certificate, resolve the Wallet
Provider through the Phase 2 resolver, fail closed on any non-trusted result,
and persist the complete trust reason and evidence in the session, including
missing or invalid attestation. Compatibility sessions retain the existing
behavior. Verifier-side credential trust evaluation remains Phase 4.

**Objective:** replace structural WUA trust placeholders with opt-in WP4 Wallet Provider trust for issuance. When the session contains the `trustFramework` flag.

**Implemented work:**

1. Credential offer, verifier request-generation, and wallet test-session
  endpoints accept the boolean `trustFramework` parameter. When true, they
  persist `trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" }`.
2. Resolve Wallet Provider anchors for WIA and KA validation using the Phase 2
  resolver and certificate fingerprints from strict `x5c` headers.
3. Fail closed for opted-in issuance sessions and persist the decision,
  reason code, evidence, and evaluation time in the session log/state.
4. Preserve a clearly labelled compatibility mode for sessions without the
  flag; verifier-side credential trust evaluation is deferred to Phase 4.
5. Add unit coverage for policy normalization, certificate-based resolution,
  decision persistence, route session persistence, and WIA/KA enforcement.

Status/revocation composition beyond the Wallet Provider certificate trust
decision, plus live end-to-end issuance against a published provider entry,
remains a conformance-hardening item for the next phase.

**Deliverables:** issuer/wallet trust adapter; configuration; migration notes;
   conformance evidence for UC-TE-03 and the relevant `ISSU_*` requirements.

**Exit criteria:** a self-contained `x5c`/JWK is insufficient by itself when
strict WP4 trust is enabled, every rejection is explainable and the session
contains the trust decision, reason code and evidence needed for diagnostics.

### Phase 4 — Integrate verifier credential and certificate trust — in progress

**Objective:** enforce provider and access-certificate trust in presentation
and verifier flows.

**Concrete plan:**

The first implementation slices are now in place. Enforcement is strictly
session-scoped: only VP sessions created with `trustFramework=true` at a VP
request-generation endpoint carry the normalized policy and activate these
checks. Requests without that parameter retain compatibility behavior. X.509
VP/JAR generation also evaluates the verifier access certificate as a WRPAC
operation and stores that decision in the VP session. Both
shared CS-02/DC API mdoc validation and the legacy custom mDL verifier path now
extract the COSE `x5chain` leaf from issuer authentication and evaluate it as
the credential issuer certificate. An optional distinct WRPRC registration
certificate can be supplied with `TRUST_WRPRC_CERT_PATH`; when configured, it
is evaluated and stored separately as `registrationCertificateTrust`.

1. **Define the verifier trust input contract.** Add a shared adapter which
  receives the stored verifier session policy, credential format, verified
   issuer claims, certificate chain or issuer key, requested `vct`/`doctype`,
   and operation. It must return the common `{ trusted, state, reasonCode,  evidence }` shape without replacing the existing credential, key-binding,
   or status validation result.
2. **Extract credential identity after cryptographic verification.** For
  SD-JWT/VC, use the verified issuer (`iss`), `vct`, `cnf`, and certificate or
   issuer-key evidence. For mdoc, use the verified issuer certificate,
   `doctype`, and namespace/profile context. Never resolve trust from an
   unverified payload or from a requested claim alone.
3. **Map credential contexts to WP4 roles and policy.** Implement explicit
  mappings for PID, QEAA, PuB-EAA, and applicable EAA profiles. The mapping
   must include the expected list type, credential context, operation, and
   permitted issuer/entity matching rules. Unknown mappings produce an
   explainable non-trusted result under strict opt-in.
4. **Compose the decision in the shared verification core.** Apply the trust
  adapter from the existing CS-02 and CS-07 response paths, including DC API.
   Existing signature, disclosure, key-binding, nonce/audience, DCQL,
   transaction-data, and status-list checks remain independent evidence. A
   strict opted-in session is successful only when all required checks pass.
5. **Add access-certificate evaluation as a separate operation.** Reuse the
  same resolver for WRPAC/WRPRC where those certificates are presented or
   required. Keep access-certificate trust separate from credential issuer
   trust so one decision cannot accidentally authorize the other.
6. **Persist and log verifier decisions.** Store the decision and evidence in
  the VP session, including the selected list type, authenticated snapshot or
   source version, matching entity/list entry, certificate fingerprint,
   freshness, and reason code. Fail closed for trust errors in opted-in
   sessions; retain current compatibility behavior without opt-in.
7. **Test in layers.** Add unit tests for identity extraction, role mapping,
  decision composition, unknown contexts, mismatches, withdrawal, stale
   snapshots, and certificate rollover. Add local signed-chain integration
   tests for SD-JWT PID and mdoc PID, plus a DC API integration path. Add a
   separately gated live test against the published WE BUILD LoTL and its
   referenced provider entry.

**Deliverables:** verifier trust adapter; explicit credential-context policy
profiles; session decision/evidence model; local positive and negative tests;
DC API coverage; and gated live-list evidence.

**Exit criteria:** under strict opt-in, credentials from an unlisted,
mismatched, withdrawn, stale, or revoked provider are rejected with an
explainable session decision, while existing CS-02/CS-07 structural checks and
non-opted-in compatibility flows remain unchanged.

For roles that intentionally share an ETSI LoTE type (currently PuB-EAA and
non-qualified EAA), a consumer must not select the first pointer returned by
the LoTL. The pilot loader authenticates and evaluates every compatible LoTL
pointer independently. A presented certificate is trusted only when it matches
an eligible, fresh entry in at least one authenticated referenced list;
unavailable or invalid unrelated lists are retained as diagnostic evidence and
cannot mask that match. If no referenced list can be authenticated, the result
is indeterminate and fails closed. `pointerUrl` remains available for a profile
that deliberately needs to restrict evaluation to one authenticated publisher.

#### Verification-context alignment plan

The current shared verifier APIs carry request/session-derived values in a
`context` argument and static validation switches in an `options` argument.
Phase 4 exposed an ambiguity where a caller supplied `context.session`, while
an mdoc branch read `options.session`. The immediate defect is fixed by using
`context.session`; the following migration keeps that distinction explicit.

Implementation status: the shared CS-02 entry point now normalizes a
verification context from the session and no longer forwards it through
`options`. CS-07 and direct-post callers supply the VP session once; the
remaining steps migrate the lower-level direct-call compatibility fields.

1. Define one `VerificationContext` shape for session, nonce, client/audience,
  transaction data, credential/key material, logging, and transport-derived
   values. The VP session appears only as `context.session`.
2. Restrict `ValidationOptions` to static policy/configuration switches such as
  strict mode, clock tolerance, environment, and feature compatibility. It
   must not carry a session or other per-request values.
3. Introduce a single context-construction helper used by direct-post, CS-07
  DC API, and test callers. It derives the duplicated fields from the session
   once and passes the session object unchanged for trust-policy decisions.
4. Migrate `validateCs02SdJwtEntriesInVpToken`,
  `validateCs02SdJwtPresentation`, and mdoc validation to consume the common
   context. During migration, reject or log deprecated `options.session` use
   so an accidental mixed call cannot silently bypass trust enforcement.
5. Update every verifier route and the CS-07 adapter, then remove the legacy
  adapter fields once callers use the common helper.
6. Add contract tests covering opted-in/non-opted-in SD-JWT and mdoc paths for
  direct post and DC API, plus a negative test proving that a session supplied
   through the deprecated options path is not accepted.

**Exit criteria:** each shared credential validator receives the session from
exactly one documented location, and no transport path can alter trust
enforcement by placing session state in validation options.

### Phase 5 — Operational hardening and evidence

**Objective:** make trust decisions safe and reproducible in continuous
   testing and deployments.

**Work:**

1. Add bounded fetching, SSRF protection, timeouts, content limits, retries,
  observability and cache isolation by trust profile.
2. Add signer/TLP certificate rollover, emergency revocation and recovery
  drills.
3. Retain authenticated snapshots and evidence sufficient to reproduce a
  historical decision.
4. Add scheduled health checks against WP4 stable/test endpoints and alert on
  expired participant fixtures or missing generated artifacts.
5. Produce conformance reports mapping decisions to WP4 use cases, ARF/ETSI
  requirements and repository tests.

**Deliverables:** runbook; security review; monitoring; fixture renewal process;
   signed evidence bundle; production-readiness decision.

**Exit criteria:** operators can explain and reproduce a decision after source
   update, cache use, key rollover, list withdrawal and temporary network loss.

## 7. Initial trust-resolution scenarios

These scenarios should drive the phase-specific plans and tests:


| Scenario                        | Required source chain                                          | Initial phase |
| ------------------------------- | -------------------------------------------------------------- | ------------- |
| Issuer validates WIA/KA         | LoTL → Wallet Provider LoTE → WUA issuer anchor → WIA/KA       | 1–3           |
| RP validates PID                | LoTL → PID Provider LoTE → PID issuer anchor → credential      | 1–4           |
| RP validates QEAA               | LoTL → national TS 119 612 TL → QTSP/service anchor → QEAA     | 1–4           |
| RP validates PuB-EAA            | LoTL → PuB-EAA LoTE → provider anchor → EAA                    | 1–4           |
| Wallet/RP validates access cert | LoTL → WRPAC/WRPRC LoTE → CA/registration anchor → certificate | 1–4           |
| Entity is withdrawn             | authenticated history/status → invalid decision                | 1–5           |
| Source is stale/unavailable     | cached snapshot + freshness policy → explicit result           | 1–5           |




## 8. Open decisions and requested WP4 inputs

These are dependencies, not implementation assumptions:

1. What is the authoritative pilot LoTL bootstrap and rollover mechanism?
2. Which format is normative for ITB+ conformance: JSON, XML, or both?
3. Which ETSI profile/version and WE BUILD constraints apply to every list type,
  and when does the pilot move from TS 119 615 V1.3.1 to V1.4.1?
4. What are the authoritative stable, development and negative-test endpoints?
5. Which statuses and service types are accepted at a given evaluation time?
6. How exactly is a presented identity matched to a listed service/anchor?
7. What history and offline/cache guarantees does the pilot provide?
8. When will current development certificates and generated LoTL artifacts be
  renewed and made available as stable fixtures?
9. Should ITB+ ever integrate the onboarding/registry API, or only consume
  published lists?

Until these questions are answered, Phase 1 may proceed with synthetic signed
fixtures, but production/conformance trust decisions must remain disabled.

## 9. Repository alignment and source map

Project-specific behaviour and current limitations: `[docs/knowledge.md](../knowledge.md)`.

The locally downloaded reference bundle and its version decisions are recorded
in `[references/README.md](references/README.md)`. It includes the current
ETSI format, consumption, certificate, EAA/PID and cryptographic profiles,
RFC 5280, and copies of the relevant WP4 implementation documents. The EU
legal/framework sources remain linked there where the environment could not
retrieve a local copy.

WP4 sources of truth for this design:

- [WP4 README](https://github.com/webuild-consortium/wp4-trust-group)
- [Trust Infrastructure Schema](https://github.com/webuild-consortium/wp4-trust-group/blob/main/task2-trust-framework/trust-infrastructure-schema.md)
- [Trust evaluation matrix](https://github.com/webuild-consortium/wp4-trust-group/blob/main/task2-trust-framework/trusted-list-registration-trust-evaluation-matrix.md)
- [Trusted-list discovery consumption](https://github.com/webuild-consortium/wp4-trust-group/blob/main/task1-use-cases/subtask1-2-trust-registry/trusted-list-discovery-consumption.md)
- [LoTL automation and TL integration](https://github.com/webuild-consortium/wp4-trust-group/blob/main/task4-trust-infrastructure-api/lotl-automation-and-tl-integration.md)
- [ETSI trusted-list implementation profile](https://github.com/webuild-consortium/wp4-trust-group/blob/main/task3-x509-pki-etsi/etsi_trusted_lists_implementation_profile.md)
- [Task 7 testing and validation](https://github.com/webuild-consortium/wp4-trust-group/blob/main/task7-testing-validation/README.md)

Normative interpretation follows the project knowledge-base order: published
specifications first, WE BUILD conformance material second, current code/tests
third, and planning documents last.
