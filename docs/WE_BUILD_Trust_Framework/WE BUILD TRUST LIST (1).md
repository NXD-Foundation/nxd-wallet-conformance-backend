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

- JSON: <https://webuild-consortium.github.io/wp4-trust-group/list_of_trusted_lists.json>
- XML: <https://webuild-consortium.github.io/wp4-trust-group/list_of_trusted_lists.xml>

The LoTL contains pointers to lists; it is not normally the list of every
provider. A pointer entry contains a URL, a TLP certificate (`trust_anchor`),
and optional operator metadata. The WP4 producer scans
`lotl/tl_entries/{tl_type}/`, generates both formats, signs them with JAdES and
XAdES, and publishes them through GitHub Pages.

WP4 currently recognizes these eight logical types:

| Type | Intended source/profile | ITB+ use |
| --- | --- | --- |
| `pid-provider` | EU PID-provider LoTE | PID issuer trust |
| `wallet-provider` | EU Wallet-provider LoTE | WIA/KA issuer trust |
| `wrpac-provider` | EU WRPAC-provider LoTE | Access-certificate trust |
| `wrprc-provider` | EU WRPRC-provider LoTE | Registration-certificate trust |
| `pub-eaa-provider` | PuB-EAA LoTE, TS 119 602 Annex H/profile | Public-body EAA trust |
| `eaa-provider` | National non-qualified EAA LoTE, TS 119 602 Annex H/profile | Rulebook-defined EAA trust |
| `qeaa-provider` | National QTSP Trusted List, TS 119 612 | QEAA trust |
| `ebwoid-provider` | Registrars/registers LoTE | Registry and entitlement trust |

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

### 3.4 Local reference baseline

The local reference bundle is under
[`references/`](references/README.md). The core format and consumption
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

| Field | Examples |
| --- | --- |
| `framework` | `webuild-wp4-pilot` |
| `role` | `pid-provider`, `wallet-provider`, `wrpac-provider`, `qeaa-provider` |
| `operation` | verify PID, verify EAA, verify WIA, verify KA, verify access certificate |
| `presentedIdentity` | issuer URL, EU entity identifier, SAN, certificate/key, DID or WUA issuer |
| `credentialContext` | VCT, `doctype`, credential configuration, attestation type |
| `evaluationTime` | explicit instant; default only when policy permits |
| `policy` | accepted statuses, revocation requirement, stale-cache allowance |

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

### 5.2 Freshness, cache and availability

The policy must define refresh interval, maximum stale age, clock skew,
`thisUpdate`/`nextUpdate` handling, history retention, and behaviour when a
source is unreachable. A cached authenticated snapshot may support a
diagnostic or explicitly permitted offline mode, but stale data must be
visible in the result and never silently treated as current.

### 5.3 Status, certificate and revocation rules

The resolver must use only entries whose effective service/entity status is
valid under the selected profile. Suspension/cancellation maps to rejection
for new trust decisions. Certificate path validation, key matching and
certificate revocation (CRL/OCSP or the applicable ETSI mechanism) are
separate checks from list signature validation. Credential, WIA and KA
revocation/status-list checks remain separate protocol checks, but their result
must be combinable into one evidence record.

## 6. Delivery phases

### Phase 0 — Contract and fixture readiness

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

### Phase 1 — Signed-list consumption proof

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
GitHub CI as an assertion of trust.

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

### Phase 3 — Integrate issuer and wallet issuance trust

**Objective:** replace structural WUA trust placeholders with opt-in WP4
Wallet Provider trust for issuance.

**Work:**

1. Resolve Wallet Provider anchors for WIA and KA validation.
2. Bind WUA issuer/provider identity to the listed entity and valid status.
3. Combine list trust with WIA, KA, Wallet Instance and WSCD/keystore
   revocation/status checks.
4. Preserve a development compatibility mode, clearly labelled and disabled
   for conformance profiles.
5. Add end-to-end positive, unlisted, withdrawn, stale and rollover tests to
   the existing issuance suites.

**Deliverables:** issuer/wallet trust adapter; configuration; migration notes;
   conformance evidence for UC-TE-03 and the relevant `ISSU_*` requirements.

**Exit criteria:** a self-contained `x5c`/JWK is insufficient by itself when
   strict WP4 trust is enabled, and every rejection is explainable.

### Phase 4 — Integrate verifier credential and certificate trust

**Objective:** enforce provider and access-certificate trust in presentation
and verifier flows.

**Work:**

1. Resolve PID, QEAA, PuB-EAA and applicable non-qualified EAA trust by
   credential context (`vct`, `doctype`, rulebook and issuer identity).
2. Resolve WRPAC/WRPRC anchors and integrate certificate path/revocation
   checks where the verifier or wallet flow requires them.
3. Keep credential signature, key binding, status-list and trust-list results
   distinct but compose them into the final presentation decision.
4. Add DC API coverage through the existing shared verification core rather
   than a separate trust implementation.

**Deliverables:** verifier trust adapter; policy profiles; negative and
   historical-list tests; reports showing the exact anchor and list entry used.

**Exit criteria:** a credential from an unlisted, invalid-status, mismatched,
   or revoked provider is rejected under strict policy, with no weakening of
   existing CS-02/CS-07 structural checks.

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

| Scenario | Required source chain | Initial phase |
| --- | --- | --- |
| Issuer validates WIA/KA | LoTL → Wallet Provider LoTE → WUA issuer anchor → WIA/KA | 1–3 |
| RP validates PID | LoTL → PID Provider LoTE → PID issuer anchor → credential | 1–4 |
| RP validates QEAA | LoTL → national TS 119 612 TL → QTSP/service anchor → QEAA | 1–4 |
| RP validates PuB-EAA | LoTL → PuB-EAA LoTE → provider anchor → EAA | 1–4 |
| Wallet/RP validates access cert | LoTL → WRPAC/WRPRC LoTE → CA/registration anchor → certificate | 1–4 |
| Entity is withdrawn | authenticated history/status → invalid decision | 1–5 |
| Source is stale/unavailable | cached snapshot + freshness policy → explicit result | 1–5 |

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

Project-specific behaviour and current limitations: [`docs/knowledge.md`](../knowledge.md).

The locally downloaded reference bundle and its version decisions are recorded
in [`references/README.md`](references/README.md). It includes the current
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
