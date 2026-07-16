# WE BUILD-Constrained FCAF Alignment Plan

## Purpose

Align the implementation with as much of the submitted `WS_RP` FCAF catalogue
as is compatible with the canonical WE BUILD specifications in `docs/core/`.
`docs/knowledge.md` is the entry point and authority order; where FCAF and WE
BUILD differ, the applicable WE BUILD profile wins.

This plan covers the Wallet Unit and Verifier roles implemented by this
repository and `wallet-client/`. It is an implementation and evidence plan,
not a commitment to make every FCAF scenario an end-to-end test case.

## Scope decisions

| Area | Decision |
|---|---|
| DataModel (142 specs) | Out of scope for this increment. Do not add PID Rulebook, mdoc PID attribute, or claim-value conformance work. |
| TrustMechanisms (14 specs) | Implement required message structures, parsing, key selection, and explicit placeholder results. Do not determine whether an entity is trusted, validate chains to anchors, resolve ETSI TL/AKI, or evaluate revocation state. |
| Negative FCAF cases | Implement the required rejection behaviour and cover it through unit/service/route tests. Do not create a separate E2E flow for each invalid case. |
| CS-02 conflicts | Mark as **inapplicable to strict CS-02**, do not add a compatibility feature just to satisfy FCAF: unsigned request objects, RS384, `x509_hash`, redirect-URI request identity, and non-CS-02 credential formats. |
| ISO mdoc | Preserve current project support and validate transport/structure where it is already a verifier capability. Do not add PID data-model/Rulebook work. |

The target set is therefore: MessageStructure (236), Interaction (71),
SecurityMechanisms (79), Shared (29), and UseCases (2), filtered by the table
above and by the applicable WE BUILD profile: CS-02 for presentation, CS-01
for issuance-related wallet paths, CS-03 only for remote-signing paths, and
CS-04 only for wallet-unit attestation lifecycle paths.

## Delivery model and evidence

Create a machine-readable FCAF applicability register under `FCAFs/` before
feature work. Every submitted WS_RP ID must have one of these dispositions:

- `implemented`: runtime behaviour and at least one focused automated test.
- `partial`: exact missing behaviour and owner phase are recorded.
- `structural-only`: parser/shape/key-binding exists but trust decision is
  intentionally not performed.
- `inapplicable-cs02`: conflicts with strict WE BUILD CS-02; rationale cites
  the relevant section in `docs/core/cs-02-credential-presentation (1).md`.
- `out-of-scope-datamodel`: deferred PID/Rulebook claim work.

Use the register to generate the status tables in the FCAF report. Never
report a percentage that counts an inapplicable, data-model-deferred, or
trust-decision-deferred spec as missing implementation.

Focused tests are the primary evidence for rejection requirements. E2E tests
prove only the representative successful flows listed in the test matrix below.

## Phase 1 — Establish strict-profile boundaries

Consolidate strict-profile selection at the public wallet and verifier entry
points. The same rules must apply to `/vp/request`, request URI retrieval,
wallet presentation, direct-post handlers, and metadata publication.

- Keep signed ES256/P-256 JAR, DCQL, `openid4vp://present`, SD-JWT selective
  disclosure, KB-JWT, nonce/audience binding, and response validation as the
  strict CS-02 baseline.
- Keep all legacy Presentation Exchange, bare `openid4vp://`, unsigned JAR,
  redirect-URI identity, broad algorithm, and compatibility metadata paths
  behind their existing compatibility/profile flags.
- Ensure generated request metadata is the filtered strict CS-02 projection;
  broad deployment metadata may remain for CS-03 or compatibility routes.
- Add a single profile-capability module that exposes allowed request modes,
  client-id schemes, VP formats, JAR/KB-JWT algorithms, JWE algorithms, and
  unsupported FCAF dispositions. Reuse it in validation, generation, and
  metadata routes so advertised and enforced behaviour cannot drift.

Acceptance: strict route generation, wallet validation, and public strict
metadata expose the same capability set; compatibility-only support cannot be
mistaken for CS-02 conformance.

## Phase 2 — Complete MessageStructure coverage

Build on `FCAFs/we-build-cs02-fcaf-message-structure-coverage.md`; retain its
existing DCQL/JAR work and close the remaining protocol gaps.

### Authorization request and request URI

- Enforce request-object precedence over deep-link query parameters and reject
  contradictions before credential selection.
- Enforce request URI method, HTTPS policy, content type, bounded response
  size, timeout, redirect policy, and one signed request object per retrieval.
- Require and validate all strict request claims: `client_id`, `nonce`,
  `state`, `response_uri`, `response_type`, `response_mode`, `aud`, `iat`,
  `exp`, and `dcql_query`.
- Keep nonce validation to URL-safe/base64url syntax plus session freshness;
  make state and nonce lifecycle one-time and bounded in Redis.

### DCQL and credential-format messages

- Expand the current DCQL parser to cover every OpenID4VP 1.0 shape used by
  applicable FCAF tests: credential and claim IDs, `credential_sets`,
  `claim_sets`, `multiple`, supported claim paths, `values`, `vct_values`,
  `doctype_value`, and transaction-data references.
- Define the supported path grammar explicitly. Reject unsupported JSONPath,
  array-index, or nested-object forms rather than silently matching them.
- Make wallet credential selection and verifier response validation use the
  same DCQL evaluator so a query accepted by the wallet can be validated by
  the verifier without divergent cardinality or claim-set rules.
- Preserve SD-JWT compact and `mso_mdoc` structural presentation support;
  classify CWT, JSON serialization, multiple mdoc DeviceResponses, and other
  non-CS-02 formats as compatibility/inapplicable rather than silently
  accepting them in strict mode.

### Authorization response and metadata messages

- Make `direct_post` require form encoding, `vp_token`, and state; make
  `direct_post.jwt` require the `response` parameter and use OpenID4VP 1.0
  unsigned encrypted JWT JSON semantics.
- Validate the decrypted top-level response shape before reading VP content.
- Complete strict client-metadata handling: schema, inline/URI precedence,
  HTTPS URI fetch policy, JWK `kid`/`alg` structure, response-mode-specific
  encryption metadata, and metadata-to-runtime consistency.
- For Token Status List, validate only claim/reference structure (type,
  index, absolute HTTPS URI and supported placement). Record an explicit
  structural-only result; do not fetch, verify, or evaluate list bits.

Acceptance: every applicable MessageStructure requirement has a common parser
or validator, a positive focused test, and rejection coverage where the FCAF
case is negative.

## Phase 3 — Complete Interaction and UseCase flows

Use small end-to-end flows to prove the protocol joins, rather than replicating
each FCAF negative row.

- Cover same-device and cross-device `openid4vp://present` invocation with
  request URI GET and POST.
- Cover strict DCQL request-to-selection-to-submission for one SD-JWT VC, one
  multi-credential `multiple=true` response, and one supported mdoc response.
- Cover `direct_post` and encrypted `direct_post.jwt`; verify state, nonce,
  response endpoint routing, session terminal status, and safe wallet error
  propagation.
- Cover `client_metadata` and `client_metadata_uri` resolution in an E2E flow
  using local HTTPS fixtures, including selected encryption key propagation.
- Cover scope-based and cross-device presentation UseCases only where they can
  be expressed without weakening DCQL-only strict CS-02 behaviour. Otherwise
  classify them as compatibility/inapplicable with an explicit rationale.
- Preserve CS-03 remote-signing and TS-12 flows as separate profile suites;
  verify they do not change CS-02 metadata or request validation.

Acceptance: a compact matrix of successful flows verifies every supported
transport, response mode, credential family, and identity scheme once.

## Phase 4 — Finish SecurityMechanisms without trust decisions

### RP integrity and verifier attestation

- Enforce signed ES256/P-256 JAR verification for `x509_san_dns`,
  `decentralized_identifier:did:web`, and `decentralized_identifier:did:jwk`.
- For X.509, parse `x5c`, select the leaf verification key, validate header
  structure/order, reject key/signature mismatch, and expose a structured
  `trust_not_evaluated` result. Do not validate chain/path/SAN-to-host trust.
- For DID, enforce HTTPS `did:web` resolution, exact `kid` to verification
  method mapping, P-256 JWK structure, and signature verification. These are
  key-resolution checks, not a trusted-DID registry decision.
- For verifier attestation, parse the embedded VA JWT and enforce its compact
  JWT/header/claim structure, time fields, client binding, and JAR-signing-key
  `cnf` binding where key material is supplied. Return `trust_not_evaluated`
  when issuer trust cannot be established; do not accept malformed VA merely
  because trust is out of scope.
- Retain strict rejection of unsigned, RS384, COSE, multi-signed, and
  `x509_hash` tests as CS-02-inapplicable behaviour.

### Device, issuer, and session binding

- Require SD-JWT `cnf.jwk` to be a structurally valid public P-256 JWK where
  holder binding is required; wallet must use the matching stored private key.
- Verify KB-JWT `typ`, signature, nonce, audience, issue time, `sd_hash`, and
  replay identifier; reject duplicates through Redis-backed one-time `jti`
  storage.
- Verify issuer signature using available configured JWK/JWKS/resolver or
  header-carried X.509 leaf key. Treat issuer trust and chain validation as
  structural-only/deferred, but never treat an invalid signature as valid.
- Validate issuer/status claim time and shape. Keep mdoc MSO revocation and
  status-list state as deferred structural-only work, not a successful
  revocation claim.
- Maintain nonce syntax, freshness, and one-time session use for all response
  modes. Make correlation/state checks consistent between direct and encrypted
  response paths.

### Session encryption

- For strict encrypted responses, require a per-request selected EC/P-256
  JWK with `use=enc`, `kid`, and `alg`; persist the key identifier and private
  key reference in the verifier session.
- Select the JWE algorithm exactly from the selected JWK, prefer A256GCM when
  advertised, otherwise use the OpenID4VP A128GCM default or an advertised
  supported algorithm.
- Validate JWE `alg`, `enc`, and `kid` against the stored session key—not only
  broad metadata—and reject success-path encryption failures with a protocol
  error rather than a plaintext downgrade.
- Bind mdoc session transcript encryption-key thumbprint when encrypted
  response support is used; preserve the non-encrypted null thumbprint path.

Acceptance: all SecurityMechanisms rows are either enforced, structural-only,
inapplicable-CS-02, or data-model-deferred; none are described as “covered”
solely because a placeholder returns success.

## Phase 5 — Shared encoding and cryptography

- Centralize base64url, UTF-8 form-body, SHA-256, SD-JWT disclosure digest,
  `sd_hash`, JWK thumbprint, and constant-time comparison helpers.
- Define one canonical representation for request/response JSON before hashing,
  signing, or encrypting; test its byte-level output against OpenID4VP and
  SD-JWT fixtures.
- Expand claim-path and disclosure-digest tests for nested object claims and
  explicit unsupported paths. Leave PID attribute semantics out of scope.
- Add JOSE algorithm/key compatibility checks at import time so unsupported
  curve/algorithm combinations fail before cryptographic operations.

Acceptance: shared helpers are used by wallet and verifier paths; no duplicate
ad-hoc hash, JWK comparison, or base64url logic remains in strict flows.

## Phase 6 — Test architecture and reporting

### Automated tests

- Add table-driven unit tests keyed by FCAF ID/disposition for parsers,
  validators, metadata, DCQL, JAR, KB-JWT, JWE, issuer signature, and trust
  structure. A negative FCAF requirement is satisfied by a focused assertion
  that the runtime rejects it with a stable protocol error.
- Add route/service tests for state transitions, Redis one-time nonce/JTI use,
  request URI fetch limits, response-mode separation, and encryption-key
  session binding.
- Keep a lean E2E suite with successful CS-02 scenarios only: direct-post,
  encrypted direct-post JWT, GET/POST request URI, x509/DID identity, SD-JWT,
  multi-credential, and mdoc structural presentation.
- Keep trust-decision and PID data-model rows skipped with a named reason;
  do not use generic skipped tests that conceal scope.

### Documents and report

- Update `FCAFs/we-build-cs02-fcaf-message-structure-coverage.md` after each
  MessageStructure phase.
- Update `/home/ni/code/fcafs/security-mechanism-analysis/merged-verifier-wallet-sm-coverage.md`
  after each SecurityMechanisms phase.
- Update `/home/ni/code/fcafs/fcaf-coverage-analysis-report.md` from the
  applicability register, replacing estimated percentages with counts by
  disposition and separating implementation evidence from executed-test
  evidence.
- Update `docs/knowledge.md` only when a project-wide profile decision,
  supported capability, or source-of-truth link changes.

## Current baseline (implementation assessed 2026-07-15)

The repository has completed a useful first pass of strict CS-02 enforcement:

- strict ES256 JAR, DCQL-only request, `openid4vp://present`, base64url nonce,
  required state, request-URI, metadata-URI, and response-mode checks exist;
- wallet and verifier validate DCQL IDs, formats, claim/credential sets,
  `multiple`, selected transaction-data structure, and SD-JWT/mdoc request
  constraints;
- `direct_post.jwt` has selected-key JWE validation, compact-JWE shape checks,
  decrypted top-level response validation, and no plaintext-success fallback;
- terminal verifier sessions reject replays; and
- trust inputs have structural-only placeholders, consistent with scope.

The work is **not** yet complete: the register is aggregate-only, not per
FCAF ID (its schema and aggregate consistency are now tested); wallet and verifier still have separate DCQL extraction adapters; verifier
attestation remains structural-only and x5c input parsing is limited to
encoding/leaf-key checks; shared Base64URL/JWK/JSON helpers now cover strict
call paths; and the compact successful E2E
matrix has not been established as plan evidence.

Successful-flow evidence is now covered by
`tests/cs02SuccessfulFlowMatrix.test.js` for selected-key `direct_post.jwt`,
direct-post state correlation, DID:jwk, multi-credential DCQL, selected
metadata encryption, mso_mdoc structure, and X.509 direct-post request shape;
full issuer/wallet cryptographic E2E fixtures remain to be added.

## Execution backlog

Complete the following items in order. Each item is independently shippable
only after its specified tests and register evidence are added.

### A. Make coverage auditable before claiming a percentage

1. Create `FCAFs/we-build-fcaf-dispositions.json` with one entry per submitted
   WS_RP FCAF ID. Each entry must contain:
   `id`, `layer`, `sub_layer`, `disposition`, `we_build_rationale`,
   `implementation_paths`, `test_paths`, and `remaining_gap`.
2. Seed the file from the FCAF source analyses and map every ID to exactly one
   disposition: `implemented`, `partial`, `structural-only`,
   `inapplicable-cs02`, or `out-of-scope-datamodel`.
3. Mark all 142 DataModel IDs `out-of-scope-datamodel`; mark unsigned JAR,
   RS384, `x509_hash`, redirect-URI identity, and non-CS-02 formats
   `inapplicable-cs02`, citing `docs/core/cs-02-credential-presentation (1).md`.
4. Add a test that rejects duplicate/missing IDs and validates the disposition
   schema. Replace the aggregate register only after this validation passes.

Acceptance: every submitted ID has an explicit status and no FCAF percentage
is published until it is derived from this file.

Current audit tooling parses 222 explicit MessageStructure rows and 79
SecurityMechanism rows. The MessageStructure source heading claims 236; the
14-row discrepancy is recorded in `FCAFs/we-build-fcaf-catalogue-inventory.json`
and blocks declaring a complete per-ID register until reconciled.
Evidence-backed overrides currently classify all 301 explicit source-matched IDs:
190 implemented, 0 partial, 38 structural-only, 72 inapplicable to strict CS-02,
and 1 datamodel-deferred. No available source row remains unclassified.

### B. Finish strict request and DCQL message semantics

1. Extract a shared, pure DCQL evaluator for the common semantics currently
   duplicated between `wallet-client/src/lib/cs02DcqlValidation.js`, wallet
   selection, and `utils/cs02VerifierResponse.js`:
   credential IDs, `credential_sets`, claim IDs, `claim_sets`, `multiple`,
   formats, `vct_values`, `doctype_value`, supported claim paths, and string
   `values` constraints.
2. Define the supported path grammar in that evaluator: non-empty string path
   segments only. Explicitly reject array indexes, JSONPath expressions, and
   any unsupported segment type with `invalid_request`.
3. Make wallet selection and verifier response validation call the same
   evaluator. Preserve SD-JWT and mdoc extraction adapters, but do not let
   them implement different cardinality or set-satisfaction rules.
4. Complete strict request-object validation on both sides: validate
   `response_uri` as absolute HTTPS in strict mode, require state/nonce/aud
   correlation consistently, and ensure transaction-data `credential_ids`
   reference known DCQL IDs at the wallet as well as verifier.
5. Add table-driven focused tests for each supported DCQL form and each
   rejected unsupported form. Link the corresponding MessageStructure IDs in
   the disposition file.

Acceptance: the same valid DCQL fixture produces the same satisfaction result
at wallet selection and verifier response validation.

The shared credential-set evaluator is now used by both wallet credential
selection and verifier VP-token validation. Claim extraction remains adapter-
specific (SD-JWT versus mdoc), as intended.
Claim-set option selection is also centralized for the verifier’s SD-JWT and
mdoc adapters; wallet adapters continue to share the same structural rules.
Presentation cardinality semantics (`multiple`) are now represented by a
shared core predicate and covered by dedicated tests.
Unknown credential IDs inside `credential_sets` are also surfaced by the
shared evaluator and rejected by strict verifier response validation.

Backlog B’s shared structural evaluator work is complete for credential sets,
claim-set options, cardinality, and supported claim paths. Remaining B work is
limited to adding evidence mappings for the corresponding FCAF IDs.

### C. Complete response, session, and key lifecycle behavior

1. Extract response validation from `routes/verify/verifierRoutes.js` into a
   pure service that validates direct-post form shape, compact JWE shape,
   decrypted response object, state, and mode consistency.
2. Store an explicit session lifecycle record: `created_at`, `expires_at`,
   `status`, `response_mode`, `nonce`, `state`, selected encryption `kid`, and
   key-reference. Reject expired and terminal sessions before parsing a VP.
3. Add Redis-backed one-time storage for KB-JWT `jti`, scoped to verifier
   session and bounded by session expiry. Reject re-use with a stable protocol
   error.
4. Persist the selected encryption key identifier/reference when generating a
   `direct_post.jwt` request; require JWE `kid`, `alg`, and `enc` to match that
   stored selection, not merely broad client metadata.
5. For encrypted mdoc responses, bind the session-transcript encryption-key
   thumbprint; preserve the existing null thumbprint rule for unencrypted mdoc.
6. Add route/service tests for expiry, terminal replay, duplicate KB-JWT jti,
   selected-key mismatch, direct-post/JWE mode confusion, and state mismatch.

Acceptance: every successful response is tied to exactly one unexpired session,
one response mode, one nonce/state pair, and—when encrypted—one selected key.

### D. Complete structural-only RP, VA, issuer, and status inputs

1. Add an x5c parser that rejects malformed base64 certificates, empty chains,
   unsupported leaf key type/curve/algorithm, and inconsistent JAR `kid`.
   Extract the leaf verification key. Return `trust_not_evaluated`; do not
   perform chain/SAN/anchor validation.
2. Parse the embedded verifier-attestation JWT instead of checking only its
   compact shape. Require JOSE header and payload object, `iss`, `sub`,
   `iat`, `exp`, verifier/client binding, and a JAR-signing-key `cnf` binding
   when the required material is present. Reject malformed or unbound VA; keep
   issuer trust as `trust_not_evaluated`.
3. Standardize SD-JWT issuer-verification outcomes: valid signature with local
   key material is `implemented`; unavailable issuer key source is
   `structural-only`; invalid signature is rejected. Do not report the latter
   as a successful trust check.
4. Keep status-list and trusted-authority validation structural-only: validate
   type/index/HTTPS URI and authority array shape; never fetch/evaluate a
   status list or authority registry in this increment.
5. Add fixtures for valid structural inputs and malformed inputs, with each
   trust-decision test explicitly skipped and labelled `trust-framework-out-of-scope`.

Acceptance: malformed structural trust/VA/X.509 input cannot pass merely
because trust evaluation is deferred.

### E. Consolidate shared strict-profile crypto and encoding helpers

1. Move strict base64url syntax, nonce syntax, JWK EC/P-256 checks, JWK public
   equality/thumbprints, compact-JWT/JWE shape checks, and JSON/form encoding
   into shared helpers consumed by wallet and verifier.
2. Define canonical JSON serialization for response hashing/signing/encryption
   where a protocol value is hashed. Add byte-level fixture tests for
   `sd_hash`, disclosure digests, JWK thumbprints, and JWE plaintext JSON.
3. Add import-time JOSE compatibility checks for every strict key: EC/P-256,
   the required `use`, `kid`, and allowed algorithm. Reject incompatible
   combinations before a signing/decryption operation.
4. Remove or quarantine compatibility-only helpers from strict call paths.

Acceptance: strict wallet and verifier flows have one implementation of each
security-sensitive encoding/key check.

### F. Add the compact successful flow matrix

Implement only successful E2E scenarios; invalid cases stay in focused tests.

| Scenario | Required evidence |
|---|---|
| X.509 + SD-JWT + `direct_post` | signed JAR, GET request URI, state/nonce, KB-JWT, disclosed claims |
| DID:web + SD-JWT + `direct_post` | HTTPS DID resolution and exact `kid` selection |
| DID:jwk + SD-JWT + `direct_post.jwt` | POST request URI, selected JWE key, encrypted top-level response JSON |
| Multi-credential DCQL | `multiple=true` and `credential_sets` satisfaction |
| mso_mdoc structural flow | doctype, requested claims, session transcript rules |
| `client_metadata_uri` flow | local HTTPS fixture, inline precedence, selected response encryption key |

Add one test file per scenario or one data-driven suite. Each scenario must
write its evidence paths into the per-ID disposition register.

Acceptance: every supported transport, identity scheme, response mode, and
credential family is proven once without adding negative E2E variants.

### G. Regenerate the FCAF report and close the plan

1. Generate counts from `we-build-fcaf-dispositions.json` by layer and
   disposition. Report implemented and structural-only counts separately.
2. Update the three FCAF reports and `docs/knowledge.md` links from generated
   data. Remove hand-estimated percentages.
3. Add CI commands for the register schema/coverage test, focused CS-02 tests,
   and compact successful flow matrix.
4. Perform a final review: every `partial` row must name a concrete next step;
   every skipped test must name either `trust-framework-out-of-scope` or
   `datamodel-out-of-scope`.

Acceptance: the report is reproducible from code/test evidence and each
remaining gap is deliberate, visible, and within the agreed scope.

The disposition register and MessageStructure coverage report are now
synchronized from the same evidence-backed counts. Dedicated validation
commands are available as `npm run test:fcaf-register` and
`npm run test:cs02-flow`; the combined `npm run test:cs02` remains the full
strict-profile gate. The register CLI also supports `--by-layer` for generated
MessageStructure/SecurityMechanisms summaries. The remaining G work is wiring
that generated output into release reporting, not a claim that the
still-unclassified catalogue rows are covered.

## Completion criteria

- Every non-DataModel submitted WS_RP FCAF ID is present in the applicability
  register with evidence or an explicit, WE BUILD-cited disposition.
- Strict CS-02 paths never weaken signed JAR, DCQL, ES256/P-256, KB-JWT,
  nonce/audience, or encrypted-response requirements to satisfy a broader
  FCAF scenario.
- Trust-related inputs are structurally parsed and bound where required, while
  the report clearly states that trust decisions and revocation evaluation are
  not performed.
- Negative requirements have focused rejection coverage; E2E coverage remains
  limited to representative successful flows.
- The FCAF report contains counts by disposition and links to the tests and
  implementation modules that provide the evidence.
