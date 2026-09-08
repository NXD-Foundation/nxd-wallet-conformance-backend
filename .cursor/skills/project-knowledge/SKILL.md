---
name: project-knowledge
description: >-
  Orient work in rfc-issuer-v1 using docs/knowledge.md as the project entry
  point. Use at the start of implementation, review, debugging, interop, ITB,
  ITB+, CS-01/02/03/04/07, WUA/KA, OpenID4VCI, OpenID4VP, trust framework,
  or conformance tasks; when docs disagree; or when deciding which spec or
  matrix to read first.
---

# Project Knowledge Base

## Start here

Before substantial work in this repository, **read
[`docs/knowledge.md`](../../docs/knowledge.md)**. It is the maintained entry
point for architecture, decisions, constraints, and where to find detail.

Do not treat `knowledge.md` as a normative specification. For wire behaviour,
follow its **Authority And Reading Order**, then verify current code, config,
and tests.

## Authority order

When sources disagree:

1. Published normative specifications and RFCs (`docs/rfc/`, linked specs).
2. WE BUILD conformance specs in `docs/core/` (no parallel top-level `cs-0*.md` copies).
3. Current code, configuration, and automated tests.
4. Project matrices, plans, and interop notes in `docs/`.

## ITB / ITB+ meaning

In this project, **this codebase** (issuer, verifier, `wallet-client/`, config,
tests) **is** the ITB+ reference deployment unless a document explicitly refers
to upstream WP4 ITB material or a separately hosted instance.

When evaluating interop, conformance, or "what ITB expects", check what this
repository actually implements — not an assumed external test bed.

## Route from Fast Lookup

Use the **Fast Lookup** table in `knowledge.md` to pick the first documents to
read for the area you are changing. Common entry points:

| Area | Start with |
| --- | --- |
| Issuance (offers, PAR, token, proofs, deferred) | CS-01, attestation options, relevant VCI matrix |
| WUA / WIA / KA | CS-04, `docs/issues/cs04-key-attestation-interoperability.md`, future WUA enforcement |
| VP / DCQL / verifier metadata | CS-02, verifier metadata model, VP matrix |
| DC API presentation | CS-07, pinned W3C DC API draft, CS-07 plan |
| Trust framework | `trust/`, WE BUILD trust docs linked from `knowledge.md` |
| mdoc / SD-JWT binding | mdoc generation, mdoc interop fixes, SD-JWT key-binding fixes |

Follow links from `knowledge.md` into companion docs for examples, matrices,
and implementation detail. Read only what the task needs.

## Working rules (carry into tasks)

- Treat matrices as implementation snapshots — confirm against routes, config,
  and tests before changing security behaviour.
- Prefer shared parsing/verification/trust functions across transports; add only
  transport-specific binding checks in handlers.
- Non-obvious project-wide decisions belong in `knowledge.md` (brief) plus a
  focused companion doc (detail). Update `knowledge.md` in the same change set
  when a linked decision, profile interpretation, or support claim changes.
- When a plan is implemented, move its summary from pending to current behaviour
  in `knowledge.md`; keep the plan as historical rationale.

## When to update knowledge.md

Update it when you change:

- A documented architectural decision or constraint
- ITB/ITB+ role or deployment interpretation
- Profile interpretation (CS-01, CS-02, CS-04, CS-07, etc.)
- Protocol support claims or documentation locations
- Fast Lookup routing for a new major area

Do **not** paste long specs or API references into `knowledge.md`; link out.

## Quick orientation checklist

Copy and use at task start:

```
- [ ] Read docs/knowledge.md (at least Project At A Glance + relevant section)
- [ ] Identify authority: spec → docs/core → code/tests → docs/
- [ ] Use Fast Lookup to open the right companion doc(s)
- [ ] Confirm behaviour in code/config/tests before claiming conformance
- [ ] Update knowledge.md if this change alters a recorded decision
```
