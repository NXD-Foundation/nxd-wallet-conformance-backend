# Agent instructions

This repository is the WE BUILD ITB+ reference issuer, verifier, and
`wallet-client`. Start substantial work from [`docs/knowledge.md`](docs/knowledge.md)
and the [project-knowledge](.cursor/skills/project-knowledge/SKILL.md) skill.

## Bug fixes require a regression test

When you fix a bug, add or extend an automated test in the same change set
that would have failed before the fix and passes after it. Do not ship a
behavioural fix without that coverage.

- Prefer a focused unit test of the helper or check that encodes the rule.
- Add a route-level or wallet-client test when the bug is on a protocol
  boundary (token, credential, proof, presentation).
- Name or describe the test so it states the regression, not only the happy
  path.
- Run the new test (and the nearest existing suite) before calling the work
  done.

Example: a wrong OpenID4VCI proof `iss` value needs both a helper assertion
test and a `/credential` rejection test, not only a wallet construction change.
