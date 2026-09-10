# WP4 Trust Group documentation snapshot

Local copy of the WE BUILD trust-framework documentation from
[webuild-consortium/wp4-trust-group](https://github.com/webuild-consortium/wp4-trust-group).

This folder is a **working snapshot**, not a git submodule and not a
replacement for published ETSI/eIDAS specifications. Refresh it from
`main` when WP4 onboarding, LoTL pointers, or the implementation profile
change.

## Provenance

| Field | Value |
| --- | --- |
| Upstream | https://github.com/webuild-consortium/wp4-trust-group |
| Commit | `c1b94bb4bc054e9b94df2a6a4b1daaee62b8a855` |
| Commit date | 2026-09-03 20:40:23 +0200 |
| Snapshot date | 2026-09-10 |
| Included | README, LICENSE, `lotl/tl_entries/`, task 1–7 markdown, `references/etsi` |
| Omitted | Git metadata, GitHub Actions, Python tooling/tests, `lotl/pages` site assets |

Published LoTL (not stored here; fetched at runtime):

- JSON: https://webuild-consortium.github.io/wp4-trust-group/list_of_trusted_lists.json
- XML: https://webuild-consortium.github.io/wp4-trust-group/list_of_trusted_lists.xml

## Start here in this repository

| Question | Read |
| --- | --- |
| How an issuer must evaluate a Wallet Unit | [task1-use-cases/subtask1-2-trust-registry/credential-issuer-evaluates-wallet-unit.md](task1-use-cases/subtask1-2-trust-registry/credential-issuer-evaluates-wallet-unit.md) (UC-TE-03) |
| How to fetch and authenticate LoTL/LoTE | [task1-use-cases/subtask1-2-trust-registry/trusted-list-discovery-consumption.md](task1-use-cases/subtask1-2-trust-registry/trusted-list-discovery-consumption.md) (UC-TE-06) |
| Wallet Provider LoTE profile (Annex E) | [task3-x509-pki-etsi/etsi_trusted_lists_implementation_profile.md](task3-x509-pki-etsi/etsi_trusted_lists_implementation_profile.md) §7.2 |
| LoTL pointer + `trust_anchor` automation | [task4-trust-infrastructure-api/lotl-automation-and-tl-integration.md](task4-trust-infrastructure-api/lotl-automation-and-tl-integration.md) |
| Pilot Wallet Provider TLP entry | [lotl/tl_entries/wallet-provider/idunion.json](lotl/tl_entries/wallet-provider/idunion.json) |
| Wallet Provider onboarding | [task1-use-cases/subtask1-1-onboarding/trusted-lists-onboarding.md](task1-use-cases/subtask1-1-onboarding/trusted-lists-onboarding.md) |

Runtime consumption code lives in [`trust/`](../../trust/), with the pilot
profile at [`data/trust/webuild-wp4-pilot.json`](../../data/trust/webuild-wp4-pilot.json).
Older ITB+ notes and the ETSI PDF bundle remain under
[`docs/WE_BUILD_Trust_Framework/`](../WE_BUILD_Trust_Framework/).
