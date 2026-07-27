# WE BUILD trust-framework reference bundle

This folder contains the local reference set used to refine the ITB+ trust
framework design. PDFs are downloaded from official ETSI publication URLs;
RFC 5280 is downloaded from the RFC Editor. The WP4 documents are local
copies of the relevant design and implementation guidance from the checked-out
`/home/ni/code/wp4-trust-group` repository.

The bundle is a working reference set, not a replacement for normative
specifications or a claim that every document is licensed for redistribution.
When distributing this repository, check the applicable ETSI and EU legal
notices. The authoritative source and retrieval date are recorded below.

## Normative/core references

| Local file | Role | Source/version decision |
| --- | --- | --- |
| [`etsi/ts_119602_v1.1.1_2025-11.pdf`](etsi/ts_119602_v1.1.1_2025-11.pdf) | LoTE data model and JSON/XML bindings | ETSI TS 119 602 V1.1.1; WP4 core |
| [`etsi/ts_119612_v2.4.1_2025-08.pdf`](etsi/ts_119612_v2.4.1_2025-08.pdf) | National Trusted List / TSL format | ETSI TS 119 612 V2.4.1; WP4 core |
| [`etsi/ts_119615_v1.3.1_wp4-reference.pdf`](etsi/ts_119615_v1.3.1_wp4-reference.pdf) | National-TL consumption baseline used by WP4 | ETSI TS 119 615 V1.3.1 |
| [`etsi/ts_119615_v1.4.1_2026-05.pdf`](etsi/ts_119615_v1.4.1_2026-05.pdf) | Current national-TL consumption review baseline | ETSI TS 119 615 V1.4.1; published May 2026 |
| [`etsi/ts_119312_v2.1.1_2026-06.pdf`](etsi/ts_119312_v2.1.1_2026-06.pdf) | Cryptographic suites and algorithm policy | ETSI TS 119 312 V2.1.1 |
| [`ietf/rfc5280.txt`](ietf/rfc5280.txt) | X.509 certificate path and CRL profile | IETF RFC 5280 |

TS 119 615 V1.4.1 should be reviewed for the production/national-TSL
profile. Do not silently change the WP4 pilot conformance baseline from
V1.3.1 until WP4 confirms the version and any profile deltas.

## Supporting EUDI trust and credential profiles

| Local file | Role |
| --- | --- |
| [`etsi/ts_119411-8_v1.1.1_2025-10.pdf`](etsi/ts_119411-8_v1.1.1_2025-10.pdf) | Access Certificate Policy for EUDI Wallet Relying Parties |
| [`etsi/ts_119475_v1.1.1_2025-10.pdf`](etsi/ts_119475_v1.1.1_2025-10.pdf) | Relying-party attributes supporting wallet authorization decisions |
| [`etsi/ts_119472-1_v1.2.1_2026-02.pdf`](etsi/ts_119472-1_v1.2.1_2026-02.pdf) | General EAA profile requirements |
| [`etsi/ts_119472-2_v1.1.1_2025-12.pdf`](etsi/ts_119472-2_v1.1.1_2025-12.pdf) | EAA/PID presentation profiles |
| [`etsi/ts_119472-3_v1.1.1_2026-03.pdf`](etsi/ts_119472-3_v1.1.1_2026-03.pdf) | EAA/PID issuance profiles |
| [`ietf/rfc5280.html`](ietf/rfc5280.html) | Browsable RFC 5280 copy |

These documents do not define the LoTL/LoTE structure. They become relevant
when the resolver’s result is applied to access certificates, credential
issuers, EAA/PID presentations or issuance policy.

## WP4 implementation and policy guidance

These files are copied from the checked-out WP4 repository and are informative
for ITB+ implementation unless a cited normative specification says
otherwise:

- [`etsi/wp4-etsi-trusted-lists-implementation-profile.md`](etsi/wp4-etsi-trusted-lists-implementation-profile.md)
- [`framework/wp4-trust-infrastructure-schema.md`](framework/wp4-trust-infrastructure-schema.md)
- [`framework/wp4-trusted-list-registration-trust-evaluation-matrix.md`](framework/wp4-trusted-list-registration-trust-evaluation-matrix.md)
- [`framework/wp4-trusted-list-discovery-consumption.md`](framework/wp4-trusted-list-discovery-consumption.md)
- [`framework/wp4-lotl-automation-and-tl-integration.md`](framework/wp4-lotl-automation-and-tl-integration.md)

## Legal/framework references

The local legal downloads attempted from EUR-Lex were unavailable in the
current environment, so the authoritative links are recorded here rather
than leaving empty placeholder files:

- Commission Implementing Decision (EU) 2015/1505:
  <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32015D1505>
- Regulation (EU) 2024/1183:
  <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1183>
- EUDI Wallet Architecture and Reference Framework 2.9.0:
  <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/tree/v2.9.0>

## Official download sources

- TS 119 602: <https://www.etsi.org/deliver/etsi_TS/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf>
- TS 119 612: <https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf>
- TS 119 615 V1.3.1: <https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.03.01_60/ts_119615v010301p.pdf>
- TS 119 615 V1.4.1: <https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf>
- ETSI ESI publication catalogue: <https://www.etsi.org/technical-groups/esi/>
- RFC 5280: <https://www.rfc-editor.org/rfc/rfc5280>

