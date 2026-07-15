# Reference Documents

Fetched on `2026-07-15` to support the core specs in `docs/core/RFC001.md`, `docs/core/RFC002.md`, and `docs/core/RFC004.md`.

## Local copies

### OpenID / OpenID4VC

- `openid/openid-4-verifiable-credential-issuance-1_0.html`
  - Source: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>
  - Used by: RFC001
- `openid/openid-4-verifiable-presentations-1_0.html`
  - Source: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
  - Used by: RFC001, RFC002
- `openid/openid4vc-high-assurance-interoperability-profile-1_0.html`
  - Source: <https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html>
  - Used by: RFC001, RFC002

### EU / ARF

- `eu/arf-v1.0.0.pdf`
  - Source download page: <https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework>
  - Direct download used: <https://ec.europa.eu/newsroom/dae/redirection/document/93678>
  - Used by: RFC001, RFC002, RFC004
- `eu/eudi-wallet-arf-page.html`
  - Source: <https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework>
  - Notes: Saved as the landing page for the ARF publication.

### APTITUDE trust material

- `aptitude/deliverable-2.1-trust.html`
  - Source: <https://aptitude-consortium.github.io/wp2-trust-specifications/latest/deliverable-2.1-trust/>
  - Used by: RFC004
- `aptitude/trust-management-process.html`
  - Source: <https://aptitude-consortium.github.io/wp2-trust-specifications/pr-46/pr-workspace/trust-management-process/>
  - Used by: RFC004

### IETF / RFCs

- `ietf/draft-ietf-oauth-status-list.html`
  - Source: <https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/>
  - Used by: RFC004
- `ietf/rfc2119.txt`
  - Source: <https://www.rfc-editor.org/rfc/rfc2119.txt>
  - Used by: RFC001, RFC002, RFC004
- `ietf/rfc8174.txt`
  - Source: <https://www.rfc-editor.org/rfc/rfc8174.txt>
  - Used by: RFC001, RFC002, RFC004
- `ietf/rfc5280.txt`
  - Source: <https://www.rfc-editor.org/rfc/rfc5280.txt>
  - Used by: RFC004
- `ietf/rfc6960.txt`
  - Source: <https://www.rfc-editor.org/rfc/rfc6960.txt>
  - Used by: RFC004

## Items not mirrored as full local source

### ETSI PDFs

Official URLs:

- <https://www.etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf>
- <https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf>

Current local status:

- `etsi/ts_11947202v010201p-firewall.html`
- `etsi/ts_11947203v010101p-firewall.html`

Notes:

- Direct `curl` fetches returned ETSI Web Application Firewall HTML instead of the PDF payload.
- The URLs are still the canonical document locations and can be opened in a browser when needed.
- RFC001 references ETSI TS 119 472-3.
- RFC002 references ETSI TS 119 472-2.

### ISO documents

The following standards are referenced by RFC002 but were not mirrored here as full text because they are typically distributed through ISO channels rather than as public direct-download documents:

- ISO/IEC TS 18013-7:2025
- ISO/IEC 18013-5:2021

If you want, the next step can be adding browser-exported local copies or catalog/landing pages for the ISO and ETSI items as well.
