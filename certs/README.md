# Certificates

The Aptitude issuer uses the EUDI pre-production signing material in this
directory for signed metadata and X.509-backed credential issuance:

- **WE-BUILD-Verifier.p12** – EUDI-issued ES256 leaf certificate and private
  key. Set its password with `WEBUILD_P12_PASSWORD`.
- **pidissuerca02_eu.pem** – PID Issuer CA 02 trust anchor from the EUDI Wallet
  Reference Implementation.

Used by:
- signed Credential Issuer metadata
- X.509-backed SD-JWT and mdoc credential issuance

The issuer sends only the leaf in its metadata `x5c` and credential `x5chain`.
The CA is verified locally and must be configured as a trust anchor by the
wallet; it must not be sent as a trust-anchor entry in `x5c`.

**Requirements:**
- `openssl` must be installed and available on PATH
