# Certificates

Place the WE-BUILD Verifier P12 file here for x509 and dc_api flows:

- **WE-BUILD-Verifier.p12** – Verifier certificate and private key (passphrase:  set `WEBUILD_P12_PASSWORD` env var)

Used by:
- x509 flows (x509_san_dns, x509_san_uri, x509_hash) when `jar_alg` is ES256
- dc_api / dc_api.jwt response mode (e.g. mDL verification)

**Requirements:**
- `openssl` must be installed and available on PATH
