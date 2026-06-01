# Certificates

Place the WE-BUILD verifier certificate material here for x509 and dc_api flows:

- **WE-BUILD-Verifier.p12** - Verifier leaf certificate and private key (set `WEBUILD_P12_PASSWORD`)
- **pidissuerca02_eu.pem** - PID Issuer CA 02 EU certificate used to extend JAR `x5c` for ES256 x509 flows

Used by:
- x509 flows (`x509_san_dns`, `x509_san_uri`, `x509_hash`) when `jar_alg` is `ES256`
- `dc_api` / `dc_api.jwt` response mode (for the verifier signing certificate)

Notes:
- `pidissuerca02_eu.pem` provenance: EUDI Android Wallet reference repo (`resources-logic/src/main/res/raw/pidissuerca02_eu.pem`)
- Override the CA PEM path with `WEBUILD_X5C_CA_PEM=/abs/or/relative/path.pem`
- Set `WEBUILD_X5C_ALLOW_LEAF_ONLY=true` only as an explicit interop fallback when the CA PEM is unavailable

Requirements:
- `openssl` must be installed and available on `PATH`
