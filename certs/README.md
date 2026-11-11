# Certificates

Place the WE-BUILD verifier certificate material here for x509 and dc_api flows:

Canonical key-role inventory: `../utils/keyMaterialPaths.js` and
`../docs/knowledge.md`.

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

Ordinary remote CS-02 presentation sessions use the original EUDI preproduction
`WE-BUILD-Verifier.p12` and the `pidissuerca02_eu.pem` chain through the
existing P12 loader (`WEBUILD_P12_PASSWORD`). Explicit
`trustFramework=true` sessions retain the Raidiam WRPAC and registration
validation. Ordinary EUDI P12 sessions omit Raidiam `verifier_info`; consequently
they are interoperability cases rather than full CS-02 v1.2 conformance cases.
CS-03 and CS-07 certificate selection is unchanged. Existing request URIs retain
their session's signing profile; create a new session to use the new default.

## WE BUILD trust-suite deployment

The [main Compose file](../docker-compose.yml) mounts a single read-only
directory. Put these two files in `secrets/` next to the VM's Compose file,
or set `RFC_ISSUER_SECRETS_DIR` to use an existing directory:

- `wrpac.key` is the private key matching the Raidiam verifier WRPAC. It
  signs VP requests for the service registered in the WRPRC manifest.
- `issuer-metadata.p12` contains the issuer's listed access certificate, its
  matching key, and any necessary intermediates. For the dev-i4mlab issuer,
  use `certs/we-build-wrpac.pem` and its matching key. The leaf is directly
  listed.

For dev-i4mlab, create the metadata bundle with restricted permissions, using
the same password configured for `WEBUILD_P12_PASSWORD` in the container
(the application defaults to `webuild`).

```sh
umask 077
mkdir -p secrets
openssl pkcs12 -export -in certs/we-build-wrpac.pem \
  -inkey /path/to/matching-issuer-key.pem \
  -out secrets/issuer-metadata.p12
```

Copy both files to the VM's secrets directory. Keep the VM service's existing
`image:` and `SERVER_URL`, and copy the signing environment variables and
directory mount from the main Compose file into that service. Run
`docker compose pull` and `docker compose up -d --no-build` on the VM.

For VP-001, send `trustFramework=true` and omit `response_mode`.
The request must use `x509_hash` and the retrieved JAR must use
`direct_post.jwt` and include both registration entries in `verifier_info`.
