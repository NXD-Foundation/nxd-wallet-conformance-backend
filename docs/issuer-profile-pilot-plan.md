# Pilot issuer profiles

The profile map in `utils/issuerProfiles.js` records agreed test assignments,
not legal classifications. Experimental profile metadata and standard offers
are guarded by `ISSUER_PROFILES_ENABLED=true`, which must remain unset in
deployment until complete wallet-to-credential, authorization-code, refresh,
deferred, and trust interoperability tests have passed. Do not expose the
example proxy location until those pieces are complete.

PID variants belong to `pid`; student ID, ferry pass, receipt, and loyalty to
`eaa`; A1/A2, ePassport, PhotoID, and PCD to `pub-eaa`; `qeaa` has no assigned
credentials. JWT VC ID card and payment/SCA configurations remain unassigned
pending an explicit scenario and rulebook decision.

Issuer identifiers will use `https://dev-i4mlab.aegean.gr/rfc-issuer/issuer/`
followed by the profile name. The metadata discovery path inserts
`/.well-known/openid-credential-issuer` after the origin. See
`deploy/nginx/issuer-profiles.conf.example`; verify the complete server block
and run `nginx -t` before deployment. The existing general well-known routing
must continue to support the shared authorization server.

Metadata access and credential-signing certificates are distinct configured
purposes. An operator may select the same key for several CSRs if the issuer
accepts it, but key reuse joins the compromise and rotation lifecycles. Do not
assume a certificate is trusted for a purpose solely because it has that key.
The IDunion direct-listing access-certificate assumption is pilot-specific;
validate actual certificate evidence, chain, and status before enabling live
trust. Unprovisioned roles must fail closed.

Credential signing material is selected by `issuerProfile` on a session, using
`ISSUER_<PROFILE>_CERT_PATH` and `ISSUER_<PROFILE>_KEY_PATH` (hyphens become
underscores), defaulting to the corresponding pilot placeholder and existing
PID key. Missing or mismatched material fails; no other profile is used as a
fallback. This selector does not authorize a profile or make offers by itself.

Profile offers bind the selected profile and configuration to their Redis
session; the credential endpoint checks this binding. The metadata JWT uses
`ISSUER_<PROFILE>_ACCESS_CERT_PATH` and `ISSUER_<PROFILE>_ACCESS_KEY_PATH`,
defaulting to the directly listed pilot access certificate and the existing key.
JSON and JWT metadata advertise only that profile's configurations. This is
pilot material, not verified role entitlement.

Remaining work: verify profile bindings throughout authorization, token,
deferred and refresh flows; wallet expected-role enforcement; full end-to-end
issuance tests; deployment validation and documentation of CS-01/CS-018 status.
Do not claim multi-profile issuance or conformance until these pass.
