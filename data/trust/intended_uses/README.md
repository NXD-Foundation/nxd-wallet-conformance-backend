# Raidiam intended-use registration bodies

These are draft request bodies for:

`POST /eudi/wrp/{RPID}/services/{SID}/intended-uses`

All 13 bodies use `https://www.aegean.gr/` as the test-infrastructure privacy URL.
This is a university homepage placeholder, not a dedicated privacy
notice. HTTPS reachability returned HTTP 200 on 20 October 2026. Review the purpose and attributes against the pilot scenarios you operate.
These files do not create registrations or issue WRPRCs by themselves.

## Scenarios and source mapping

| File | Current source |
| --- | --- |
| `pid-basic.json` | `data/dc-api-config.json: profiles.pid-basic` |
| `qualified-signing.json` | `data/dc-api-config.json: profiles.qualified-signing` |
| `ts12-dpc.json` | `data/dc-api-config.json: profiles.ts12-dpc` |
| `ts12-dpc-pid.json` | `data/dc-api-config.json: profiles.ts12-dpc-pid` |
| `ts12-iban.json` | `data/dc-api-config.json: profiles.ts12-iban` |
| `ts12-iban-pid.json` | `data/dc-api-config.json: profiles.ts12-iban-pid` |
| `ts12-user.json` | `data/dc-api-config.json: profiles.ts12-user` |
| `ts12-user-pid.json` | `data/dc-api-config.json: profiles.ts12-user-pid` |
| `pid-mdoc.json` | `utils/routeUtils.js: DEFAULT_MDL_DCQL_QUERY` |
| `age-over-18-mdoc.json` | `routes/verify/mdlRoutes.js: AGE_VERIFICATION_DCQL_QUERY` |
| `pid-arf.json` | `utils/routeUtils.js: ARF_PID_DCQL_QUERY` |
| `ts12-dpc-pid-standalone.json` | `utils/routeUtils.js: TS12_DPC_PID_DCQL_QUERY` |
| `pid-sd-jwt-full.json` | `data/presentation_definition_pid.json (legacy full PID template)` |

`ts12-payment` is an alias of `ts12-dpc` in the checked-in DC API configuration;
use the same intended use rather than registering a duplicate.

The default SD-JWT PID scenario (`pid-basic`) requests only `family_name`.
`pid-sd-jwt-full` is a separate, broader legacy template, not the default request.
The mdoc PID scenario requests `nationality`, not `age_over_18`; this differs from
the older registration draft under `docs/WE_BUILD_Trust_Framework/nxd-submission`.
Payment scenarios use current SCA VCT URLs, not the old transaction-data type
`urn:eudi:sca:payment:1` as a credential VCT.

The combined payment/PID scenarios include the union of all potentially requested
PID claims, including optional email, phone number, and address. The declarations
do not make those optional claims mandatory in presentation requests. Request
IDs, `claim_sets`, and presentation workflow fields are not registration fields.

The CSC X.509 signing body preserves `certificatePolicies` and omits claims because
the source query has no claims. Raidiam accepted and issued the signing scenario
during the live sandbox run; signer trust remains subject to the same checks as
all other scenarios.

Coverage is the checked-in DC API profiles, default PID/age mdoc requests, ARF PID,
standalone TS-12 DPC PID, and the full PID template discussed during onboarding.
Caller-supplied custom DCQL, other legacy presentation definitions, and dynamic
payment overrides need their own declarations if deployed. A registration is tied
to the selected intended use; do not assume one WRPRC authorizes all these bodies.

## Provision all scenarios

From the repository root:

```bash
# Lists the 13 declarations without API calls or certificate/key reads.
node scripts/provisionRaidiamWrprc.js --dry-run

# Uses verified TLS. Supply the server CA chain when it is not system-trusted.
RAIDIAM_TLS_CA=/path/to/trusted-server-ca-chain.pem \
  node scripts/provisionRaidiamWrprc.js
```

The command obtains a certificate-bound OAuth token with `directory:software`,
reconciles existing intended-use registrations and issued certificates, and
provisions missing certificates. It validates each signed JWT's signature,
expiry, registrar trust, entity binding, intended-use scope, purpose and privacy
URL before activating it. Registrar trust uses the configured WE BUILD trust
profile (`TRUST_PROFILE_PATH`); the transport CA option does not establish
registrar trust. An explicitly supplied CA bundle may contain a trusted intermediate
(Node.js `allowPartialTrustChain`); only that supplied anchor is trusted. No
TLS-verification bypass is provided.

Defaults bind to entity `VATEL-090264862`, service
`4c3ecfb0-76ff-4eea-8e51-c8fac931e186` and the local WRPAC and transport files
listed below. The WRPAC entity/service subject, certificate validity, transport
service and key pairing are checked locally before requesting an OAuth token.

Optional environment settings:

| Variable | Purpose |
| --- | --- |
| `RAIDIAM_CLIENT_ID` | Complete OAuth Client ID when different from service ID |
| `RAIDIAM_TRANSPORT_CERT`, `RAIDIAM_TRANSPORT_KEY` | Matching mTLS credentials |
| `RAIDIAM_WRPAC` | Explicit provisioning WRPAC override; otherwise uses `TRUST_WRPAC_CERT_PATH` or the shared ES256 default |
| `RAIDIAM_TLS_CA` | Trusted server CA bundle; TLS verification stays enabled |
| `RAIDIAM_AUTH_URL`, `RAIDIAM_API_URL` | Sandbox authentication/API origins |
| `RAIDIAM_REGISTRY_URI` | Public registry service URI; signed token URI takes precedence |
| `TRUST_WRPRC_MANIFEST_PATH` | Default `certs/raidiam/registration/manifest.json` |
| `RAIDIAM_RPID`, `RAIDIAM_SID` | Explicit alternate identity, which must match WRPAC |

The manifest records each scenario's canonical declaration hash, intended-use
identifier, matching registrar dataset, relative certificate filename and expiry.
It is replaced atomically; previous manifest snapshots and token files are kept.
Issued tokens are first saved to content-addressed `.unverified.*.jwt` quarantine
files. `quarantineFile`, `certificateId`, and `registryStatus` record issuance
even if validation fails. Only a verified token gains an active `certificateFile`;
quarantine files must never be selected for requests.
OAuth tokens and private keys are never persisted or printed. Keep the certificate
store outside version control. A lock prevents concurrent provisioning commands;
after an interrupted process, remove its `.lock` only after confirming no process
is still running.

Rerun this same command to renew. An unchanged declaration with a valid verified
local token makes no API call for that scenario. Saved registration identifiers
and live list reconciliation avoid duplicate registrations after partial failures.
Unrecognized response schemas or ambiguous matches fail closed. The command
continues other scenarios, reports safe per-scenario diagnostics and exits nonzero
if any is unavailable. Unsupported credential formats, particularly CSC signing,
remain blockers rather than silently changing the declaration. The sandbox list schema (`certId`, `coversIntendedUseId`,
`registrationCertificate`) is supported. Issuance success alone does not establish
registrar trust: a signer absent from the configured WE BUILD LoTE leaves the
scenario quarantined and unavailable. Expired tokens can renew; malformed or
untrusted remote certificates fail without issuing duplicates.

## Submit one intended use

### Certificate and service binding

The WRPAC was replaced with the P-256/ES256 certificate on 21 October 2026:

- WRPAC: `certs/raidiam/uAaqzBHXMTOW0maXduvtPyAgFWY2RppjzxH5ucvky7U.pem`.
- WRPAC subject organisation: `University of the Aegean`, country `GR`.
- WRP identifier (`organizationIdentifier`): `VATEL-090264862`.
- Service/Application ID (WRPAC `OU`): `4c3ecfb0-76ff-4eea-8e51-c8fac931e186`.
- WRPAC signing algorithm: ES256 (P-256).
- WRPAC `client_id`: `x509_hash:uAaqzBHXMTOW0maXduvtPyAgFWY2RppjzxH5ucvky7U`.
- WRPAC DNS SAN: `dev-i4mlab.aegean.gr`.
- WRPAC SHA-256 fingerprint: `B8:06:AA:CC:11:D7:31:33:96:D2:66:97:76:EB:ED:3F:20:20:15:66:36:46:9A:63:CF:11:F9:B9:CB:E4:CB:B5`.
- API transport certificate: `certs/raidiam/Trust_Registry_API authentication/trust_api_call.pem`.
  Its subject CN matches the same Application ID.

Both certificates passed OpenSSL chain verification using the local
`certs/raidiam/eudi-sandbox-issuing-ca-g1.pem` as a trusted intermediate
(`-partial_chain`). This checks signatures and validity against that supplied
CA; it is not a revocation check or an independent verification of the CA source.
The initial public-certificate inspection did not read private keys. The
provisioning command checks the transport certificate/key pair locally and uses
it for mTLS; it does not print or export the private key.

These intended-use bodies contain requested credential formats/types and claims,
not the verifier's certificate. Do not add `x5c`, a WRPAC PEM, certificate paths,
or private keys to the POST bodies. `credentials` describes credentials requested
from the wallet; the RPID/SID URL path selects the registered relying-party service.
The transport certificate authenticates API calls. The WRPAC is used separately
by the verifier for wallet-facing authentication/presentation requests.

Set `API`, `CERT`, `KEY`, and `ACCESS_TOKEN` using the transport certificate flow.
The certificate/key used here must match the certificate-bound access token.

```bash
# Run from the repository root. Keep paths quoted because they contain spaces.
CERT="$PWD/certs/raidiam/Trust_Registry_API authentication/trust_api_call.pem"
KEY="$PWD/certs/raidiam/Trust_Registry_API authentication/4c3ecfb0-76ff-4eea-8e51-c8fac931e186-rtstransport.key"
API='https://matls-api.sandbox.eudi.raidiam.io'
RPID='VATEL-090264862'
SID='4c3ecfb0-76ff-4eea-8e51-c8fac931e186'
BODY='data/trust/intended_uses/pid-basic.json'

# Run from the repository root. The university homepage is a test placeholder.
if jq -e '.privacyPolicy[].url | contains("example.invalid")' "$BODY" >/dev/null; then
  echo 'Replace the privacy notice URL before submitting.' >&2
else
  curl --fail-with-body -sS --request POST \
    "$API/eudi/wrp/$RPID/services/$SID/intended-uses" \
    --cert "$CERT" --key "$KEY" \
    --header "Authorization: Bearer $ACCESS_TOKEN" \
    --header 'Content-Type: application/json' \
    --data-binary "@$BODY"
fi
```

Use `--cacert /path/to/raidiam-ca-chain.pem` if your system does not trust the
sandbox server chain. Raidiam's examples use `-k` for the sandbox, which disables
server certificate verification.

Record each returned `intendedUseIdentifier` alongside its filename. Use that
specific identifier as `intendedUseId` when posting to
`/eudi/wrp/{RPID}/services/{SID}/registration-certificates`. Avoid selecting the
first entry in a list, which can certify the wrong intended use. Store issued
certificates separately from these request bodies.

Sources:
- https://www.raidiam.com/developers/docs/raidiam-webuild-eudi-ecosystem-docs/manage-intended-uses-and-certificates/
- https://www.raidiam.com/developers/docs/raidiam-webuild-eudi-ecosystem-docs/connect-to-trust-registry-apis/

## Live issuance result (20 October 2026)

All 13 intended uses and registration certificates were created in the Raidiam
sandbox. Their IDs and quarantined token filenames are recorded in
`certs/raidiam/registration/manifest.json`. All 13 tokens passed offline signature,
expiry, subject, intended-use, query-scope and dataset checks. None was activated:
the configured WE BUILD LoTL/LoTE resolver returned `ENTITY_NOT_LISTED` for the
`EUDI Sandbox Registration Certificate Signer` (Raidiam Services Ltd).

This requires recognition of that signer through the configured trust framework;
no local bypass or implicit trusted-signer fallback has been added. After the
trusted-list issue is resolved, rerun provisioning to validate and activate the
existing certificates. Reruns reconcile `coversIntendedUseId` and `certId` from the
live API rather than issuing duplicates for a trust rejection.

Trust-enabled requests fail until their scenario has an activated certificate.
Use `wrprc_scenario=<scenario filename without .json>` on a request URL to select
an explicit scenario for a custom query. Known route/profile defaults select their
scenario before checking the finalized query. A changed local declaration requires
reprovisioning, even if a previous token has not expired. Query scope never grants
access merely because another scenario's certificate covers the same attributes.

`TRUST_WRPRC_CERT_PATH` is not used to select registration JWTs. Configure
`TRUST_WRPRC_MANIFEST_PATH` for the local issued-certificate manifest instead.


## Registrar datasets without WRPRC trust

Strict CS-02 requests include `verifier_info: [{ format: "registrar_dataset", data: ... }]`
when trust enforcement is disabled. Selection still checks the registered scenario,
WRPAC entity/service, declaration hash and requested credential/claim scope. A
retained `registrarDataset` is preferred; otherwise the dataset is reconstructed
from the saved registrar-issued `intendedUseId` and the submitted declaration.
The purpose also supplies the service-description fallback. The public service
registry URI defaults to `https://data.sandbox.eudi.raidiam.io/wrp/{entityId}/services/{serviceId}`
and can be overridden with `RAIDIAM_REGISTRY_URI`.

This metadata is signed inside the verifier request; its inclusion does not
establish independent registrar trust. Neither `quarantineFile` nor an active
certificate file is opened for dataset-only requests. The selection is pinned in
the VP session, so replacing the manifest does not silently change an existing
request's registration identity. Sessions created before dataset pinning must be
recreated. Compatibility mode retains its previous optional-metadata behavior.

With `trustFramework=true`, a trusted activated registration JWT remains required.
The Raidiam JWTs stay quarantined until their signer is recognised by the configured
WRPRC-provider trust policy; there is no dataset-only fallback for that mode.
