# Pre-ship ITB flow

Run it with:

```bash
npm run test:pre-ship
```

When port 6379 is closed, the command starts a `redis:7-alpine` container named `pre-ship-redis` on `127.0.0.1:6379` and removes it at the end. An existing Redis on that port is left as it is. With `ISSUER` and `WALLET` unset, the command starts ngrok for ports 3000 and 4000, then starts the issuer and `wallet-client` when those ports are free. Set both variables to use tunnels that are already up:

```bash
ISSUER=https://issuer.example WALLET=https://wallet.example npm run test:pre-ship
```

One case, or a comma-separated list:

```bash
npm run test:pre-ship -- --case=VCI-001,VP-001
```

The command stops the Redis container, issuer, wallet, and ngrok process it started. A case passes when issuer or verifier status is `success`, and a presentation also has `claims`. `did:web` stays out of this run.

The sections below are the requests that command sends. The run replays the active cases in the CTS v1.1 trust-framework suite (`tf-test-suite`). Each case is a fresh session.

The GITB handler `getcredentialrequestallparams` forwards every scriptlet
input except `endpoint` and `type` as query parameters. This sheet calls
the same paths with the same parameters. `did:web`, `jwk`, and `kid-jwk`
issuance are out of this run. CS-10 revocation and the relying-party
auth-handoff suites are separate runs.

VCI-005 is titled as mdoc signed with X509. Its catalog scriptlet
`ac-04.xml` sends `signatureType=did:web`. This sheet sends
`signatureType=x509`.

## Setup

The issuer reads `REDIS` and the wallet reads `WALLET_REDIS`, both as
`host:port`, and both default to `localhost:6379` with no password. Give
the issuer and the wallet each a public HTTPS origin, for
example two ngrok tunnels. `SERVER_URL` is the issuer origin the deep
link and `request_uri` must use, including any path prefix and without a
trailing slash.

```bash
export ISSUER=https://issuer.example
export WALLET=https://wallet.example
export PID='urn:eu.europa.ec.eudi:pid:1'
export MDOC='urn:eu.europa.ec.eudi:pid:1:mso_mdoc'

# issuer / verifier, port 3000
SERVER_URL="$ISSUER" node server.js

# wallet-client, port 4000
cd wallet-client
WALLET_PROFILE=webuild-cs01 \
WALLET_CLIENT_ID=wallet-client \
WALLET_ATTESTATION_SOURCE=local-key \
WALLET_PROVIDER_URL="$WALLET" \
WALLET_STATUS_ADMIN_TOKEN=dev-status-admin \
npm start
```

Leave `WALLET_AUTH_HANDOFF` unset so authorization-code issuance stays on
the headless path. Leave `VERIFIER_CS02_COMPATIBILITY` and
`CS02_COMPATIBILITY` unset so presentation defaults to `direct_post.jwt`
and `x509_hash`.

`webuild-cs01` refuses to start unless `WALLET_PROVIDER_URL` is HTTPS and
`WALLET_STATUS_ADMIN_TOKEN` is set. Trust-framework issuance fetches
`{WALLET}/status-lists/wia/1` and `{WALLET}/status-lists/ka/1` from the
issuer, so the wallet origin has to be reachable from the issuer.

Confirm the tunnel returns JSON. A free ngrok interstitial is an HTML page
and will fail the wallet's later fetch of the same host.

```bash
curl -sS -D- "$ISSUER/.well-known/openid-credential-issuer" | head
```

## Shared calls

Use a new UUID for every case. Keep it for the offer, the wallet session,
the status poll, and the logs.

Issuance offer. Set `PATH` to the row in the table below.

```bash
SESSION=$(uuidgen)
curl -sS -G "$ISSUER$PATH" \
  --data-urlencode "credentialType=$CRED" \
  --data-urlencode "sessionId=$SESSION" \
  --data-urlencode "signatureType=x509" \
  --data-urlencode "trustFramework=true" \
  | tee "/tmp/$SESSION.json"
```

The body has `qr` (a PNG data URL), `deepLink`, and `sessionId`. VCI-007
also has `txCode`. `sessionId` in the body equals `$SESSION`, and `qr` is
non-empty. The suite decodes `qr` and requires that text to equal
`deepLink`.

Wallet. Add `"pin": "<txCode>"` only for VCI-007.

```bash
curl -sS -X POST "$WALLET/session" \
  -H 'content-type: application/json' \
  -d "$(jq -n \
    --arg deepLink "$(jq -r .deepLink /tmp/$SESSION.json)" \
    --arg sessionId "$SESSION" \
    --arg issuer "$ISSUER" \
    --arg pin "$(jq -r '.txCode // empty' /tmp/$SESSION.json)" \
    '{deepLink:$deepLink, sessionId:$sessionId, trustFramework:true, issuer:$issuer, verifier:$issuer}
     + (if $pin == "" then {} else {pin:$pin} end)')"
```

The wallet response status is `ok`. Then:

```bash
curl -sS -G "$ISSUER/issueStatus" --data-urlencode "sessionId=$SESSION"
curl -sS "$ISSUER/logs/$SESSION"
curl -sS "$WALLET/logs/$SESSION"
```

`/issueStatus` returns HTTP 200 with `"status":"failed"` when the session
is missing. The pass value is `"status":"success"`.

Presentation request. Set `PATH` and any extra query fields from the table.

```bash
SESSION=$(uuidgen)
curl -sS -G "$ISSUER$PATH" \
  --data-urlencode "credentialType=$CRED" \
  --data-urlencode "sessionId=$SESSION" \
  --data-urlencode "trustFramework=true" \
  | tee "/tmp/$SESSION.json"
```

Add `--data-urlencode "response_mode=direct_post.jwt"` and
`--data-urlencode "invocation_scheme=$SCHEME"` only when the row lists them.
Drive the wallet with the same `POST /session` body, without `pin`. Then:

```bash
curl -sS -G "$ISSUER/verificationStatus" --data-urlencode "sessionId=$SESSION"
```

Pass is `"status":"success"` and a `claims` value. PID DCQL cases include
`family_name`. Fetch `/logs/$SESSION` on both services as above.

The x509 DCQL routes keep their built-in PID query (`urn:eu.europa.ec.eudi:pid:1`,
claim `family_name`). The mdoc route keeps its built-in mdoc query
(doctype `urn:eu.europa.ec.eudi:pid:1`). `credentialType` is still sent
because the suite sends it.

### Link check

`deepLink` is `{scheme}://?` with an empty authority. Decoded `request_uri`
is `$ISSUER` plus the path in the table and `/$SESSION`. `client_id` matches
`x509_hash:` plus 43 unpadded base64url characters. POST rows have exactly
`request_uri`, `client_id`, and `request_uri_method=post`. VP-007 has
`request_uri` and `client_id`, and `request_uri_method` is either absent or
`get`.

```bash
python3 - "$SESSION" openid4vp post /x509/x509VPrequest <<'PY'
import json, re, sys
from urllib.parse import parse_qs, urlparse
session, scheme, method, path = sys.argv[1:5]
body = json.load(open(f"/tmp/{session}.json"))
link = body["deepLink"]
assert body.get("qr"), "empty qr"
assert body["sessionId"] == session, body["sessionId"]
parsed = urlparse(link)
assert parsed.scheme == scheme and parsed.netloc == "" and parsed.path == "", link
query = parse_qs(parsed.query, keep_blank_values=True)
names = set(query)
assert names >= {"request_uri", "client_id"}, names
assert query["request_uri"] == [f"{__import__('os').environ['ISSUER']}{path}/{session}"]
assert re.fullmatch(r"x509_hash:[A-Za-z0-9_-]{43}", query["client_id"][0])
if method == "post":
    assert names == {"request_uri", "client_id", "request_uri_method"}, names
    assert query["request_uri_method"] == ["post"]
else:
    assert names <= {"request_uri", "client_id", "request_uri_method"}, names
    assert query.get("request_uri_method", ["get"]) == ["get"]
print("link ok", link)
PY
```

Change the four arguments to the scheme, method, and path for that row.
`ISSUER` must be exported in the shell that runs the check.

## Cases

Run the SD-JWT presentations while the VCI-001 credential is the stored PID.
VCI-006 and VCI-007 issue that same PID type again. Run them after those
presentations, or repeat VCI-001 before presenting. Run VP-007 while the
VCI-005 mdoc is the stored mdoc. VCI-008 issues that mdoc type again.

| Case | Offer or request | Wallet |
| --- | --- | --- |
| VCI-001 | `GET /offer-code-sd-jwt`, `$PID`, `signatureType=x509` | Authorization-code issuance. SD-JWT presentations use this credential. |
| VCI-005 | `GET /offer-code-sd-jwt`, `$MDOC`, `signatureType=x509` | Authorization-code mdoc. VP-007 uses this credential. |
| VCI-006 | `GET /offer-no-code`, `$PID`, `signatureType=x509` | Pre-authorized issuance. |
| VCI-007 | `GET /offer-tx-code`, `$PID`, `signatureType=x509` | Pre-authorized issuance. `pin` is the response `txCode`. |
| VCI-008 | `GET /offer-no-code`, `$MDOC`, `signatureType=x509` | Pre-authorized mdoc. |
| VP-001 | `GET /x509/generateVPRequestDCQL`, `$PID` | `openid4vp`, POST, default `direct_post.jwt`. |
| VP-002 | Same path, plus `response_mode=direct_post.jwt` | `openid4vp`, POST. |
| VP-003 | `GET /x509/generateVPRequestDCQLGET`, `$PID`, `response_mode=direct_post.jwt` | `openid4vp`, GET retrieval on that route. Run the link check with method `get` and path `/x509/x509VPrequest`. |
| VP-007 | `GET /mdl/generateVPRequest`, `$MDOC`, `response_mode=direct_post.jwt` | `openid4vp`, GET. Path `/mdl/VPrequest`. Extension case, outside CS-02 v1.2 scoring. |
| VP-011 | `GET /x509/generateVPRequestDCQL`, `$PID`, `invocation_scheme=openid4vp`, `response_mode=direct_post.jwt` | Required. |
| VP-012 | Same, `invocation_scheme=eu-eaap` | Required. Link scheme `eu-eaap`. |
| VP-013 | Same, `invocation_scheme=haip-vp` | Optional. Link scheme `haip-vp`. An unsupported scheme is a skipped capability. |

## Trust stop

Leave `trustFramework=true` on every request. A wallet rejection because
`verifier_info` has no `registrar_dataset`, or because WRPRC material is
missing, is a counterpart stop. Record the wallet error and both logs, and
stop the remaining presentation cases. That result is not a reason to turn
trust off or to set a compatibility flag.
