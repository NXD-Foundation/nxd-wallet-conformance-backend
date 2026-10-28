# Native Android wallet harness

The external verifier is the SUT. The APK observes its existing presentation flow
and reports events and its outcome; ITB displays these without a verifier verdict.

Configure the backend with independent random `ITB_WALLET_SERVICE_KEY` and
`ITB_WALLET_TOKEN_SECRET` (at least 32 characters). Configure the Java test service
with the same service key plus `ITB_WALLET_BACKEND=https://backend.example`.
Keep secrets in deployment environment configuration. No keys belong in APKs or TDL.

Routes under `/itb-wallet/v1`:

* POST `/sessions` with `{sessionId: UUID}` (optional UUID is generated if absent).
* POST `/sessions/{UUID}/pair` with `{installationId: UUID, pairingRequestId: UUID}`.
  This returns uploadToken, expiresAt and uploadExpiresAt (epoch milliseconds).
* POST `/sessions/{UUID}/attempts/{attemptId}/events` with
  `{schemaVersion:1, events:[{eventId, sequence, timestamp, metadata:{event, transport}}]}`.
  Response: `{acceptedEventIds:[]}`. Repeated identical events are acknowledged;
  conflicting IDs/sequences fail with 409. Maximum 100 events/batch, 2000/session.
* POST `/sessions/{UUID}/complete` with `{schemaVersion:1, completionId:UUID,
  reportedOutcome, attempts:[{attemptId, finalSequence}]}`. Requires contiguous
  uploaded evidence. Outcome: response_produced, cancelled, error, interrupted.
* GET `/sessions/{UUID}` returns `{sessionId,status,reportedOutcome,evidenceComplete,...}`.
* GET `/sessions/{UUID}/logs` returns `{sessionId,logs,count}` for the existing ITB renderer.

Creation and reads require `X-ITB-Service-Key`. Upload and completion require
`Authorization: Bearer <uploadToken>`. Pairing uses the unpredictable execution UUID
and is rate limited in Redis. One installation can claim it, with retry recovery
using the same pairingRequestId. Tokens are derived with HMAC and never stored in
logs. Use HTTPS and a correctly configured reverse proxy client IP policy.

Execution/pairing window is four minutes, with 24-hour upload grace. Redis retains
sessions for 48 hours plus the initial window; IDs remain consumed within retention.
Always generate fresh UUIDs. These records are independent of issuer/verifier logs
and their 100-entry rolling limit. Redis persistence must be enabled in deployment
if evidence must survive Redis restarts. HTTP acknowledgement confirms Redis writes,
not an external archive. Pairing and upload fail closed when Redis is unavailable.

Only allowlisted event metadata is stored. Arbitrary free-text messages and raw
credentials/tokens are dropped. No response payload is sent by the APK. A response
intent being ready means response_produced, not external verifier acceptance.

## Reverse-proxy deployment paths

The wallet and Java client preserve the service base path. For the Aegean
deployment use `https://dev-i4mlab.aegean.gr/rfc-issuer` for the wallet backend
field, Java `ITB_WALLET_BACKEND`, and ITB domain `webuild` (without a trailing
slash). The pairing route is then
`/rfc-issuer/itb-wallet/v1/sessions/{UUID}/pair`. The proxy forwards requests to
the Node `/itb-wallet/v1` router. `/itb/` is the separate test-bed UI.
Use APK 0.1.1-itb or later and the updated Java client for path-prefix support.

## Android diagnostic batches

The native wallet sends `diagnostic` events alongside presentation milestones.
The reporting endpoint accepts these events at debug level and retains only
allowlisted stages, nonnegative integer counts/timing, boolean trust/authentication
results, bounded exception class chains and stack frames. Raw event messages,
unknown metadata and exception messages remain excluded. Diagnostic events count
toward the completion sequence manifest, so rejecting them prevents completion.
Deploy this backend update before the diagnostics APK. The recovery APK retries
previous HTTP 400 rejections once at startup, within the original upload grace;
it keeps event IDs, sequence numbers and acknowledgement progress unchanged.
