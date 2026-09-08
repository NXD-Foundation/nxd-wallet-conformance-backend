# OpenID4VP Wallet Invocation (`openid4vp://`)

## Summary

CS-02 wallet invocation is the empty-authority form `openid4vp://?…`. The
host `present` is a compatibility form, not part of approved CS-02 v1.1.

## Normative basis

- **CS-02 Credential Presentation** (§6.1.2, §7.1.3, §8.1) uses
  `openid4vp://?request_uri=<URL>`.
- **OpenID4VP 1.0** lists RFC 3986 as a URI-syntax reference and shows a
  custom-scheme authorization endpoint without a `present` host.
- **RFC 3986** allows an empty registered-name authority (`openid4vp://`).

## URI structure

| Form | RFC 3986 | CS-02 | Wallet-client usage |
| --- | --- | --- | --- |
| `openid4vp://?request_uri=…` | Valid (empty authority) | Required invocation | Emitted and required in strict CS-02 |
| `openid4vp://present?request_uri=…` | Valid | Not CS-02 | Compatibility input/output only |
| `openid4vp://callback?…` | Valid | Wrong endpoint | Rejected |

In RFC 3986 terms, `present` is an **authority** (host). CS-02 leaves that
component empty.

## Code

Constants live in `src/lib/openid4vpUri.js`:

- `OPENID4VP_CS02_URI` — `openid4vp://` (OAuth `redirect_uri` and CS-02 invocation)
- `OPENID4VP_CS02_QUERY_PREFIX` — `openid4vp://?` (by-value VP links)
- `OPENID4VP_PRESENT_URI` / `OPENID4VP_PRESENT_QUERY_PREFIX` — compatibility `present` form

Call sites:

- `utils/tokenUtils.js` — `buildVPbyValue()` builds `openid4vp://?…`
- `src/server.js` — authorization-code flow uses `redirect_uri=openid4vp://`
- `src/lib/cs02RequestValidation.js` — strict CS-02 rejects `present` unless
  `CS02_ALLOW_PRESENT_INVOCATION` (or the alias `CS02_ALLOW_LEGACY_INVOCATION`) is set
- `utils/cs02VerifierRequest.js` — strict verifier emit is `openid4vp://?`;
  compatibility emit may still use `present`

## Interoperability

Strict CS-02 **requires** empty-authority `openid4vp://?…` and **rejects**
`openid4vp://present?…`. Compatibility mode still parses `present` deep links
from other implementations. This issuer's default OAuth redirect URI is also
`openid4vp://`.

## Consent scope

`wallet-client` is a headless test wallet used for issuer/verifier integration
and protocol testing. It does not implement an end-user consent UI or a runtime
approval callback before presentation generation.

Production wallet integrations that wrap this library must add their own
consent gate before calling the presentation flow. At minimum, that wrapper
must show the verifier identity, requested credential query ids, requested
claim paths, response mode, and any transaction data summary, and it must
return a protocol error such as `access_denied` if the holder declines.

Consent/audit logs in those production wrappers must avoid raw credential
contents and private key material.

## Examples

Wallet invocation (by reference):

```
openid4vp://?request_uri=https%3A%2F%2Fverifier.example.org%2Frequest%2F123&client_id=…
```

Authorization code redirect (issuance code flow):

```
openid4vp://?code=abc123&state=xyz
```
