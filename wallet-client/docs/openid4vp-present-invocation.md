# OpenID4VP `openid4vp://present` Wallet Invocation

## Summary

The wallet-client emits and registers OAuth redirect URIs using the CS-02 wallet
invocation form `openid4vp://present?…` instead of bare `openid4vp://?…`.

## Normative basis

- **CS-02 Credential Presentation** (§6.1.2, §7.1.3, §8.1) requires wallet
  invocation via `openid4vp://present?request_uri=<URL>`.
- **OpenID4VP 1.0** lists **RFC 3986** as a normative reference for URI syntax.
- **RFC 3986** allows an empty registered-name authority (`openid4vp://`), but
  many URI parsers add extra validation beyond the generic grammar and reject
  bare custom-scheme URLs. Using an explicit authority (`present`) avoids those
  failures while matching CS-02.

OpenID4VP §13.1.2 shows a non-normative metadata example with
`"authorization_endpoint": "openid4vp:"`; that example does not override CS-02
for this profile.

## URI structure

| Form | RFC 3986 | CS-02 | Wallet-client usage |
| --- | --- | --- | --- |
| `openid4vp://?request_uri=…` | Valid (empty authority) | Not the CS-02 invocation endpoint | Legacy input only (still parsed) |
| `openid4vp://present?request_uri=…` | Valid | Required invocation | Emitted for VP deep links |
| `openid4vp://callback?…` | Valid | Wrong endpoint (`callback` is authority) | Not used |

In RFC 3986 terms, `present` is the **authority** (host) component; query
parameters (`request_uri`, `client_id`, etc.) follow the `?` as usual.

## Code changes

Constants live in `src/lib/openid4vpUri.js`:

- `OPENID4VP_PRESENT_URI` — `openid4vp://present` (OAuth `redirect_uri`)
- `OPENID4VP_PRESENT_QUERY_PREFIX` — `openid4vp://present?` (by-value VP links)

Updated call sites:

- `utils/tokenUtils.js` — `buildVPbyValue()` builds `openid4vp://present?…`
- `src/server.js` — authorization-code flow uses `redirect_uri=openid4vp://present`
- `src/lib/presentation.js` — documents CS-02 authority when parsing deep links

## Interoperability

The wallet **accepts** legacy bare `openid4vp://?…` deep links when parsing
incoming verifier requests (for example from older demo verifiers in this repo).
It **emits** CS-02-compliant `openid4vp://present?…` URLs and registers
`openid4vp://present` as its OAuth redirect URI.

## Examples

Wallet invocation (by reference):

```
openid4vp://present?request_uri=https%3A%2F%2Fverifier.example.org%2Frequest%2F123&client_id=…
```

Authorization code redirect (issuance code flow):

```
openid4vp://present?code=abc123&state=xyz
```
