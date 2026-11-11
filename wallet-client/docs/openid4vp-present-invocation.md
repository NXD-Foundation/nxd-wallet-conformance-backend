# OpenID4VP Wallet Invocation

## Summary

Generated CS-02 links use the empty-authority form shown in CS-02 §8.1,
`openid4vp://?…` (and the same query on `eu-eaap://` and `haip-vp://`).
The wallet accepts any authority on those schemes. `openid4vp://present?…`,
`openid4vp://authorize?…`, and `openid4vp://another-name?…` use the same query
processing as `openid4vp://?…`.

## Normative basis

- **CS-02** §6.1.2 and §8.1 require the schemes and show empty-authority
  examples. They do not require the wallet to reject another host. The host
  is not in the §6.1.3 validation list.
- **OpenID4VP 1.0** §9 and §13.1.2 describe custom-scheme invocation without
  prescribing `present` or `authorize`.
- The hostname does not identify or authenticate the verifier. Request
  retrieval uses `request_uri` (`request_uri_method` defaults to `get`), and
  the signed request is validated afterwards.

## URI structure

| Form | Wallet-client |
| --- | --- |
| `openid4vp://?request_uri=…` | Accepted. This is the form this deployment generates. |
| `openid4vp://present?request_uri=…` | Accepted. The host is ignored. |
| `eu-eaap://<host>?request_uri=…` and `haip-vp://<host>?request_uri=…` | Accepted under the same query rules. |
| `https://…` | Rejected. This policy applies only to the custom invocation schemes. |

## Code

- `src/lib/openid4vpUri.js` — `parseInvocationDeepLink()` reads the query
  independently of host and path. `OPENID4VP_CS02_URI` is the generated form.
- `src/lib/cs02RequestValidation.js` — strict mode still requires an absolute
  HTTP(S) `request_uri` and a supported `request_uri_method`.
- `utils/tokenUtils.js` — `buildVPbyValue()` emits `openid4vp://?…`.

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
