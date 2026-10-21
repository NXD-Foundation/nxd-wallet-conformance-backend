# CS-04: independent WIA and DPoP keys

This implementation follows the CS-01 v1.4 / CS-04 v1.2 changes proposed in
[WP4 architecture PR #355](https://github.com/webuild-consortium/wp4-architecture/pull/355),
reviewed at head `f3a19ac9438ed51223e95a880ecd56f9e8a5e6c2` (open at review).
The checked-in profile copies incorporate that proposal. TS-03 v1.5.2 removes
the earlier requirement to use the WIA confirmation key for DPoP.

## Key roles

| Role | Binding |
| --- | --- |
| WIA client authentication | Client Attestation PoP verifies under WIA `cnf.jwk`; the WIA signature, expiry, status and configured trust policy still apply |
| DPoP sender constraint | PAR `dpop_jkt`, token proof, access-token `cnf.jkt`, credential/deferred requests and refresh-token binding use the actual DPoP key |
| Credential holder | KA-attested key and credential proof follow the existing credential-key rules |

For CS-04 the issuer accepts either distinct or identical WIA and DPoP keys.
It still rejects a token proof that differs from the DPoP key bound at PAR,
or a protected-resource proof that differs from the access-token binding.
WIA authentication and DPoP are independently verified.

The wallet transport retains `cnfKeyPair` for WIA authentication and
`dpopKeyPair` for sender constraints. Both survive authorization-code browser
handoff and nonce/attestation retries, with fresh proof JWTs on each attempt.
Pre-authorized issuance creates independent keys without a PAR step. Refresh
retains the original DPoP key while independently authenticating with a current
WIA. The configured `keyPath` supplies WIA key material; DPoP keys are generated
separately and retained in the existing pending/refresh context. JWT access-token
confirmation checks compare with the actual DPoP key. Opaque tokens continue to
use the token response's DPoP indication; the wallet does not decode them.

CS-05 is unchanged: its issuer PAR and token checks still require the BWIA
confirmation key to be the DPoP key. This relaxation is limited to CS-04.
It does not change provider trust policy, status checking, KA proof binding,
DPoP nonce/replay controls, PKCE, or refresh rotation.

## Regression coverage

- `tests/sharedIssuanceFlows.test.js`: both CS-04 initial grants accept distinct
  keys and bind the token to the actual DPoP key; PAR/token DPoP mismatch and
  CS-05/BWIA mismatch rejection remain covered.
- `tests/oauthClientAttestation.test.js`: a PoP signed by a key other than the
  WIA confirmation key remains invalid.
- Wallet CS-01 tests cover separate keys at PAR, handoff, token retries and
  refresh, plus confirmation checks against the DPoP key.

Run the issuer suites with a dedicated Redis instance and the wallet suite with
`npm run test:cs01 --prefix wallet-client`. Route tests bind local HTTP servers.
