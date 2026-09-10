# Future WUA Stricter Enforcements

This note records current WUA enforcement design decisions that are intentionally less strict than the final CS04 lifecycle target.

## Status Field Completeness And Issuance-Time Bit Evaluation

Current behavior:
- Missing WIA `client_status` fails WUA-required issuance.
- Expired WIA `client_status.exp` fails WUA-required issuance.
- Incomplete WIA `client_status.status.status_list` (`uri` / non-negative integer `idx`) fails WUA-required issuance.
- Missing KA `key_storage_status` fails KA/WUA validation.
- Expired KA `key_storage_status.exp` fails KA/WUA validation.
- Incomplete KA `key_storage_status.status.status_list` fails CS-04 KA validation.
- WUA-required issuance fetches each Status List Token, verifies it with the Wallet Provider key that authenticated the WIA or KA when that key matches, otherwise with the Status List Token protected-header `x5c` or `jwk`, and requires the referenced value to be VALID (`0x00`). `bits` may be 1, 2, 4, or 8 (draft-20 §4.2); INVALID is revoked and other types including SUSPENDED fail closed.
- Status List Token `exp` is checked only when present (draft-20 §5.1 RECOMMENDED / §8.3). Missing `exp` is accepted; a present, past `exp` still fails. This is distinct from the required WIA `client_status.exp` / KA `key_storage_status.exp` claims.
- Status-list fetch follows a bounded number of HTTPS redirects and re-validates each hop (draft-20 §8.2 SHOULD follow; §11.4). Trust-list `fetchDocument` still defaults to rejecting redirects. Response `Content-Type` must be `application/statuslist+jwt` (draft-20 §8.2 MUST).
- DPoP `jkt` vs WIA `cnf` thumbprint mismatch is warning-only on WUA-required token requests. Current TS-03 v1.5.2 rolled back the 1.5.1 requirement that DPoP use the WIA `cnf` key; the issuer still requires OAuth Client Attestation PoP under `cnf`. Missing DPoP on a WUA-required session still fails.

Future stricter enforcement:
- Enforce preferred remaining status maintenance periods where advertised.
- Re-check WIA and KA revocation at least every 24 hours for the validity period of a longer-lived PID (CS-04 §7.2). Issuance-time checking is sufficient when credential validity is under 24 hours.
- Fail the token request when DPoP `jkt` does not match WIA `cnf.jwk`. That is CS-04 §7.3 / CS-01 §7.4 (copied from TS-03 1.5.1), not current TS-03 1.5.2.

## Wallet Provider Trust Material

Current behavior:
- Trust-list checks are out of scope unless the session opts in with `trustFramework=true`.
- All issuers/wallet providers are treated as trusted in this environment.
- When no configured trusted JWKS is present, WIA/KA signature verification may use key material carried in the JWT header, such as `x5c` or `jwk`, as a transitional interoperability mode.

Future stricter enforcement:
- Require configured trusted Wallet Provider keys, trusted certificate chains, or trust-list-derived material for WIA and KA verification.
- Reject self-contained `jwk` verification material in conformance/production mode.
- Keep any self-contained key fallback behind an explicit development-only setting.
