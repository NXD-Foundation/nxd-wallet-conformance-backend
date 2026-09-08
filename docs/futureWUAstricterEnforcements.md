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
- WUA-required issuance fetches each Status List Token, verifies it with the Wallet Provider key that authenticated the WIA or KA, and requires the referenced bit to be VALID.

Future stricter enforcement:
- Enforce preferred remaining status maintenance periods where advertised.
- Re-check WIA and KA revocation at least every 24 hours for the validity period of a longer-lived PID (CS-04 §7.2). Issuance-time checking is sufficient when credential validity is under 24 hours.

## Wallet Provider Trust Material

Current behavior:
- Trust-list checks are out of scope unless the session opts in with `trustFramework=true`.
- All issuers/wallet providers are treated as trusted in this environment.
- When no configured trusted JWKS is present, WIA/KA signature verification may use key material carried in the JWT header, such as `x5c` or `jwk`, as a transitional interoperability mode.

Future stricter enforcement:
- Require configured trusted Wallet Provider keys, trusted certificate chains, or trust-list-derived material for WIA and KA verification.
- Reject self-contained `jwk` verification material in conformance/production mode.
- Keep any self-contained key fallback behind an explicit development-only setting.
