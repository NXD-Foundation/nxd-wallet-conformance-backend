# Future WUA Stricter Enforcements

This note records current WUA enforcement design decisions that are intentionally less strict than the final CS04 lifecycle target.

## Status Field Completeness

Current behavior:
- Missing WIA `client_status` fails WUA-required issuance.
- Expired WIA `client_status.exp` fails WUA-required issuance.
- Missing KA `key_storage_status` fails KA/WUA validation.
- Expired KA `key_storage_status.exp` fails KA/WUA validation.
- Incomplete status structures, such as present-but-empty or malformed `status_list` details, are logged as warnings for now.

Future stricter enforcement:
- Reject incomplete WIA `client_status.status.status_list` values.
- Reject missing or non-numeric WIA `client_status.status.status_list.idx`.
- Reject incomplete KA `key_storage_status.status.status_list` values.
- Reject missing or non-numeric KA `key_storage_status.status.status_list.idx`.
- Enforce preferred remaining status maintenance periods where advertised.

## Wallet Provider Trust Material

Current behavior:
- Trust-list checks are out of scope.
- All issuers/wallet providers are treated as trusted in this environment.
- When no configured trusted JWKS is present, WIA/KA signature verification may use key material carried in the JWT header, such as `x5c` or `jwk`, as a transitional interoperability mode.

Future stricter enforcement:
- Require configured trusted Wallet Provider keys, trusted certificate chains, or trust-list-derived material for WIA and KA verification.
- Reject self-contained `jwk` verification material in conformance/production mode.
- Keep any self-contained key fallback behind an explicit development-only setting.
