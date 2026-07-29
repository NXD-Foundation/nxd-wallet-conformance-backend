/** Resolve a DCQL path against a reconstructed credential claim object. */
export { getSdJwtPathValue as getDcqlPathValue } from "./sdJwtClaims.js";
export { getMdocPathValue } from "./mdocClaims.js";

import {
  getSdJwtPathValue as getDcqlPathValue,
  selectSdJwtPathValues,
} from "./sdJwtClaims.js";

function matchesRequestedValue(value, constraint) {
  if (!constraint || typeof constraint !== "object") return true;
  if (Array.isArray(constraint.values)) {
    return constraint.values.some((candidate) => JSON.stringify(candidate) === JSON.stringify(value));
  }
  if (Object.prototype.hasOwnProperty.call(constraint, "value")) {
    return JSON.stringify(constraint.value) === JSON.stringify(value);
  }
  return true;
}

/** Validate that a reconstructed credential satisfies the requested DCQL claims. */
export function validateDcqlClaims(claims, dcqlClaims) {
  if (!Array.isArray(dcqlClaims) || dcqlClaims.length === 0) {
    return { ok: true, errors: [] };
  }

  // VP extraction returns one reconstructed claim object per presented
  // credential. Treat that outer array as a list of candidate claim roots,
  // rather than attempting to resolve object-member paths on the array itself.
  const claimRoots = Array.isArray(claims) ? claims : [claims];
  const errors = [];
  for (const claim of dcqlClaims) {
    const path = claim?.path;
    const values = claimRoots.flatMap((root) =>
      selectSdJwtPathValues(root, path),
    );
    const label = Array.isArray(path) ? path.join(".") : "<invalid path>";
    if (values.length === 0) {
      errors.push(`missing requested DCQL claim '${label}'`);
      continue;
    }
    if (!values.some((value) => matchesRequestedValue(value, claim))) {
      errors.push(`DCQL value constraint failed for '${label}'`);
    }
  }
  return { ok: errors.length === 0, errors };
}

/**
 * Validate mdoc DCQL claims. mdoc issuer-signed elements are extracted into a
 * flat object, while DCQL paths include the namespace as their first segment.
 */
export function validateMdocDcqlClaims(claims, dcqlQuery) {
  const credentials = Array.isArray(dcqlQuery?.credentials)
    ? dcqlQuery.credentials.filter((credential) => credential?.format === "mso_mdoc")
    : [];
  const requestedClaims = credentials.flatMap((credential) =>
    Array.isArray(credential.claims)
      ? credential.claims.map((claim) => ({ ...claim, path: claim?.path?.slice(-1) }))
      : [],
  );
  return validateDcqlClaims(claims, requestedClaims);
}
