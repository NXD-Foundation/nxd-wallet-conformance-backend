/** Resolve a DCQL path against a reconstructed credential claim object. */
export function getDcqlPathValue(claims, path) {
  if (!Array.isArray(path) || path.length === 0) return undefined;
  return path.reduce((value, segment) => {
    if (value == null || typeof value !== "object") return undefined;
    return value[segment];
  }, claims);
}

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

  const errors = [];
  for (const claim of dcqlClaims) {
    const path = claim?.path;
    const value = getDcqlPathValue(claims, path);
    const label = Array.isArray(path) ? path.join(".") : "<invalid path>";
    if (value === undefined) {
      errors.push(`missing requested DCQL claim '${label}'`);
      continue;
    }
    if (!matchesRequestedValue(value, claim)) {
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
