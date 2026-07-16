/** Shared WE BUILD CS-02 DCQL structural rules. */

export function isSupportedCs02ClaimPathSegment(segment) {
  return (
    typeof segment === "string" &&
    segment.length > 0 &&
    !/[\[\]$*]/.test(segment)
  );
}

export function validateSupportedCs02ClaimPath(path) {
  if (!Array.isArray(path) || path.length === 0) {
    throw new Error("DCQL claim path must be a non-empty array");
  }
  for (const segment of path) {
    if (!isSupportedCs02ClaimPathSegment(segment)) {
      throw new Error("DCQL claim path contains an unsupported segment");
    }
  }
  return path;
}

export function evaluateCs02CredentialSets(dcqlQuery, vpTokenObject) {
  const credentials = Array.isArray(dcqlQuery?.credentials) ? dcqlQuery.credentials : [];
  const knownIds = new Set(credentials.map((cred) => cred.id).filter(Boolean));
  const sets = Array.isArray(dcqlQuery?.credential_sets) ? dcqlQuery.credential_sets : [];
  const requiredSets = sets.filter((set) => set?.required !== false);
  const unknownOptionIds = [];
  for (const set of sets) for (const option of Array.isArray(set?.options) ? set.options : []) {
    for (const id of Array.isArray(option) ? option : []) if (!knownIds.has(id)) unknownOptionIds.push(id);
  }
  const satisfiedOptions = requiredSets.map((set) => (Array.isArray(set?.options) ? set.options : []).find(
    (option) => Array.isArray(option) && option.length > 0 && option.every((id) => Object.prototype.hasOwnProperty.call(vpTokenObject, id)),
  ) || null);
  const allowedIds = requiredSets.length === 0
    ? knownIds
    : new Set(satisfiedOptions.flatMap((option) => option || []));
  return {
    knownIds,
    requiredSets,
    satisfied: satisfiedOptions.every(Boolean),
    allowedIds,
    unknownOptionIds: Array.from(new Set(unknownOptionIds)),
  };
}

export function selectSatisfiedCs02ClaimSet(credQuery, isClaimSatisfied) {
  const claimSets = Array.isArray(credQuery?.claim_sets) ? credQuery.claim_sets : [];
  if (claimSets.length === 0) return null;
  const claimsById = new Map((credQuery?.claims || [])
    .filter((claim) => typeof claim?.id === "string" && claim.id.length > 0)
    .map((claim) => [claim.id, claim]));
  for (const claimSet of claimSets) {
    const references = Array.isArray(claimSet) ? claimSet : claimSet?.ids;
    if (!Array.isArray(references) || references.length === 0) continue;
    const claims = references.map((id) => claimsById.get(id));
    if (claims.every(Boolean) && claims.every((claim) => isClaimSatisfied(claim))) return new Set(references);
  }
  return null;
}

export function isCs02PresentationCardinalityValid(value, multiple = false) {
  if (multiple === true) return Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === "string" && item.length > 0);
  return (typeof value === "string" && value.length > 0) ||
    (Array.isArray(value) && value.length === 1 && typeof value[0] === "string" && value[0].length > 0);
}
