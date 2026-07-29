/** Shared OpenID4VP DCQL structural rules (profile-neutral). */

function own(object, key) {
  return !!object && Object.prototype.hasOwnProperty.call(object, key);
}

export function isSupportedClaimPathSegment(segment) {
  if (segment === null) return true;
  if (typeof segment === "number" && Number.isInteger(segment) && segment >= 0) {
    return true;
  }
  return (
    typeof segment === "string" &&
    segment.length > 0 &&
    !/[\[\]$*]/.test(segment)
  );
}

export function dcqlValuesInclude(values, actualValue) {
  if (!Array.isArray(values) || values.length === 0) return true;
  if (actualValue === undefined) return false;
  return values.some((expected) => {
    if (actualValue === expected) return true;
    return JSON.stringify(expected) === JSON.stringify(actualValue);
  });
}

export function selectClaimPathValues(root, path) {
  if (!Array.isArray(path) || path.length === 0) return [];

  let current = [root];
  for (const segment of path) {
    const next = [];
    for (const value of current) {
      if (segment === null) {
        if (Array.isArray(value)) next.push(...value);
        continue;
      }
      if (typeof segment === "number" && Number.isInteger(segment) && segment >= 0) {
        if (Array.isArray(value) && segment < value.length) next.push(value[segment]);
        continue;
      }
      if (typeof segment === "string" && segment.length > 0 && !/[\[\]$*]/.test(segment)) {
        if (value && typeof value === "object" && !Array.isArray(value) && own(value, segment)) {
          next.push(value[segment]);
        }
      }
    }
    if (next.length === 0) return [];
    current = next;
  }
  return current;
}

export function validateSupportedClaimPath(path) {
  if (!Array.isArray(path) || path.length === 0) {
    throw new Error("DCQL claim path must be a non-empty array");
  }
  for (const segment of path) {
    if (!isSupportedClaimPathSegment(segment)) {
      throw new Error("DCQL claim path contains an unsupported segment");
    }
  }
  return path;
}

export function evaluateCredentialSets(dcqlQuery, vpTokenObject) {
  const credentials = Array.isArray(dcqlQuery?.credentials) ? dcqlQuery.credentials : [];
  const knownIds = new Set(credentials.map((cred) => cred.id).filter(Boolean));
  const sets = Array.isArray(dcqlQuery?.credential_sets) ? dcqlQuery.credential_sets : [];
  const requiredSets = sets.filter((set) => set?.required !== false);
  const unknownOptionIds = [];
  for (const set of sets) {
    for (const option of Array.isArray(set?.options) ? set.options : []) {
      for (const id of Array.isArray(option) ? option : []) {
        if (!knownIds.has(id)) unknownOptionIds.push(id);
      }
    }
  }
  const satisfiedOptions = requiredSets.map(
    (set) =>
      (Array.isArray(set?.options) ? set.options : []).find(
        (option) =>
          Array.isArray(option) &&
          option.length > 0 &&
          option.every((id) => Object.prototype.hasOwnProperty.call(vpTokenObject, id)),
      ) || null,
  );
  const allowedIds =
    requiredSets.length === 0
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

export function selectSatisfiedClaimSet(credQuery, isClaimSatisfied) {
  const claimSets = Array.isArray(credQuery?.claim_sets) ? credQuery.claim_sets : [];
  if (claimSets.length === 0) return null;
  const claimsById = new Map(
    (credQuery?.claims || [])
      .filter((claim) => typeof claim?.id === "string" && claim.id.length > 0)
      .map((claim) => [claim.id, claim]),
  );
  for (const claimSet of claimSets) {
    const references = Array.isArray(claimSet) ? claimSet : claimSet?.ids;
    if (!Array.isArray(references) || references.length === 0) continue;
    const claims = references.map((id) => claimsById.get(id));
    if (claims.every(Boolean) && claims.every((claim) => isClaimSatisfied(claim))) {
      return new Set(references);
    }
  }
  return null;
}

export function isPresentationCardinalityValid(value, multiple = false) {
  if (multiple === true) {
    return (
      Array.isArray(value) &&
      value.length > 0 &&
      value.every((item) => typeof item === "string" && item.length > 0)
    );
  }
  return (
    (typeof value === "string" && value.length > 0) ||
    (Array.isArray(value) &&
      value.length === 1 &&
      typeof value[0] === "string" &&
      value[0].length > 0)
  );
}
