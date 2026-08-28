/** Resolve a DCQL path against a reconstructed credential claim object. */
export { getSdJwtPathValue as getDcqlPathValue } from "./sdJwtClaims.js";
export { getMdocPathValue } from "./mdocClaims.js";

import {
  getSdJwtPathValue as getDcqlPathValue,
  selectSdJwtPathValues,
} from "./sdJwtClaims.js";
import { selectSatisfiedClaimSet } from "./dcqlCore.js";

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

function claimPathKey(path) {
  return Array.isArray(path) ? path.join(".") : "";
}

function isClaimPresentInRoot(claimRoot, claim) {
  const values = selectSdJwtPathValues(claimRoot, claim?.path);
  return (
    values.length > 0 && values.some((value) => matchesRequestedValue(value, claim))
  );
}

function claimRootSatisfiesCredentialQuery(claimRoot, credQuery) {
  const claims = Array.isArray(credQuery?.claims) ? credQuery.claims : [];
  if (claims.length === 0) {
    return true;
  }

  if (Array.isArray(credQuery.claim_sets) && credQuery.claim_sets.length > 0) {
    return (
      selectSatisfiedClaimSet(credQuery, (claim) =>
        isClaimPresentInRoot(claimRoot, claim),
      ) !== null
    );
  }

  return claims.every((claim) => isClaimPresentInRoot(claimRoot, claim));
}

function claimsForCredentialValidation(credQuery, claimRoot) {
  const claims = Array.isArray(credQuery?.claims) ? credQuery.claims : [];
  if (!Array.isArray(credQuery?.claim_sets) || credQuery.claim_sets.length === 0) {
    return claims;
  }

  const satisfiedClaimSet = selectSatisfiedClaimSet(credQuery, (claim) =>
    isClaimPresentInRoot(claimRoot, claim),
  );
  if (!satisfiedClaimSet) {
    return claims;
  }

  return claims.filter(
    (claim) => typeof claim?.id === "string" && satisfiedClaimSet.has(claim.id),
  );
}

function getOptionalCredentialIds(dcqlQuery) {
  const optionalIds = new Set();
  for (const set of Array.isArray(dcqlQuery?.credential_sets)
    ? dcqlQuery.credential_sets
    : []) {
    if (set?.required === false) {
      for (const option of Array.isArray(set?.options) ? set.options : []) {
        for (const id of Array.isArray(option) ? option : []) {
          optionalIds.add(id);
        }
      }
    }
  }
  return optionalIds;
}

function sortCredentialsForMatching(credentials) {
  const claimPathOwners = new Map();
  for (const credential of credentials) {
    for (const claim of credential?.claims || []) {
      const key = claimPathKey(claim?.path);
      if (!key) continue;
      if (!claimPathOwners.has(key)) {
        claimPathOwners.set(key, new Set());
      }
      claimPathOwners.get(key).add(credential.id);
    }
  }

  return [...credentials].sort((left, right) => {
    const leftExclusive = (left?.claims || []).filter(
      (claim) => claimPathOwners.get(claimPathKey(claim?.path))?.size === 1,
    ).length;
    const rightExclusive = (right?.claims || []).filter(
      (claim) => claimPathOwners.get(claimPathKey(claim?.path))?.size === 1,
    ).length;
    return rightExclusive - leftExclusive;
  });
}

function findMatchingClaimRootIndex(credQuery, claimRoots, usedIndices) {
  for (let index = 0; index < claimRoots.length; index += 1) {
    if (usedIndices.has(index)) continue;
    if (claimRootSatisfiesCredentialQuery(claimRoots[index], credQuery)) {
      return index;
    }
  }
  return -1;
}

/**
 * Validate extracted VP claims against a full DCQL query, honouring claim_sets
 * and optional credential_sets entries.
 */
export function validateDcqlQueryClaims(claims, dcqlQuery) {
  const credentials = Array.isArray(dcqlQuery?.credentials)
    ? dcqlQuery.credentials.filter((credential) => credential?.format !== "mso_mdoc")
    : [];
  if (credentials.length === 0) {
    return { ok: true, errors: [] };
  }

  const claimRoots = Array.isArray(claims) ? claims : [claims];
  const optionalCredentialIds = getOptionalCredentialIds(dcqlQuery);
  const usedRootIndices = new Set();
  const errors = [];

  for (const credQuery of sortCredentialsForMatching(credentials)) {
    const rootIndex = findMatchingClaimRootIndex(
      credQuery,
      claimRoots,
      usedRootIndices,
    );

    if (rootIndex === -1) {
      if (optionalCredentialIds.has(credQuery.id)) {
        continue;
      }
      errors.push(`missing presentation for credential '${credQuery.id}'`);
      continue;
    }

    usedRootIndices.add(rootIndex);
    const validation = validateDcqlClaims(
      [claimRoots[rootIndex]],
      claimsForCredentialValidation(credQuery, claimRoots[rootIndex]),
    );
    if (!validation.ok) {
      errors.push(
        ...validation.errors.map(
          (error) => `credential '${credQuery.id}': ${error}`,
        ),
      );
    }
  }

  return { ok: errors.length === 0, errors };
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
