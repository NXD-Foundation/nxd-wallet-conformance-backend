import { digest } from "@sd-jwt/crypto-nodejs";
import { decodeSdJwtSync, splitSdJwt, unpackSync } from "@sd-jwt/decode";

function own(object, key) {
  return !!object && Object.prototype.hasOwnProperty.call(object, key);
}

export function sdJwtPathToString(path) {
  return Array.isArray(path) ? path.join(".") : "";
}

export function getSdJwtPathValue(claims, path) {
  if (!Array.isArray(path) || path.length === 0) return undefined;

  let current = claims;
  for (const segment of path) {
    if (typeof segment !== "string" || segment.length === 0) return undefined;
    if (!current || typeof current !== "object" || !own(current, segment)) {
      current = undefined;
      break;
    }
    current = current[segment];
  }
  if (current !== undefined) return current;

  const dottedPath = sdJwtPathToString(path);
  if (dottedPath && own(claims, dottedPath)) {
    return claims[dottedPath];
  }

  return undefined;
}

export function parseSdJwtClaims(sdJwt) {
  const decoded = decodeSdJwtSync(sdJwt, digest);
  const { unpackedObj, disclosureKeymap } = unpackSync(
    decoded.jwt.payload,
    decoded.disclosures,
    digest,
  );
  const split = splitSdJwt(sdJwt);
  const encodedDisclosures = split.disclosures || [];
  const hashConfig = {
    hasher: digest,
    alg: typeof decoded.jwt.payload?._sd_alg === "string" ? decoded.jwt.payload._sd_alg : "sha-256",
  };

  const encodedDisclosureByHash = {};
  for (let index = 0; index < decoded.disclosures.length; index += 1) {
    const disclosure = decoded.disclosures[index];
    const encodedDisclosure = encodedDisclosures[index];
    if (!encodedDisclosure) continue;
    const hash = disclosure.digestSync(hashConfig);
    encodedDisclosureByHash[hash] = encodedDisclosure;
  }

  return {
    claims: unpackedObj,
    disclosureKeymap,
    encodedDisclosureByHash,
    decoded,
  };
}

export function sdJwtDisclosureHashesForPath(path, disclosureKeymap = {}) {
  const pathString = sdJwtPathToString(path);
  if (!pathString) return new Set();
  const hashes = new Set();

  for (const [disclosedPath, hash] of Object.entries(disclosureKeymap || {})) {
    if (
      disclosedPath === pathString ||
      pathString.startsWith(`${disclosedPath}.`) ||
      disclosedPath.startsWith(`${pathString}.`)
    ) {
      hashes.add(hash);
    }
  }

  return hashes;
}

function claimSatisfiesValueConstraint(claim, claims) {
  if (!Array.isArray(claim?.values) || claim.values.length === 0) return true;
  const actualValue = getSdJwtPathValue(claims, claim.path);
  return typeof actualValue === "string" && claim.values.includes(actualValue);
}

export function claimSatisfiesSdJwtConstraints(claim, claims) {
  return (
    getSdJwtPathValue(claims, claim?.path) !== undefined &&
    claimSatisfiesValueConstraint(claim, claims)
  );
}

export function selectSatisfiedSdJwtClaimSet(credQuery, claims) {
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
    const referencedClaims = references.map((id) => claimsById.get(id)).filter(Boolean);
    if (referencedClaims.length !== references.length) continue;
    if (referencedClaims.every((claim) => claimSatisfiesSdJwtConstraints(claim, claims))) {
      return new Set(references);
    }
  }

  return null;
}
