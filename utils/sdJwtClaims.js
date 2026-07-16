import { digest } from "@sd-jwt/crypto-nodejs";
import { decodeSdJwtSync, splitSdJwt, unpackSync } from "@sd-jwt/decode";
import { selectSatisfiedCs02ClaimSet } from "./cs02DcqlCore.js";

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
  return selectSatisfiedCs02ClaimSet(credQuery, (claim) => claimSatisfiesSdJwtConstraints(claim, claims));
}
