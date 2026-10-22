import { digest } from "@sd-jwt/crypto-nodejs";
import { decodeSdJwtSync, splitSdJwt, unpackSync } from "@sd-jwt/decode";
import {
  dcqlValuesInclude,
  selectClaimPathValues,
  selectSatisfiedClaimSet,
} from "./dcqlCore.js";

function own(object, key) {
  return !!object && Object.prototype.hasOwnProperty.call(object, key);
}

export function sdJwtPathToString(path) {
  if (!Array.isArray(path)) return "";
  return path.map((segment) => (segment === null ? "null" : String(segment))).join(".");
}

function disclosedSegmentsMatchDcqlPath(disclosed, dcql, di, ci) {
  if (ci >= dcql.length) return di >= disclosed.length;
  if (di >= disclosed.length) return false;

  const segment = dcql[ci];
  if (segment === null) {
    return disclosedSegmentsMatchDcqlPath(disclosed, dcql, di + 1, ci + 1);
  }
  if (typeof segment === "number") {
    if (disclosed[di] !== String(segment)) return false;
    return disclosedSegmentsMatchDcqlPath(disclosed, dcql, di + 1, ci + 1);
  }
  if (typeof segment === "string") {
    if (disclosed[di] !== segment) return false;
    return disclosedSegmentsMatchDcqlPath(disclosed, dcql, di + 1, ci + 1);
  }
  return false;
}

export function disclosedPathMatchesDcqlPath(disclosedPath, dcqlPath) {
  if (!Array.isArray(dcqlPath) || dcqlPath.length === 0) return false;
  const disclosedSegments = String(disclosedPath || "")
    .split(".")
    .filter((segment) => segment.length > 0);
  return disclosedSegmentsMatchDcqlPath(disclosedSegments, dcqlPath, 0, 0);
}

function disclosurePathRelevantToDcqlPath(disclosedPath, dcqlPath) {
  if (!disclosedPath || !Array.isArray(dcqlPath) || dcqlPath.length === 0) return false;
  if (disclosedPathMatchesDcqlPath(disclosedPath, dcqlPath)) return true;

  const disclosedSegments = String(disclosedPath)
    .split(".")
    .filter((segment) => segment.length > 0);
  if (disclosedSegments.length === 0 || disclosedSegments.length > dcqlPath.length) {
    return false;
  }

  let di = 0;
  for (let ci = 0; ci < dcqlPath.length && di < disclosedSegments.length; ci += 1) {
    const segment = dcqlPath[ci];
    if (segment === null) {
      di += 1;
      continue;
    }
    if (typeof segment === "number") {
      if (disclosedSegments[di] !== String(segment)) return false;
    } else if (disclosedSegments[di] !== segment) {
      return false;
    }
    di += 1;
  }
  return di === disclosedSegments.length;
}

export function getSdJwtPathValue(claims, path) {
  const selected = selectSdJwtPathValues(claims, path);
  return selected.length > 0 ? selected[0] : undefined;
}

export function selectSdJwtPathValues(claims, path) {
  const selected = selectClaimPathValues(claims, path);
  if (selected.length > 0) return selected;

  const dottedPath = sdJwtPathToString(path);
  if (dottedPath && own(claims, dottedPath)) {
    return [claims[dottedPath]];
  }

  return [];
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
  if (!Array.isArray(path) || path.length === 0) return new Set();
  const pathString = sdJwtPathToString(path);
  const allStringPath = path.every((segment) => typeof segment === "string");
  const hashes = new Set();

  for (const [disclosedPath, hash] of Object.entries(disclosureKeymap || {})) {
    const matches =
      disclosurePathRelevantToDcqlPath(disclosedPath, path) ||
      (allStringPath &&
        (disclosedPath === pathString ||
          pathString.startsWith(`${disclosedPath}.`) ||
          disclosedPath.startsWith(`${pathString}.`)));
    if (matches) hashes.add(hash);
  }

  return hashes;
}

function claimSatisfiesValueConstraint(claim, claims) {
  const selected = selectSdJwtPathValues(claims, claim?.path);
  if (selected.length === 0) return false;
  if (!Array.isArray(claim?.values) || claim.values.length === 0) return true;
  return selected.some((actualValue) => dcqlValuesInclude(claim.values, actualValue));
}

export function claimSatisfiesSdJwtConstraints(claim, claims) {
  return claimSatisfiesValueConstraint(claim, claims);
}

export function selectSatisfiedSdJwtClaimSet(credQuery, claims) {
  return selectSatisfiedClaimSet(credQuery, (claim) =>
    claimSatisfiesSdJwtConstraints(claim, claims),
  );
}
