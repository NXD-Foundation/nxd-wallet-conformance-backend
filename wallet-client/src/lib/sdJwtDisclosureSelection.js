import { validateDcqlClaimPath } from "./cs02DcqlValidation.js";
import { Cs02ValidationError } from "./cs02RequestValidation.js";

function decodeSdJwtDisclosure(disclosure) {
  try {
    const decoded = JSON.parse(
      Buffer.from(disclosure, "base64url").toString("utf8"),
    );
    return Array.isArray(decoded) ? decoded : null;
  } catch {
    return null;
  }
}

function readJwtPayload(jwt) {
  try {
    const parts = String(jwt).split(".");
    if (parts.length < 2) return null;
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

export function sdJwtWithoutKbJwt(sdJwt) {
  let token = String(sdJwt || "");
  while (token.endsWith("~")) token = token.slice(0, -1);
  const parts = token.split("~");
  const issuerJwt = parts[0];
  const disclosures = parts.slice(1).filter((part) => !part.includes("."));
  return { issuerJwt, disclosures };
}

function requestedSdJwtClaimNames(dcqlCredentialQuery) {
  if (
    !dcqlCredentialQuery ||
    !["dc+sd-jwt", "vc+sd-jwt"].includes(dcqlCredentialQuery.format) ||
    !Array.isArray(dcqlCredentialQuery.claims)
  ) {
    return [];
  }

  return Array.from(
    new Set(
      dcqlCredentialQuery.claims.map((claim, index) => {
        validateDcqlClaimPath(
          claim?.path,
          `credentials[${dcqlCredentialQuery.id}].claims[${index}]`,
        );
        if (claim.path.length !== 1) {
          throw new Cs02ValidationError(
            `Unsupported SD-JWT DCQL claim path "${claim.path.join(".")}": only top-level claim paths are currently supported`,
            "invalid_request",
          );
        }
        return Array.isArray(claim?.path) ? claim.path[0] : null;
      }).filter((name) => typeof name === "string" && name.length > 0),
    ),
  );
}

function availableSdJwtClaimNames(issuerJwt, disclosures) {
  const available = new Set();
  const clearPayload = readJwtPayload(issuerJwt) || {};
  for (const key of Object.keys(clearPayload)) {
    if (!key.startsWith("_")) available.add(key);
  }
  for (const disclosure of disclosures) {
    const decoded = decodeSdJwtDisclosure(disclosure);
    if (typeof decoded?.[1] === "string" && decoded[1].length > 0) {
      available.add(decoded[1]);
    }
  }
  return available;
}

function selectedClaimSetNames(dcqlCredentialQuery, availableNames) {
  const claimSets = Array.isArray(dcqlCredentialQuery?.claim_sets)
    ? dcqlCredentialQuery.claim_sets
    : [];
  if (claimSets.length === 0) return null;

  const claimsById = new Map(
    (dcqlCredentialQuery?.claims || [])
      .filter((claim) => typeof claim?.id === "string" && claim.id.length > 0)
      .map((claim) => [claim.id, claim]),
  );

  for (const claimSet of claimSets) {
    const references = Array.isArray(claimSet) ? claimSet : claimSet?.ids;
    if (!Array.isArray(references) || references.length === 0) continue;
    const referencedClaims = references
      .map((claimId) => claimsById.get(claimId))
      .filter(Boolean);
    if (referencedClaims.length !== references.length) continue;

    const claimNames = referencedClaims
      .map((claim) => (Array.isArray(claim.path) ? claim.path[0] : null))
      .filter((name) => typeof name === "string" && name.length > 0);
    if (claimNames.length !== references.length) continue;
    if (claimNames.every((name) => availableNames.has(name))) {
      return new Set(claimNames);
    }
  }

  throw new Error("Stored SD-JWT does not satisfy any DCQL claim_sets option");
}

export function filterSdJwtByDcqlClaims(sdJwt, dcqlCredentialQuery) {
  let requestedNames = requestedSdJwtClaimNames(dcqlCredentialQuery);
  if (requestedNames.length === 0) return sdJwt;

  const { issuerJwt, disclosures } = sdJwtWithoutKbJwt(sdJwt);
  const availableNames = availableSdJwtClaimNames(issuerJwt, disclosures);
  const claimSetNames = selectedClaimSetNames(dcqlCredentialQuery, availableNames);
  if (claimSetNames) {
    requestedNames = requestedNames.filter((name) => claimSetNames.has(name));
  }

  const requested = new Set(requestedNames);
  const filteredDisclosures = disclosures.filter((disclosure) => {
    const decoded = decodeSdJwtDisclosure(disclosure);
    return typeof decoded?.[1] === "string" && requested.has(decoded[1]);
  });

  const clearPayload = readJwtPayload(issuerJwt) || {};
  const missing = requestedNames.filter(
    (name) =>
      !Object.prototype.hasOwnProperty.call(clearPayload, name) &&
      !filteredDisclosures.some((disclosure) => {
        const decoded = decodeSdJwtDisclosure(disclosure);
        return decoded?.[1] === name;
      }),
  );
  if (missing.length > 0) {
    throw new Error(
      `Stored SD-JWT is missing requested DCQL disclosure(s): ${missing.join(", ")}`,
    );
  }

  return `${issuerJwt}${filteredDisclosures.length > 0 ? `~${filteredDisclosures.join("~")}` : ""}~`;
}
