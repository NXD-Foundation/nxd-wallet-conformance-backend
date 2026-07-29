import {
  dcqlValuesInclude,
  validateSupportedClaimPath,
} from "../../utils/dcqlCore.js";
import {
  parseSdJwtClaims,
  sdJwtDisclosureHashesForPath,
  sdJwtPathToString,
  selectSdJwtPathValues,
  selectSatisfiedSdJwtClaimSet,
} from "../../utils/sdJwtClaims.js";

export class DcqlDisclosureSelectionError extends Error {
  constructor(message, errorCode = "access_denied") {
    super(message);
    this.name = "DcqlDisclosureSelectionError";
    this.errorCode = errorCode;
  }
}

function validateDcqlClaimPath(path, label) {
  try {
    validateSupportedClaimPath(path);
  } catch (error) {
    throw new DcqlDisclosureSelectionError(
      `${label}: ${error.message}`,
      "invalid_request",
    );
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
      dcqlCredentialQuery.claims
        .map((claim, index) => {
          validateDcqlClaimPath(
            claim?.path,
            `credentials[${dcqlCredentialQuery.id}].claims[${index}]`,
          );
          return Array.isArray(claim?.path) ? sdJwtPathToString(claim.path) : null;
        })
        .filter((name) => typeof name === "string" && name.length > 0),
    ),
  );
}

export function filterSdJwtByDcqlClaims(sdJwt, dcqlCredentialQuery) {
  const requestedNames = requestedSdJwtClaimNames(dcqlCredentialQuery);
  if (requestedNames.length === 0) return sdJwt;

  const { issuerJwt } = sdJwtWithoutKbJwt(sdJwt);
  const parsed = parseSdJwtClaims(sdJwt);
  const satisfiedClaimSet = selectSatisfiedSdJwtClaimSet(
    dcqlCredentialQuery,
    parsed.claims,
  );
  if (
    Array.isArray(dcqlCredentialQuery?.claim_sets) &&
    dcqlCredentialQuery.claim_sets.length > 0 &&
    !satisfiedClaimSet
  ) {
    throw new Error("Stored SD-JWT does not satisfy any DCQL claim_sets option");
  }

  const claimsById = new Map(
    (dcqlCredentialQuery?.claims || [])
      .filter((claim) => typeof claim?.id === "string" && claim.id.length > 0)
      .map((claim) => [claim.id, claim]),
  );
  const claimsToCheck = satisfiedClaimSet
    ? Array.from(satisfiedClaimSet).map((id) => claimsById.get(id)).filter(Boolean)
    : (dcqlCredentialQuery?.claims || []);

  const requiredDisclosureHashes = new Set();
  for (const claim of claimsToCheck) {
    validateDcqlClaimPath(
      claim?.path,
      `credentials[${dcqlCredentialQuery.id}].claims`,
    );
    const selectedValues = selectSdJwtPathValues(parsed.claims, claim.path);
    if (selectedValues.length === 0) {
      throw new Error(
        `Stored SD-JWT is missing requested DCQL disclosure(s): ${claim.path.join(".")}`,
      );
    }
    for (const hash of sdJwtDisclosureHashesForPath(claim.path, parsed.disclosureKeymap)) {
      requiredDisclosureHashes.add(hash);
    }
    if (
      Array.isArray(claim?.values) &&
      claim.values.length > 0 &&
      !selectedValues.some((actualValue) => dcqlValuesInclude(claim.values, actualValue))
    ) {
      throw new DcqlDisclosureSelectionError(
        `Stored SD-JWT claim "${claim.path.join(".")}" does not satisfy requested DCQL values constraint`,
        "access_denied",
      );
    }
  }

  const filteredDisclosures = Array.from(requiredDisclosureHashes)
    .map((hash) => parsed.encodedDisclosureByHash[hash])
    .filter((value) => typeof value === "string" && value.length > 0);

  return `${issuerJwt}${filteredDisclosures.length > 0 ? `~${filteredDisclosures.join("~")}` : ""}~`;
}
