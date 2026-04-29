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
      dcqlCredentialQuery.claims
        .map((claim) => (Array.isArray(claim?.path) ? claim.path[0] : null))
        .filter((name) => typeof name === "string" && name.length > 0),
    ),
  );
}

export function filterSdJwtByDcqlClaims(sdJwt, dcqlCredentialQuery) {
  const requestedNames = requestedSdJwtClaimNames(dcqlCredentialQuery);
  if (requestedNames.length === 0) return sdJwt;

  const requested = new Set(requestedNames);
  const { issuerJwt, disclosures } = sdJwtWithoutKbJwt(sdJwt);
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
