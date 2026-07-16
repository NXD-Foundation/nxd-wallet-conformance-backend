import { decode } from "cbor-x";
import { selectSatisfiedCs02ClaimSet } from "./cs02DcqlCore.js";

function normalizeNameSpaces(nameSpaces) {
  if (!nameSpaces) return {};
  if (nameSpaces instanceof Map) {
    return Object.fromEntries(nameSpaces.entries());
  }
  return typeof nameSpaces === "object" ? nameSpaces : {};
}

function decodeMdocInput(mdocInput) {
  if (typeof mdocInput === "string") {
    return decode(Buffer.from(String(mdocInput), "base64url"));
  }
  if (mdocInput && typeof mdocInput === "object") {
    return mdocInput;
  }
  throw new Error("Unsupported mdoc input");
}

function normalizeMdocDocument(decoded) {
  if (decoded?.version && Array.isArray(decoded?.documents) && decoded.documents.length > 0) {
    return decoded.documents[0];
  }
  if (decoded?.docType || decoded?.issuerSigned) {
    return decoded;
  }
  if (decoded?.nameSpaces && decoded?.issuerAuth) {
    return {
      docType: null,
      issuerSigned: decoded,
    };
  }
  throw new Error("Unknown mdoc structure");
}

export function extractMdocClaimsByNamespace(mdocInput, { fallbackDocType = null } = {}) {
  const decoded = decodeMdocInput(mdocInput);
  const document = normalizeMdocDocument(decoded);
  const issuerSigned = document.issuerSigned || document;
  const nameSpaces = normalizeNameSpaces(issuerSigned?.nameSpaces);
  const claimsByNamespace = {};

  for (const [namespace, elements] of Object.entries(nameSpaces)) {
    if (!Array.isArray(elements)) continue;
    const claims = {};
    for (const element of elements) {
      try {
        const decodedElement = element?.tag !== undefined ? decode(element.value) : decode(element);
        if (
          typeof decodedElement?.elementIdentifier === "string" &&
          decodedElement.elementIdentifier.length > 0 &&
          decodedElement.elementValue !== undefined
        ) {
          claims[decodedElement.elementIdentifier] = decodedElement.elementValue;
        }
      } catch {}
    }
    claimsByNamespace[namespace] = claims;
  }

  return {
    docType: document.docType || fallbackDocType || null,
    claimsByNamespace,
  };
}

export function getMdocPathValue(claimsByNamespace, path) {
  if (!Array.isArray(path) || path.length === 0) return undefined;
  let current = claimsByNamespace;
  for (const segment of path) {
    if (typeof segment !== "string" || segment.length === 0) return undefined;
    if (!current || typeof current !== "object") return undefined;
    current = current[segment];
  }
  return current;
}

function claimSatisfiesValueConstraint(claim, claimsByNamespace) {
  if (!Array.isArray(claim?.values) || claim.values.length === 0) return true;
  const actualValue = getMdocPathValue(claimsByNamespace, claim.path);
  return typeof actualValue === "string" && claim.values.includes(actualValue);
}

function claimIsPresent(claim, claimsByNamespace) {
  return getMdocPathValue(claimsByNamespace, claim?.path) !== undefined;
}

export function claimSatisfiesMdocConstraints(claim, claimsByNamespace) {
  return claimIsPresent(claim, claimsByNamespace) && claimSatisfiesValueConstraint(claim, claimsByNamespace);
}

export function selectSatisfiedMdocClaimSet(credQuery, claimsByNamespace) {
  return selectSatisfiedCs02ClaimSet(credQuery, (claim) => claimSatisfiesMdocConstraints(claim, claimsByNamespace));
}
