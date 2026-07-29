import crypto from "crypto";
import { decode } from "cbor-x";
import {
  dcqlValuesInclude,
  selectClaimPathValues,
  selectSatisfiedClaimSet,
} from "./dcqlCore.js";

function derToPem(der) {
  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

function certificateFingerprint(pem) {
  const der = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return crypto.createHash("sha256").update(Buffer.from(der, "base64")).digest("hex");
}

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

export function extractMdocIssuerCertificate(mdocInput) {
  const decoded = decodeMdocInput(mdocInput);
  const document = normalizeMdocDocument(decoded);
  const issuerAuth = document.issuerSigned?.issuerAuth;
  const coseSign1 = issuerAuth?.value || issuerAuth;
  if (!Array.isArray(coseSign1) || coseSign1.length < 2) return null;

  const headers = coseSign1[1];
  const x5chain =
    headers instanceof Map ? headers.get(33) || headers.get("33") : headers?.[33] || headers?.["33"];
  const leaf = Array.isArray(x5chain) ? x5chain[0] : null;
  if (!(Buffer.isBuffer(leaf) || leaf instanceof Uint8Array)) return null;
  const certificatePem = derToPem(leaf);
  return {
    certificatePem,
    certificateFingerprint: certificateFingerprint(certificatePem),
  };
}

export function getMdocPathValue(claimsByNamespace, path) {
  const selected = selectClaimPathValues(claimsByNamespace, path);
  return selected.length > 0 ? selected[0] : undefined;
}

function claimSatisfiesValueConstraint(claim, claimsByNamespace) {
  const selected = selectClaimPathValues(claimsByNamespace, claim?.path);
  if (selected.length === 0) return false;
  if (!Array.isArray(claim?.values) || claim.values.length === 0) return true;
  return selected.some((actualValue) => dcqlValuesInclude(claim.values, actualValue));
}

export function claimSatisfiesMdocConstraints(claim, claimsByNamespace) {
  return claimSatisfiesValueConstraint(claim, claimsByNamespace);
}

export function selectSatisfiedMdocClaimSet(credQuery, claimsByNamespace) {
  return selectSatisfiedClaimSet(credQuery, (claim) =>
    claimSatisfiesMdocConstraints(claim, claimsByNamespace),
  );
}
