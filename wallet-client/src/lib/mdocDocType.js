import { decode } from "cbor-x";

function unwrapCborTag(value) {
  if (value && typeof value === "object" && "tag" in value && "value" in value) {
    return value.value;
  }
  return value;
}

function decodeCborBytes(value) {
  const unwrapped = unwrapCborTag(value);
  if (unwrapped instanceof Uint8Array || Buffer.isBuffer(unwrapped)) {
    return decode(unwrapped);
  }
  if (unwrapped instanceof ArrayBuffer) {
    return decode(new Uint8Array(unwrapped));
  }
  return unwrapped;
}

function readIssuerAuthDocType(issuerAuth) {
  const coseSign1 = unwrapCborTag(issuerAuth);
  if (!Array.isArray(coseSign1) || coseSign1.length < 3) return null;

  try {
    const mobileSecurityObject = decodeCborBytes(coseSign1[2]);
    return typeof mobileSecurityObject?.docType === "string"
      ? mobileSecurityObject.docType
      : null;
  } catch {
    return null;
  }
}

/**
 * Extract the mdoc document type from stored issuance or presentation CBOR.
 *
 * OID4VCI mso_mdoc credentials may be IssuerSigned-only:
 * { nameSpaces, issuerAuth }. In that case docType is in the issuerAuth MSO
 * payload, not as a top-level field. If the issuerAuth cannot be decoded,
 * callers may provide a fallback from validated issuer metadata.
 *
 * @param {string} mdocB64 base64url-encoded CBOR mdoc credential
 * @param {object} [options]
 * @param {string|null} [options.fallbackDocType]
 * @returns {string|null}
 */
export function extractMdocDocType(mdocB64, { fallbackDocType = null } = {}) {
  const decoded = decode(Buffer.from(String(mdocB64), "base64url"));

  if (decoded?.documents?.[0]?.docType) return decoded.documents[0].docType;
  if (typeof decoded?.docType === "string") return decoded.docType;

  const issuerSigned =
    decoded?.issuerSigned ||
    (decoded?.nameSpaces && decoded?.issuerAuth ? decoded : null);
  if (!issuerSigned) return null;

  const msoDocType = readIssuerAuthDocType(issuerSigned.issuerAuth);
  if (msoDocType) return msoDocType;

  return fallbackDocType;
}
