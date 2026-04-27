/**
 * DCQL-driven wallet credential selection (OpenID4VP 1.0).
 * Picks a stored credential type that matches dcql_query.credentials[] before
 * falling back to presentation_definition heuristics.
 */

import { isMdocCredential } from "../../utils/mdlVerification.js";
import { decode } from "cbor-x";
import base64url from "base64url";

/**
 * @param {string} mdocB64
 * @returns {string|null}
 */
function readMdocDocType(mdocB64) {
  try {
    const buf = base64url.toBuffer(mdocB64);
    const d = decode(buf);
    if (d && typeof d === "object" && d.documents && d.documents[0]?.docType) {
      return d.documents[0].docType;
    }
    if (d?.docType) return d.docType;
    return null;
  } catch {
    return null;
  }
}

/**
 * @param {string} sdJwt
 * @returns {string|undefined}
 */
function readSdJwtVct(sdJwt) {
  try {
    const first = String(sdJwt).split("~")[0];
    const parts = first.split(".");
    if (parts.length < 2) return undefined;
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8"),
    );
    return payload.vct;
  } catch {
    return undefined;
  }
}

/**
 * @param {object} credQuery
 * @param {string} token
 * @returns {boolean}
 */
export function storedCredentialMatchesDcqlQuery(credQuery, token) {
  if (!credQuery || !token) return false;
  const format = String(credQuery.format || "");
  if (format === "mso_mdoc") {
    if (!isMdocCredential(token)) return false;
    const want = credQuery.meta?.doctype_value;
    if (typeof want === "string" && want.length > 0) {
      const got = readMdocDocType(token);
      return got === want;
    }
    return true;
  }
  if (format === "dc+sd-jwt" || format === "vc+sd-jwt") {
    if (!String(token).includes("~") || isMdocCredential(token)) return false;
    const vct = readSdJwtVct(token);
    const vctValues = credQuery.meta?.vct_values;
    if (Array.isArray(vctValues) && vctValues.length > 0) {
      return vctValues.includes(vct);
    }
    return true;
  }
  return false;
}

/**
 * OpenID4VP `presentation_submission` descriptor `format` and wire expectations.
 * @param {object} credQuery - dcql_query.credentials[i]
 * @returns {string}
 */
export function presentationFormatFromDcqlQuery(credQuery) {
  const f = String(credQuery?.format || "");
  if (f === "mso_mdoc") return "mso_mdoc";
  if (f === "dc+sd-jwt") return "dc+sd-jwt";
  if (f === "vc+sd-jwt") return "vc+sd-jwt";
  if (f === "jwt_vc_json" || f === "jwt_vc_json-ld") return "jwt_vc_json";
  return f || "dc+sd-jwt";
}

/**
 * @param {object} params
 * @param {object|null} [params.dcqlQuery]
 * @param {() => Promise<string[]>} params.listWalletCredentialTypes
 * @param {(type: string) => Promise<object|null>} params.getWalletCredentialByType
 * @param {(envelope: object|null|undefined) => string|null} params.extractCredentialString
 * @returns {Promise<{ selectedType: string, matchedQuery: object }|null>}
 */
export async function selectWalletCredentialTypeForDcql({
  dcqlQuery,
  listWalletCredentialTypes,
  getWalletCredentialByType,
  extractCredentialString,
}) {
  if (!dcqlQuery || !Array.isArray(dcqlQuery.credentials)) return null;
  if (dcqlQuery.credentials.length === 0) return null;

  for (const credQuery of dcqlQuery.credentials) {
    if (!credQuery || !credQuery.format) continue;
    const types = await listWalletCredentialTypes();
    for (const t of types) {
      const stored = await getWalletCredentialByType(t);
      const token = extractCredentialString(stored?.credential);
      if (!token) continue;
      if (storedCredentialMatchesDcqlQuery(credQuery, token)) {
        return { selectedType: t, matchedQuery: credQuery };
      }
    }
  }
  return null;
}
