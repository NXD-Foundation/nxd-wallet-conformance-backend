/**
 * DCQL-driven wallet credential selection (OpenID4VP 1.0).
 * Picks a stored credential type that matches dcql_query.credentials[] before
 * falling back to presentation_definition heuristics.
 */

import { isMdocCredential } from "../../utils/mdlVerification.js";
import { extractMdocDocType } from "./mdocDocType.js";

function safeSlog(slog, event, data) {
  if (typeof slog !== "function") return;
  try {
    slog(event, data);
  } catch {}
}

/**
 * @param {string} mdocB64
 * @param {(event: string, data?: object) => void} [slog]
 * @param {string|null} [fallbackDocType]
 * @returns {string|null}
 */
function readMdocDocType(mdocB64, slog, fallbackDocType = null) {
  try {
    const docType = extractMdocDocType(mdocB64, { fallbackDocType });
    if (docType === fallbackDocType && fallbackDocType) {
      safeSlog(slog, "[dcql] using fallback mdoc doctype", {
        fallbackDocType,
        reason: "stored credential did not expose an MSO/top-level docType",
      });
    }
    return docType;
  } catch (e) {
    safeSlog(slog, "[dcql] mdoc doctype decode failed", {
      error: e?.message || String(e),
    });
    return null;
  }
}

/**
 * @param {string} sdJwt
 * @returns {string|undefined}
 */
function readSdJwtVct(sdJwt, slog) {
  try {
    const first = String(sdJwt).split("~")[0];
    const parts = first.split(".");
    if (parts.length < 2) {
      safeSlog(slog, "[dcql] sd-jwt has no payload segment", {
        partCount: parts.length,
      });
      return undefined;
    }
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8"),
    );
    return payload.vct;
  } catch (e) {
    safeSlog(slog, "[dcql] sd-jwt vct decode failed", {
      error: e?.message || String(e),
    });
    return undefined;
  }
}

/**
 * @param {object} credQuery
 * @param {string} token
 * @param {(event: string, data?: object) => void} [slog]
 * @param {object} [options]
 * @param {string|null} [options.fallbackDocType]
 * @returns {boolean}
 */
export function storedCredentialMatchesDcqlQuery(
  credQuery,
  token,
  slog,
  options = {},
) {
  if (!credQuery || !token) {
    safeSlog(slog, "[dcql] match skipped", {
      hasCredentialQuery: !!credQuery,
      hasToken: !!token,
    });
    return false;
  }
  const format = String(credQuery.format || "");
  if (format === "mso_mdoc") {
    if (!isMdocCredential(token)) {
      safeSlog(slog, "[dcql] mdoc match rejected", {
        credentialId: credQuery.id,
        reason: "stored token is not mdoc",
      });
      return false;
    }
    const want = credQuery.meta?.doctype_value;
    if (typeof want === "string" && want.length > 0) {
      const got = readMdocDocType(token, slog, options.fallbackDocType);
      const matched = got === want;
      safeSlog(slog, "[dcql] mdoc doctype comparison", {
        credentialId: credQuery.id,
        expected: want,
        actual: got,
        fallbackDocType: options.fallbackDocType || null,
        matched,
      });
      return matched;
    }
    safeSlog(slog, "[dcql] mdoc match accepted", {
      credentialId: credQuery.id,
      reason: "no doctype_value constraint",
    });
    return true;
  }
  if (format === "dc+sd-jwt" || format === "vc+sd-jwt") {
    if (!String(token).includes("~") || isMdocCredential(token)) {
      safeSlog(slog, "[dcql] sd-jwt match rejected", {
        credentialId: credQuery.id,
        format,
        reason: "stored token is not sd-jwt",
      });
      return false;
    }
    const vct = readSdJwtVct(token, slog);
    const vctValues = credQuery.meta?.vct_values;
    if (Array.isArray(vctValues) && vctValues.length > 0) {
      const matched = vctValues.includes(vct);
      safeSlog(slog, "[dcql] sd-jwt vct comparison", {
        credentialId: credQuery.id,
        format,
        expected: vctValues,
        actual: vct,
        matched,
      });
      return matched;
    }
    safeSlog(slog, "[dcql] sd-jwt match accepted", {
      credentialId: credQuery.id,
      format,
      reason: "no vct_values constraint",
    });
    return true;
  }
  safeSlog(slog, "[dcql] unsupported credential format", {
    credentialId: credQuery.id,
    format,
  });
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

function validateCredentialSets(dcqlQuery, slog) {
  const credentials = Array.isArray(dcqlQuery?.credentials)
    ? dcqlQuery.credentials
    : [];
  const knownIds = new Set(
    credentials
      .map((c) => c?.id)
      .filter((id) => typeof id === "string" && id.length > 0),
  );
  const credentialSets = Array.isArray(dcqlQuery?.credential_sets)
    ? dcqlQuery.credential_sets
    : [];

  for (let setIndex = 0; setIndex < credentialSets.length; setIndex += 1) {
    const set = credentialSets[setIndex];
    const options = Array.isArray(set?.options) ? set.options : [];
    if (options.length === 0) {
      const error = "credential_sets entries must contain at least one option";
      safeSlog(slog, "[dcql] credential_sets invalid", { setIndex, error });
      throw new Error(error);
    }

    for (let optionIndex = 0; optionIndex < options.length; optionIndex += 1) {
      const option = options[optionIndex];
      if (!Array.isArray(option) || option.length === 0) {
        const error = "credential_sets options must be non-empty arrays";
        safeSlog(slog, "[dcql] credential_sets invalid", {
          setIndex,
          optionIndex,
          error,
        });
        throw new Error(error);
      }
      const unknownIds = option.filter((id) => !knownIds.has(id));
      if (unknownIds.length > 0) {
        const error = `credential_sets option references unknown credential id(s): ${unknownIds.join(", ")}`;
        safeSlog(slog, "[dcql] credential_sets invalid", {
          setIndex,
          optionIndex,
          unknownIds,
          knownIds: Array.from(knownIds),
        });
        throw new Error(error);
      }
    }
  }

  safeSlog(slog, "[dcql] credential_sets validated", {
    credentialCount: credentials.length,
    credentialSetCount: credentialSets.length,
  });
}

function credentialIdSatisfiesRequiredCredentialSets(dcqlQuery, credentialId) {
  const credentialSets = Array.isArray(dcqlQuery?.credential_sets)
    ? dcqlQuery.credential_sets
    : [];
  const requiredSets = credentialSets.filter((set) => set?.required !== false);
  if (requiredSets.length === 0) return true;

  return requiredSets.every((set) =>
    set.options.some(
      (option) => option.length === 1 && option[0] === credentialId,
    ),
  );
}

function inferDoctypeFromStoredCredential(type, stored) {
  const metadataDocType = stored?.metadata?.doctype;
  if (typeof metadataDocType === "string" && metadataDocType.length > 0) {
    return metadataDocType;
  }

  const configurationId = stored?.metadata?.configurationId || type;
  if (typeof configurationId !== "string" || configurationId.length === 0) {
    return null;
  }
  if (configurationId.endsWith(":mso_mdoc")) {
    return configurationId.slice(0, -":mso_mdoc".length);
  }
  if (configurationId.includes(":") && configurationId !== "mso_mdoc") {
    return configurationId;
  }
  return null;
}

/**
 * @param {object} params
 * @param {object|null} [params.dcqlQuery]
 * @param {() => Promise<string[]>} params.listWalletCredentialTypes
 * @param {(type: string) => Promise<object|null>} params.getWalletCredentialByType
 * @param {(envelope: object|null|undefined) => string|null} params.extractCredentialString
 * @param {(event: string, data?: object) => void} [params.slog]
 * @returns {Promise<{ selectedType: string, matchedQuery: object }|null>}
 */
export async function selectWalletCredentialTypeForDcql({
  dcqlQuery,
  listWalletCredentialTypes,
  getWalletCredentialByType,
  extractCredentialString,
  slog,
}) {
  if (!dcqlQuery || !Array.isArray(dcqlQuery.credentials)) {
    safeSlog(slog, "[dcql] selection skipped", {
      reason: "dcql_query.credentials missing",
    });
    return null;
  }
  if (dcqlQuery.credentials.length === 0) {
    safeSlog(slog, "[dcql] selection skipped", {
      reason: "dcql_query.credentials empty",
    });
    return null;
  }

  validateCredentialSets(dcqlQuery, slog);
  safeSlog(slog, "[dcql] selection started", {
    credentialQueryCount: dcqlQuery.credentials.length,
    credentialSetCount: Array.isArray(dcqlQuery.credential_sets)
      ? dcqlQuery.credential_sets.length
      : 0,
  });

  const types = await listWalletCredentialTypes();
  safeSlog(slog, "[dcql] wallet credential candidates", {
    count: types.length,
    types,
  });
  for (const credQuery of dcqlQuery.credentials) {
    if (!credQuery || !credQuery.format) {
      safeSlog(slog, "[dcql] credential query skipped", {
        credentialId: credQuery?.id,
        reason: "missing format",
      });
      continue;
    }
    if (!credentialIdSatisfiesRequiredCredentialSets(dcqlQuery, credQuery.id)) {
      safeSlog(slog, "[dcql] credential query skipped", {
        credentialId: credQuery.id,
        reason: "does not satisfy required credential_sets in single-credential mode",
      });
      continue;
    }
    for (const t of types) {
      const stored = await getWalletCredentialByType(t);
      const token = extractCredentialString(stored?.credential);
      if (!token) {
        safeSlog(slog, "[dcql] wallet credential skipped", {
          credentialId: credQuery.id,
          type: t,
          reason: "no presentable token",
          foundStored: !!stored,
        });
        continue;
      }
      if (
        storedCredentialMatchesDcqlQuery(credQuery, token, slog, {
          fallbackDocType: inferDoctypeFromStoredCredential(t, stored),
        })
      ) {
        safeSlog(slog, "[dcql] selection matched", {
          selectedType: t,
          credentialId: credQuery.id,
          format: credQuery.format,
        });
        return { selectedType: t, matchedQuery: credQuery };
      }
    }
  }
  safeSlog(slog, "[dcql] selection failed", {
    credentialQueryIds: dcqlQuery.credentials
      .map((c) => c?.id)
      .filter(Boolean),
  });
  return null;
}
