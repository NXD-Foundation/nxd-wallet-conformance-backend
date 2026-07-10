/**
 * DCQL-driven wallet credential selection (OpenID4VP 1.0).
 * Picks a stored credential type that matches dcql_query.credentials[] before
 * falling back to presentation_definition heuristics.
 */

import { isMdocCredential } from "../../utils/mdlVerification.js";
import {
  claimSatisfiesMdocConstraints,
  extractMdocClaimsByNamespace,
  selectSatisfiedMdocClaimSet,
} from "../../utils/mdocClaims.js";
import { parseSdJwtClaims, selectSatisfiedSdJwtClaimSet, claimSatisfiesSdJwtConstraints } from "../../utils/sdJwtClaims.js";
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
      if (!matched) return false;
    }
    const claimConstraints = Array.isArray(credQuery.claims) ? credQuery.claims : [];
    if (claimConstraints.length > 0) {
      let claimsByNamespace;
      try {
        claimsByNamespace = extractMdocClaimsByNamespace(token, {
          fallbackDocType: options.fallbackDocType,
        }).claimsByNamespace;
      } catch (e) {
        safeSlog(slog, "[dcql] mdoc claims decode failed", {
          credentialId: credQuery.id,
          error: e?.message || String(e),
        });
        return false;
      }

      const satisfiedClaimSet = selectSatisfiedMdocClaimSet(credQuery, claimsByNamespace);
      const claimsById = new Map(
        claimConstraints
          .filter((claim) => typeof claim?.id === "string" && claim.id.length > 0)
          .map((claim) => [claim.id, claim]),
      );
      const claimsToCheck = satisfiedClaimSet
        ? Array.from(satisfiedClaimSet).map((id) => claimsById.get(id)).filter(Boolean)
        : claimConstraints;

      if (Array.isArray(credQuery.claim_sets) && credQuery.claim_sets.length > 0 && !satisfiedClaimSet) {
        safeSlog(slog, "[dcql] mdoc claim_sets unsatisfied", {
          credentialId: credQuery.id,
        });
        return false;
      }

      for (const claim of claimsToCheck) {
        const matched = claimSatisfiesMdocConstraints(claim, claimsByNamespace);
        safeSlog(slog, "[dcql] mdoc claim constraint comparison", {
          credentialId: credQuery.id,
          path: claim?.path,
          expectedValues: claim?.values || null,
          matched,
        });
        if (!matched) {
          return false;
        }
      }
    }
    safeSlog(slog, "[dcql] mdoc match accepted", {
      credentialId: credQuery.id,
      reason: claimConstraints.length > 0 ? "doctype and claim constraints satisfied" : "no doctype_value or claim constraints",
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
      if (!matched) return false;
    }
    const claimConstraints = Array.isArray(credQuery.claims) ? credQuery.claims : [];
    const needsClaimMatching = claimConstraints.length > 0;
    if (needsClaimMatching) {
      let parsed;
      try {
        parsed = parseSdJwtClaims(token);
      } catch (e) {
        safeSlog(slog, "[dcql] sd-jwt claims decode failed", {
          error: e?.message || String(e),
        });
        return false;
      }
      const satisfiedClaimSet = selectSatisfiedSdJwtClaimSet(credQuery, parsed.claims);
      const claimsById = new Map(
        claimConstraints
          .filter((claim) => typeof claim?.id === "string" && claim.id.length > 0)
          .map((claim) => [claim.id, claim]),
      );
      const claimsToCheck = satisfiedClaimSet
        ? Array.from(satisfiedClaimSet).map((id) => claimsById.get(id)).filter(Boolean)
        : claimConstraints;
      if (Array.isArray(credQuery.claim_sets) && credQuery.claim_sets.length > 0 && !satisfiedClaimSet) {
        safeSlog(slog, "[dcql] sd-jwt claim_sets unsatisfied", {
          credentialId: credQuery.id,
          format,
        });
        return false;
      }
      for (const claim of claimsToCheck) {
        const matched = claimSatisfiesSdJwtConstraints(claim, parsed.claims);
        safeSlog(slog, "[dcql] sd-jwt claim comparison", {
          credentialId: credQuery.id,
          format,
          path: claim?.path,
          expected: claim?.values || null,
          matched,
        });
        if (!matched) return false;
      }
    }
    safeSlog(slog, "[dcql] sd-jwt match accepted", {
      credentialId: credQuery.id,
      format,
      reason: needsClaimMatching ? "vct_values and claim constraints satisfied" : "no vct_values or claim constraints",
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

async function findWalletMatchesForDcqlQuery({
  credQuery,
  types,
  getWalletCredentialByType,
  extractCredentialString,
  slog,
}) {
  const matches = [];
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
      matches.push({
        selectedType: t,
        matchedQuery: credQuery,
        stored,
        token,
      });
      if (credQuery.multiple !== true) {
        break;
      }
    }
  }
  return matches;
}

function resolveTargetCredentialQueryIds(dcqlQuery, matchesByQueryId) {
  const matchedIds = new Set(matchesByQueryId.keys());
  const credentialSets = Array.isArray(dcqlQuery?.credential_sets)
    ? dcqlQuery.credential_sets
    : [];
  const requiredSets = credentialSets.filter((set) => set?.required !== false);

  if (requiredSets.length === 0) {
    const requestedIds = dcqlQuery.credentials.map((credQuery) => credQuery?.id).filter(Boolean);
    return requestedIds.every((id) => matchedIds.has(id)) ? requestedIds : null;
  }

  const selectedIds = new Set();
  for (const set of requiredSets) {
    let selectedOption = null;
    for (const option of set.options) {
      if (option.every((id) => matchedIds.has(id))) {
        selectedOption = option;
        break;
      }
    }
    if (!selectedOption) return null;
    for (const id of selectedOption) selectedIds.add(id);
  }
  return Array.from(selectedIds);
}

/**
 * Select one or more wallet credentials for a DCQL query, honoring multiple=true
 * and required credential_sets options.
 *
 * @returns {Promise<Array<{ selectedType: string, matchedQuery: object, stored: object, token: string }>>}
 */
export async function selectWalletCredentialsForDcql({
  dcqlQuery,
  listWalletCredentialTypes,
  getWalletCredentialByType,
  extractCredentialString,
  slog,
}) {
  if (!dcqlQuery || !Array.isArray(dcqlQuery.credentials) || dcqlQuery.credentials.length === 0) {
    safeSlog(slog, "[dcql] selection skipped", { reason: "dcql_query.credentials missing or empty" });
    return [];
  }

  validateCredentialSets(dcqlQuery, slog);
  const types = await listWalletCredentialTypes();
  safeSlog(slog, "[dcql] multi-selection started", {
    credentialQueryCount: dcqlQuery.credentials.length,
    walletTypeCount: types.length,
  });

  const matchesByQueryId = new Map();
  for (const credQuery of dcqlQuery.credentials) {
    if (!credQuery?.format) continue;
    const matches = await findWalletMatchesForDcqlQuery({
      credQuery,
      types,
      getWalletCredentialByType,
      extractCredentialString,
      slog,
    });
    if (matches.length > 0) {
      matchesByQueryId.set(credQuery.id, matches);
    }
  }

  const targetQueryIds = resolveTargetCredentialQueryIds(dcqlQuery, matchesByQueryId);
  if (!targetQueryIds || targetQueryIds.length === 0) {
    safeSlog(slog, "[dcql] multi-selection failed", {
      matchedQueryIds: Array.from(matchesByQueryId.keys()),
    });
    return [];
  }

  const selections = [];
  for (const queryId of targetQueryIds) {
    const credQuery = dcqlQuery.credentials.find((entry) => entry?.id === queryId);
    const matches = matchesByQueryId.get(queryId) || [];
    if (matches.length === 0) {
      safeSlog(slog, "[dcql] required credential query unsatisfied", { queryId });
      return [];
    }
    if (credQuery?.multiple === true) {
      selections.push(...matches);
    } else {
      selections.push(matches[0]);
    }
  }

  safeSlog(slog, "[dcql] multi-selection matched", {
    selectionCount: selections.length,
    credentialQueryIds: targetQueryIds,
  });
  return selections;
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
  const selections = await selectWalletCredentialsForDcql({
    dcqlQuery,
    listWalletCredentialTypes,
    getWalletCredentialByType,
    extractCredentialString,
    slog,
  });
  if (selections.length === 0) {
    return null;
  }
  const first = selections[0];
  return { selectedType: first.selectedType, matchedQuery: first.matchedQuery };
}
