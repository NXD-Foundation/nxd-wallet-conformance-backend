/**
 * WE BUILD CS-02 strict DCQL validation for wallet presentation requests.
 * Runs after JAR validation and before credential selection.
 */

import { Cs02ValidationError } from "./cs02RequestValidation.js";

export const CS02_ALLOWED_DCQL_FORMATS = new Set(["dc+sd-jwt", "vc+sd-jwt", "mso_mdoc"]);
export const CS02_COMPATIBILITY_DCQL_FORMATS = new Set(["jwt_vc_json", "jwt_vc_json-ld"]);
export const CS02_CREDENTIAL_QUERY_ID_PATTERN = /^[A-Za-z0-9_-]+$/;

const SD_JWT_FORMATS = new Set(["dc+sd-jwt", "vc+sd-jwt"]);

function logDcqlFailure(log, check, details = {}) {
  try {
    log?.("[CS02] DCQL validation failed", { check, ...details });
  } catch {}
}

function isPlainObject(value) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.prototype.toString.call(value) === "[object Object]"
  );
}

export function isSupportedDcqlClaimPathSegment(segment) {
  return typeof segment === "string" && segment.length > 0;
}

export function validateDcqlClaimPath(path, context, log = () => {}) {
  if (!Array.isArray(path) || path.length === 0) {
    logDcqlFailure(log, "claim_path_empty", { context });
    throw new Cs02ValidationError(
      `DCQL claim path must be a non-empty array (${context})`,
      "invalid_request",
    );
  }

  for (let index = 0; index < path.length; index += 1) {
    const segment = path[index];
    if (!isSupportedDcqlClaimPathSegment(segment)) {
      logDcqlFailure(log, "claim_path_segment", { context, index, segmentType: typeof segment });
      throw new Cs02ValidationError(
        `DCQL claim path contains an unsupported segment at index ${index} (${context})`,
        "invalid_request",
      );
    }
  }
}

function validateDcqlClaims(credQuery, log = () => {}) {
  if (credQuery.claims == null) return;
  if (!Array.isArray(credQuery.claims)) {
    logDcqlFailure(log, "claims_not_array", { credentialId: credQuery.id });
    throw new Cs02ValidationError("DCQL claims must be an array", "invalid_request");
  }

  const claimIds = new Set();
  const hasClaimSets = Array.isArray(credQuery.claim_sets) && credQuery.claim_sets.length > 0;

  for (let index = 0; index < credQuery.claims.length; index += 1) {
    const claim = credQuery.claims[index];
    const context = `credentials[${credQuery.id}].claims[${index}]`;
    validateDcqlClaimPath(claim?.path, context, log);

    if (hasClaimSets) {
      if (typeof claim?.id !== "string" || claim.id.length === 0) {
        logDcqlFailure(log, "claim_id_required", { credentialId: credQuery.id, index });
        throw new Cs02ValidationError(
          "DCQL claim id is required when claim_sets is present",
          "invalid_request",
        );
      }
      if (claimIds.has(claim.id)) {
        logDcqlFailure(log, "duplicate_claim_id", { credentialId: credQuery.id, claimId: claim.id });
        throw new Cs02ValidationError(
          `Duplicate DCQL claim id "${claim.id}"`,
          "invalid_request",
        );
      }
      claimIds.add(claim.id);
    }
  }

  if (hasClaimSets) {
    for (let setIndex = 0; setIndex < credQuery.claim_sets.length; setIndex += 1) {
      const claimSet = credQuery.claim_sets[setIndex];
      const references = Array.isArray(claimSet) ? claimSet : claimSet?.ids;
      if (!Array.isArray(references) || references.length === 0) {
        logDcqlFailure(log, "claim_sets_empty", { credentialId: credQuery.id, setIndex });
        throw new Cs02ValidationError("DCQL claim_sets entries must be non-empty", "invalid_request");
      }
      for (const claimId of references) {
        if (!claimIds.has(claimId)) {
          logDcqlFailure(log, "claim_sets_unknown_id", {
            credentialId: credQuery.id,
            setIndex,
            claimId,
          });
          throw new Cs02ValidationError(
            `DCQL claim_sets references unknown claim id "${claimId}"`,
            "invalid_request",
          );
        }
      }
    }
  }
}

function validateDcqlMeta(credQuery, { strict }, log = () => {}) {
  const format = String(credQuery.format || "");
  const meta = credQuery.meta;
  if (meta == null) return;
  if (!isPlainObject(meta)) {
    logDcqlFailure(log, "meta_not_object", { credentialId: credQuery.id });
    throw new Cs02ValidationError("DCQL credential query meta must be an object", "invalid_request");
  }

  if (SD_JWT_FORMATS.has(format) && meta.vct_values != null) {
    if (!Array.isArray(meta.vct_values) || meta.vct_values.length === 0) {
      logDcqlFailure(log, "vct_values_invalid", { credentialId: credQuery.id });
      throw new Cs02ValidationError(
        "DCQL meta.vct_values must be a non-empty array when present",
        "invalid_request",
      );
    }
    for (const value of meta.vct_values) {
      if (typeof value !== "string" || value.length === 0) {
        logDcqlFailure(log, "vct_values_entry", { credentialId: credQuery.id, value });
        throw new Cs02ValidationError(
          "DCQL meta.vct_values entries must be non-empty strings",
          "invalid_request",
        );
      }
    }
  }

  if (format === "mso_mdoc" && meta.doctype_value != null) {
    if (typeof meta.doctype_value !== "string" || meta.doctype_value.length === 0) {
      logDcqlFailure(log, "doctype_value_invalid", { credentialId: credQuery.id });
      throw new Cs02ValidationError(
        "DCQL meta.doctype_value must be a non-empty string when present",
        "invalid_request",
      );
    }
  }

  if (meta.trusted_authorities != null) {
    validateCs02TrustedAuthorities(credQuery, log);
  }
}

function validateHolderBindingPolicy(credQuery, log = () => {}) {
  const format = String(credQuery.format || "");
  if (!SD_JWT_FORMATS.has(format)) return;
  if (credQuery.require_cryptographic_holder_binding === false) {
    logDcqlFailure(log, "holder_binding_disabled", { credentialId: credQuery.id, format });
    throw new Cs02ValidationError(
      "CS-02 requires cryptographic holder binding for SD-JWT-VC credentials",
      "vp_formats_not_supported",
    );
  }
}

export async function validateCs02TrustedAuthorities(credQuery, log = () => {}) {
  // TODO(CS-02 trust registry): enforce trusted_authorities against configured trust registry.
  try {
    log?.("[CS02] trusted_authorities ignored (no trust registry configured)", {
      credentialId: credQuery?.id,
      trustedAuthorities: credQuery?.meta?.trusted_authorities,
    });
  } catch {}
  return { enforced: false, placeholder: true };
}

function validateDcqlCredentialQuery(credQuery, index, options, log = () => {}) {
  const context = `credentials[${index}]`;
  if (!isPlainObject(credQuery)) {
    logDcqlFailure(log, "credential_query_not_object", { index });
    throw new Cs02ValidationError("DCQL credential query must be an object", "invalid_request");
  }

  if (typeof credQuery.id !== "string" || credQuery.id.length === 0) {
    logDcqlFailure(log, "missing_credential_id", { index });
    throw new Cs02ValidationError("DCQL credential query id is required", "invalid_request");
  }
  if (!CS02_CREDENTIAL_QUERY_ID_PATTERN.test(credQuery.id)) {
    logDcqlFailure(log, "invalid_credential_id", { credentialId: credQuery.id });
    throw new Cs02ValidationError(
      `DCQL credential query id "${credQuery.id}" contains invalid characters`,
      "invalid_request",
    );
  }

  if (credQuery.format == null || credQuery.format === "") {
    logDcqlFailure(log, "missing_format", { credentialId: credQuery.id });
    throw new Cs02ValidationError("DCQL credential query format is required", "invalid_request");
  }

  const format = String(credQuery.format);
  if (options.strict) {
    if (!CS02_ALLOWED_DCQL_FORMATS.has(format)) {
      logDcqlFailure(log, "unsupported_format", { credentialId: credQuery.id, format });
      throw new Cs02ValidationError(
        `Unsupported DCQL credential format "${format}" in CS-02 mode`,
        "vp_formats_not_supported",
      );
    }
  } else if (
    !CS02_ALLOWED_DCQL_FORMATS.has(format) &&
    !CS02_COMPATIBILITY_DCQL_FORMATS.has(format)
  ) {
    logDcqlFailure(log, "unsupported_format", { credentialId: credQuery.id, format });
    throw new Cs02ValidationError(
      `Unsupported DCQL credential format "${format}"`,
      "vp_formats_not_supported",
    );
  }

  if (credQuery.multiple != null && typeof credQuery.multiple !== "boolean") {
    logDcqlFailure(log, "invalid_multiple", { credentialId: credQuery.id });
    throw new Cs02ValidationError("DCQL credential query multiple must be a boolean", "invalid_request");
  }

  validateDcqlMeta(credQuery, options, log);
  if (credQuery.trusted_authorities != null) {
    validateCs02TrustedAuthorities(credQuery, log);
  }
  validateDcqlClaims(credQuery, log);
  validateHolderBindingPolicy(credQuery, log);
}

function validateDcqlCredentialSets(dcqlQuery, knownIds, log = () => {}) {
  const credentialSets = Array.isArray(dcqlQuery?.credential_sets)
    ? dcqlQuery.credential_sets
    : [];
  for (let setIndex = 0; setIndex < credentialSets.length; setIndex += 1) {
    const set = credentialSets[setIndex];
    const options = Array.isArray(set?.options) ? set.options : [];
    if (options.length === 0) {
      logDcqlFailure(log, "credential_sets_empty", { setIndex });
      throw new Cs02ValidationError(
        "DCQL credential_sets entries must contain at least one option",
        "invalid_request",
      );
    }
    for (let optionIndex = 0; optionIndex < options.length; optionIndex += 1) {
      const option = options[optionIndex];
      if (!Array.isArray(option) || option.length === 0) {
        logDcqlFailure(log, "credential_sets_option_empty", { setIndex, optionIndex });
        throw new Cs02ValidationError(
          "DCQL credential_sets options must be non-empty arrays",
          "invalid_request",
        );
      }
      const unknownIds = option.filter((id) => !knownIds.has(id));
      if (unknownIds.length > 0) {
        logDcqlFailure(log, "credential_sets_unknown_id", {
          setIndex,
          optionIndex,
          unknownIds,
        });
        throw new Cs02ValidationError(
          `DCQL credential_sets references unknown credential id(s): ${unknownIds.join(", ")}`,
          "invalid_request",
        );
      }
    }
  }
}

export function validateCs02DcqlQuery(dcqlQuery, options = { strict: true }, log = () => {}) {
  if (!isPlainObject(dcqlQuery)) {
    logDcqlFailure(log, "dcql_query_not_object");
    throw new Cs02ValidationError("dcql_query must be an object", "invalid_request");
  }

  if (!Array.isArray(dcqlQuery.credentials) || dcqlQuery.credentials.length === 0) {
    logDcqlFailure(log, "credentials_missing");
    throw new Cs02ValidationError(
      "dcql_query.credentials must be a non-empty array",
      "invalid_request",
    );
  }

  const seenIds = new Set();
  for (let index = 0; index < dcqlQuery.credentials.length; index += 1) {
    const credQuery = dcqlQuery.credentials[index];
    validateDcqlCredentialQuery(credQuery, index, options, log);
    if (seenIds.has(credQuery.id)) {
      logDcqlFailure(log, "duplicate_credential_id", { credentialId: credQuery.id });
      throw new Cs02ValidationError(
        `Duplicate DCQL credential query id "${credQuery.id}"`,
        "invalid_request",
      );
    }
    seenIds.add(credQuery.id);
  }

  validateDcqlCredentialSets(dcqlQuery, seenIds, log);
}

export function validateCs02PresentationQuery(payload, options = { strict: true }, log = () => {}) {
  if (options.strict && payload?.presentation_definition) {
    logDcqlFailure(log, "presentation_definition_present");
    throw new Cs02ValidationError(
      "presentation_definition is not supported in CS-02 mode; use dcql_query",
      "invalid_request",
    );
  }

  if (options.strict && payload?.scope && !payload?.dcql_query) {
    logDcqlFailure(log, "scope_only_query");
    throw new Cs02ValidationError(
      "scope-only credential queries are not supported in CS-02 mode",
      "invalid_request",
    );
  }

  if (payload?.dcql_query && payload?.scope) {
    logDcqlFailure(log, "dcql_and_scope");
    throw new Cs02ValidationError(
      "Authorization request must not contain both dcql_query and scope",
      "invalid_request",
    );
  }

  if (options.strict && !payload?.dcql_query) {
    logDcqlFailure(log, "missing_dcql_query");
    throw new Cs02ValidationError("CS-02 authorization request requires dcql_query", "invalid_request");
  }

  if (payload?.dcql_query) {
    validateCs02DcqlQuery(payload.dcql_query, options, log);
  }
}

export function buildCs02VpTokenMember(presentations, multiple = false) {
  const values = Array.isArray(presentations) ? presentations : [presentations];
  if (values.length === 0) {
    throw new Cs02ValidationError(
      "DCQL presentation generation produced no credentials",
      "access_denied",
    );
  }
  if (multiple === true) {
    return values;
  }
  return values.length === 1 ? values[0] : values[0];
}

export function buildCs02VpTokenObject(entries) {
  const vpTokenObject = {};
  for (const entry of entries) {
    if (!entry?.credQueryId || !Array.isArray(entry.presentations)) continue;
    vpTokenObject[entry.credQueryId] = buildCs02VpTokenMember(
      entry.presentations,
      entry.multiple === true,
    );
  }
  if (Object.keys(vpTokenObject).length === 0) {
    throw new Cs02ValidationError(
      "No credential satisfies the verifier DCQL query",
      "access_denied",
    );
  }
  return vpTokenObject;
}

export function resolveCs02KbJwtAudience(payload, deepLinkClientId) {
  const clientId = payload?.client_id || deepLinkClientId;
  if (!clientId) {
    throw new Cs02ValidationError(
      "Unable to determine verifier client_id for KB-JWT audience",
      "invalid_client",
    );
  }
  return clientId;
}
