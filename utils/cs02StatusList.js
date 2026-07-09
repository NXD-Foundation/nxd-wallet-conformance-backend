/**
 * WE BUILD CS-02 placeholder status-list validation for SD-JWT-VC credentials.
 *
 * Future strict behavior (once trust framework exists):
 * - reject missing status when CS02_STRICT_STATUS_VALIDATION=true
 * - reject malformed, suspended, or revoked credentials after fetching status-list tokens
 */

import { decodeJwt } from "jose";

export class Cs02StatusListError extends Error {
  constructor(message, errorCode = "invalid_credential", statusState = "structurally_invalid") {
    super(message);
    this.name = "Cs02StatusListError";
    this.errorCode = errorCode;
    this.statusState = statusState;
  }
}

function truthyEnv(value) {
  if (value == null || value === "") return false;
  const normalized = String(value).trim().toLowerCase();
  return normalized === "true" || normalized === "1" || normalized === "yes";
}

export function resolveCs02StatusListOptions(env = process.env) {
  return {
    strictMissingStatus: truthyEnv(env.CS02_STRICT_STATUS_VALIDATION),
  };
}

function normalizeStatusListOptions(optionsOrEnv = process.env) {
  const input = optionsOrEnv || {};
  const env = input.env || input;
  const trustPolicyOptions = input.trustPolicyOptions || {};
  const envOptions = resolveCs02StatusListOptions(env);
  const strictMissingStatus =
    trustPolicyOptions.strictStatus === true ||
    (typeof input.strictMissingStatus === "boolean"
      ? input.strictMissingStatus
      : envOptions.strictMissingStatus);
  return {
    strictMissingStatus,
    trustPolicyOptions,
    log: typeof input.log === "function" ? input.log : () => {},
  };
}

function logStatusPlaceholder(log, message, details) {
  try {
    log?.("[CS02] status-list placeholder decision", {
      level: "debug",
      message,
      ...details,
    });
  } catch {}
}

export function decodeSdJwtIssuerPayload(sdJwt) {
  if (typeof sdJwt !== "string" || sdJwt.length === 0) return null;
  const issuerJwt = sdJwt.split("~")[0];
  if (!issuerJwt || issuerJwt.split(".").length < 2) return null;
  try {
    return decodeJwt(issuerJwt);
  } catch {
    return null;
  }
}

export function validateCs02StatusListReference(status, options = { strictMissingStatus: false }) {
  if (status == null) {
    if (options.strictMissingStatus) {
      throw new Cs02StatusListError(
        "SD-JWT-VC credential is missing required status claim",
        "invalid_credential",
      );
    }
    return {
      ok: true,
      present: false,
      statusState: "absent",
      enforced: false,
      placeholder: true,
      futureBehavior:
        "When CS02_STRICT_STATUS_VALIDATION=true and trust framework exists, missing status will be rejected.",
    };
  }

  if (typeof status !== "object" || Array.isArray(status)) {
    throw new Cs02StatusListError("Credential status claim must be an object", "invalid_credential");
  }

  const statusList = status.status_list;
  if (statusList == null) {
    if (options.strictMissingStatus) {
      throw new Cs02StatusListError(
        "Credential status claim is missing status_list",
        "invalid_credential",
      );
    }
    return {
      ok: true,
      present: false,
      statusState: "absent",
      enforced: false,
      placeholder: true,
      futureBehavior:
        "When CS02_STRICT_STATUS_VALIDATION=true and trust framework exists, missing status_list will be rejected.",
    };
  }

  if (typeof statusList !== "object" || Array.isArray(statusList)) {
    throw new Cs02StatusListError("status.status_list must be an object", "invalid_credential");
  }

  const idx = statusList.idx;
  if (!Number.isInteger(idx) || idx < 0) {
    throw new Cs02StatusListError(
      "status.status_list.idx must be a non-negative integer",
      "invalid_credential",
    );
  }

  const uri = statusList.uri;
  if (typeof uri !== "string" || uri.length === 0) {
    throw new Cs02StatusListError("status.status_list.uri must be a non-empty string", "invalid_credential");
  }

  let parsedUri;
  try {
    parsedUri = new URL(uri);
  } catch {
    throw new Cs02StatusListError("status.status_list.uri must be an absolute URI", "invalid_credential");
  }

  if (parsedUri.protocol !== "https:") {
    throw new Cs02StatusListError("status.status_list.uri must use HTTPS", "invalid_credential");
  }

  return {
    ok: true,
    present: true,
    statusState: "structurally_valid_placeholder",
    enforced: false,
    idx,
    uri,
    placeholder: true,
    todos: [
      "Load trusted status-list issuers from trust framework configuration",
      "Define allowed status-list JWT algorithms",
      "Fetch status-list token from uri with cache/timeout/max-size policy",
      "Apply fetch timeout and maximum response size limits",
      "Verify status-list token signature against trusted issuers",
      "Decode bitstring and evaluate revoked/suspended bit for idx",
    ],
  };
}

export async function validateCs02CredentialStatusList(sdJwt, optionsOrEnv = process.env) {
  const options = normalizeStatusListOptions(optionsOrEnv);
  const payload = decodeSdJwtIssuerPayload(sdJwt);
  if (!payload) {
    throw new Cs02StatusListError("Unable to decode SD-JWT issuer payload", "invalid_credential");
  }

  const reference = validateCs02StatusListReference(payload.status, options);
  if (reference.placeholder) {
    logStatusPlaceholder(options.log, "status-list trust framework is not configured", {
      issuer: typeof payload.iss === "string" ? payload.iss : null,
      statusState: reference.statusState,
      present: reference.present,
      trustEnforced: options.trustPolicyOptions?.hasTrustRegistry === true,
    });
  }
  // TODO(CS-02 status framework): fetch, verify, cache, and evaluate status-list token
  // once trusted status-list issuers, allowed JWT algorithms, cache lifetime, fetch timeout,
  // maximum response size, and revoked/suspended bit interpretation are configured.
  return {
    ...reference,
    issuer: typeof payload.iss === "string" ? payload.iss : null,
    trustPolicy: {
      hasTrustRegistry: options.trustPolicyOptions?.hasTrustRegistry === true,
      strictStatus: options.strictMissingStatus === true,
    },
  };
}
