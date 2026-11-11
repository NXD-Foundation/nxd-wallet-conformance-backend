/**
 * Verifier-side credential revocation check for a cleartext SD-JWT `status` claim.
 *
 * A present `status.status_list` is fetched and verified with the same key that
 * verified the credential. Lists are cached in this process until the freshness
 * deadline. A missing status claim is accepted unless strict status validation
 * is enabled. A selectively disclosed `status` claim is rejected.
 */

import { decodeJwt } from "jose";
import { CredentialStatusFreshnessError, evaluateCredentialStatusFreshness } from "./credentialStatusFreshness.js";
import {
  evaluateWuaStatusList,
  publicJwkOnly,
  WuaStatusListValidationError,
} from "./wuaStatusListVerifier.js";

const statusListCache = new Map();
const statusListFetches = new Map();

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
    verificationJwk: publicJwkOnly(input.verificationJwk),
  };
}

export function resetCredentialStatusCacheForTests() {
  statusListCache.clear();
  statusListFetches.clear();
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

function sdJwtDisclosureParts(sdJwt) {
  const tail = String(sdJwt || "").split("~").slice(1).filter((part) => part.length > 0);
  const last = tail[tail.length - 1];
  const hasKeyBinding = Boolean(last && last.split(".").length === 3);
  return hasKeyBinding ? tail.slice(0, -1) : tail;
}

export function sdJwtDisclosesStatus(sdJwt) {
  for (const encoded of sdJwtDisclosureParts(sdJwt)) {
    try {
      const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
      if (Array.isArray(decoded) && decoded[1] === "status") return true;
    } catch {
      // A malformed disclosure is rejected by SD-JWT claim reconstruction.
    }
  }
  return false;
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
    };
  }

  if (typeof status !== "object" || Array.isArray(status)) {
    throw new Cs02StatusListError("Credential status claim must be an object", "invalid_credential");
  }

  const statusList = status.status_list;
  if (statusList == null) {
    throw new Cs02StatusListError(
      "Credential status claim is missing status_list",
      "invalid_credential",
    );
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
    idx,
    uri,
  };
}

function cacheKey(uri, verificationJwk) {
  return `${uri}\n${JSON.stringify(verificationJwk)}`;
}

function statusFailure(error) {
  if (error instanceof Cs02StatusListError) return error;
  if (error instanceof CredentialStatusFreshnessError) {
    return new Cs02StatusListError(
      error.message,
      "invalid_credential",
      error.reason === "stale" ? "stale" : "status_unavailable",
    );
  }
  if (error instanceof WuaStatusListValidationError && error.reason === "expired") {
    return new Cs02StatusListError(error.message, "invalid_credential", "stale");
  }
  const message = error?.message || "credential status validation failed";
  return new Cs02StatusListError(
    `Unable to validate credential status: ${message}`,
    "invalid_credential",
    "status_unavailable",
  );
}

function rejectionForStatus(status) {
  if (status === 0) return null;
  if (status === 1) {
    return new Cs02StatusListError("Credential status is INVALID", "invalid_credential", "revoked");
  }
  return new Cs02StatusListError("Credential status is not VALID", "invalid_credential", "invalid");
}

function rememberedList(reference, verificationJwk, now) {
  const key = cacheKey(reference.uri, verificationJwk);
  const cached = statusListCache.get(key);
  if (!cached || cached.cacheUntil <= now) return null;
  return { key, cached };
}

function credentialStatusRequest(reference, verificationJwk, jwt) {
  return {
    uri: reference.uri,
    idx: reference.idx,
    verificationJwk,
    kind: "credential",
    allowHeaderKey: false,
    acceptInvalidStatus: true,
    ...(jwt ? { jwt } : {}),
  };
}

async function readCachedStatus(reference, verificationJwk, cached) {
  const evaluated = await evaluateWuaStatusList(credentialStatusRequest(reference, verificationJwk, cached.jwt));
  return { evaluated, fromCache: true, freshness: cached.freshness };
}

async function fetchCredentialStatus(reference, verificationJwk, now) {
  const key = cacheKey(reference.uri, verificationJwk);
  const pending = statusListFetches.get(key);
  if (pending) {
    await pending;
    const cached = statusListCache.get(key);
    if (!cached || cached.cacheUntil <= now) {
      throw new Cs02StatusListError(
        "Unable to validate credential status: status list was not cached",
        "invalid_credential",
        "status_unavailable",
      );
    }
    return readCachedStatus(reference, verificationJwk, cached);
  }

  let resolveFetch;
  let rejectFetch;
  const gate = new Promise((resolve, reject) => {
    resolveFetch = resolve;
    rejectFetch = reject;
  });
  gate.catch(() => {});
  statusListFetches.set(key, gate);
  try {
    const evaluated = await evaluateWuaStatusList(credentialStatusRequest(reference, verificationJwk));
    const freshness = evaluateCredentialStatusFreshness({
      iat: evaluated.iat,
      exp: evaluated.exp,
      ttl: evaluated.ttl,
      fetchedAt: now,
      now,
    });
    const loaded = { evaluated, fromCache: false, freshness };
    statusListCache.set(key, { jwt: evaluated.jwt, cacheUntil: freshness.cacheUntil, freshness });
    resolveFetch(loaded);
    return loaded;
  } catch (error) {
    rejectFetch(error);
    throw error;
  } finally {
    statusListFetches.delete(key);
  }
}

async function enforceCredentialStatus(reference, verificationJwk) {
  if (!verificationJwk) {
    throw new Cs02StatusListError(
      "Credential status cannot be verified without the credential issuer key",
      "invalid_credential",
      "status_unavailable",
    );
  }
  const now = Math.floor(Date.now() / 1000);
  const remembered = rememberedList(reference, verificationJwk, now);
  const loaded = remembered
    ? await readCachedStatus(reference, verificationJwk, remembered.cached)
    : await fetchCredentialStatus(reference, verificationJwk, now);
  const rejected = rejectionForStatus(loaded.evaluated.status);
  if (rejected) throw rejected;
  return {
    ...reference,
    statusState: "valid",
    enforced: true,
    fromCache: loaded.fromCache,
    freshness: loaded.freshness,
  };
}

export async function validateCs02CredentialStatusList(sdJwt, optionsOrEnv = process.env) {
  const options = normalizeStatusListOptions(optionsOrEnv);
  if (sdJwtDisclosesStatus(sdJwt)) {
    throw new Cs02StatusListError(
      "Credential status claim must be in the issuer-signed payload",
      "invalid_credential",
    );
  }
  const payload = decodeSdJwtIssuerPayload(sdJwt);
  if (!payload) {
    throw new Cs02StatusListError("Unable to decode SD-JWT issuer payload", "invalid_credential");
  }

  const reference = validateCs02StatusListReference(payload.status, options);
  const issuer = typeof payload.iss === "string" ? payload.iss : null;
  const trustPolicy = {
    hasTrustRegistry: options.trustPolicyOptions?.hasTrustRegistry === true,
    strictStatus: options.strictMissingStatus === true,
  };
  if (!reference.present) {
    return { ...reference, issuer, trustPolicy };
  }
  try {
    const enforced = await enforceCredentialStatus(reference, options.verificationJwk);
    return { ...enforced, issuer, trustPolicy };
  } catch (error) {
    throw statusFailure(error);
  }
}
