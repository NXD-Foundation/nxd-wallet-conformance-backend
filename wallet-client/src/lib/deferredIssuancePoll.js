import { parseCredentialResponsePayload } from "./credentialResponseEncryption.js";

/** OIDC4VCI §9 / RFC001 §6.3 — server hint in seconds; wait at least this long between polls. */
export function getNextPollDelayMs(issuerIntervalSeconds, clientIntervalMs = 2000) {
  const client = Math.max(0, Number(clientIntervalMs) || 0) || 2000;
  if (
    typeof issuerIntervalSeconds === "number" &&
    Number.isFinite(issuerIntervalSeconds) &&
    issuerIntervalSeconds >= 0
  ) {
    return Math.max(client, issuerIntervalSeconds * 1000);
  }
  return client;
}

/**
 * @param {object} opts
 * @param {number} opts.status
 * @param {boolean} opts.ok
 * @param {string | null | undefined} opts.contentType
 * @param {string} opts.responseText
 * @param {import("jose").KeyLike | null | undefined} opts.decryptionPrivateKey
 * @returns {Promise<{ kind: "success"; body: object } | { kind: "pending"; interval?: number } | { kind: "terminal"; status: number; errorBody: object }>}
 */
export async function resolveDeferredPollResult({
  status,
  ok,
  contentType,
  responseText,
  decryptionPrivateKey,
}) {
  if (ok) {
    let body;
    try {
      body = await parseCredentialResponsePayload(
        responseText,
        contentType,
        decryptionPrivateKey,
      );
    } catch (e) {
      return {
        kind: "terminal",
        status,
        errorBody: {
          error: "invalid_response",
          error_description: e?.message || "Failed to parse deferred credential response",
        },
      };
    }
    if (!body || typeof body !== "object") {
      return {
        kind: "terminal",
        status,
        errorBody: {
          error: "invalid_response",
          error_description: "Deferred credential success body was not a JSON object",
        },
      };
    }
    return { kind: "success", body };
  }

  let errorBody = {};
  const text = responseText ?? "";
  try {
    errorBody = text ? JSON.parse(text) : {};
  } catch {
    errorBody = {
      error: "invalid_response",
      error_description: text || `HTTP ${status}`,
    };
  }

  const code = errorBody.error;

  if (status >= 400 && status < 500 && code === "issuance_pending") {
    return {
      kind: "pending",
      interval: errorBody.interval,
    };
  }

  if (code === "invalid_transaction_id" || code === "expired_transaction_id") {
    return { kind: "terminal", status, errorBody };
  }

  if (status >= 400 && status < 500) {
    return { kind: "terminal", status, errorBody };
  }

  return { kind: "terminal", status, errorBody };
}

export function formatDeferredTerminalError(outcome) {
  const desc = outcome.errorBody?.error_description || outcome.errorBody?.error || "deferred poll failed";
  return `deferred_poll_terminal ${outcome.status}: ${desc}`;
}
