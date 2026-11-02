import { encryptDeferredRequest, parseCredentialResponsePayload } from "./credentialResponseEncryption.js";
import { requestWithDpopNonce } from "./dpopNonce.js";
import { computeAthForDpop } from "../../utils/tokenUtils.js";
export function resolveDeferredPollIntervalMs(issuerIntervalSeconds, pollIntervalMs) {
  if (Number.isFinite(issuerIntervalSeconds) && issuerIntervalSeconds > 0) {
    return issuerIntervalSeconds * 1000;
  }
  if (Number.isFinite(pollIntervalMs) && pollIntervalMs > 0) {
    return pollIntervalMs;
  }
  return 2000;
}

export function isTerminalDeferredPollError(status, errorBody) {
  if (status === 401) {
    return true;
  }
  if (status !== 400) {
    return false;
  }
  const code = errorBody?.error;
  return code === "invalid_transaction_id" || code === "credential_request_denied";
}

export async function parseDeferredPollResponseBody(response) {
  const text = await response.text().catch(() => "");
  if (!text) {
    return { text, body: null };
  }
  try {
    return { text, body: JSON.parse(text) };
  } catch {
    return { text, body: null };
  }
}

/**
 * Poll /credential_deferred until the credential is ready or a terminal error occurs.
 */
export async function pollDeferredCredentialIssuance({
  transactionId,
  issuerIntervalSeconds,
  pollTimeoutMs,
  pollIntervalMs,
  deferredEndpoint,
  buildPollRequest,
  httpPostJson,
  logSessionId,
  sleep,
  log = () => {},
  issuerMeta,
  encryptionContext,
}) {
  const timeout = pollTimeoutMs ?? 30000;
  let intervalMs = resolveDeferredPollIntervalMs(issuerIntervalSeconds, pollIntervalMs);
  const start = Date.now();

  await sleep(intervalMs);

  while (Date.now() - start < timeout) {
    const poll = await buildPollRequest();
    const body = encryptionContext
      ? await encryptDeferredRequest({ ...poll.body, credential_response_encryption: encryptionContext.credential_response_encryption }, issuerMeta)
      : poll.body;
    const defRes = await requestWithDpopNonce({
      url: deferredEndpoint, state: poll.dpopBinding?.nonceState,
      privateJwk: poll.dpopBinding?.privateJwk, publicJwk: poll.dpopBinding?.publicJwk,
      enabled: Boolean(poll.headers?.DPoP),
      ath: poll.accessToken ? computeAthForDpop(poll.accessToken) : null,
      send: (proof) => httpPostJson(deferredEndpoint, body, logSessionId,
        { ...poll.headers, ...(encryptionContext ? { "content-type": "application/jwt" } : {}), ...(proof ? { DPoP: proof } : {}) }),
      log,
    });
    log("deferred poll", { status: defRes.status, transactionId });

    const responseText = await defRes.text().catch(() => "");
    if (defRes.status === 202 || defRes.status === 200) {
      const responseBody = await parseCredentialResponsePayload(responseText, defRes.headers.get("content-type"), encryptionContext?.privateKey);
      if (!responseBody || typeof responseBody !== "object") throw new Error("Invalid deferred response");
      if (defRes.status === 200) return responseBody;
      if (responseBody.transaction_id !== transactionId) throw new Error("Invalid deferred transaction_id");
      intervalMs = resolveDeferredPollIntervalMs(responseBody.interval, intervalMs);
      await sleep(intervalMs);
      continue;
    }
    throw new Error(`credential_error ${defRes.status}: ${responseText}`);

  }

  throw new Error("timeout: Deferred issuance timed out");
}
