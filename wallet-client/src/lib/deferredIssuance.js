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
}) {
  const timeout = pollTimeoutMs ?? 30000;
  let intervalMs = resolveDeferredPollIntervalMs(issuerIntervalSeconds, pollIntervalMs);
  const start = Date.now();

  await sleep(intervalMs);

  while (Date.now() - start < timeout) {
    const poll = await buildPollRequest();
    const defRes = await httpPostJson(
      deferredEndpoint,
      poll.body,
      logSessionId,
      poll.headers,
    );
    log("deferred poll", { status: defRes.status, transactionId });

    if (defRes.status === 202) {
      const { body: pendingBody } = await parseDeferredPollResponseBody(defRes);
      intervalMs = resolveDeferredPollIntervalMs(pendingBody?.interval, intervalMs);
      await sleep(intervalMs);
      continue;
    }

    const { text: responseText, body: responseBody } = await parseDeferredPollResponseBody(defRes);

    if (defRes.status === 200) {
      return responseBody ?? {};
    }

    if (isTerminalDeferredPollError(defRes.status, responseBody)) {
      throw new Error(
        `credential_error ${defRes.status}: ${responseText || JSON.stringify(responseBody)}`,
      );
    }

    await sleep(intervalMs);
  }

  throw new Error("timeout: Deferred issuance timed out");
}
