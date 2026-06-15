export const DEFERRED_CREDENTIAL_POLL_INTERVAL_SECONDS = 5;

export function getDeferredCredentialReadyAfterPolls(env = process.env) {
  const parsed = parseInt(env.DEFERRED_CREDENTIAL_READY_AFTER_POLLS ?? "2", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 2;
}

export function getDeferredSessionAccessToken(sessionObject, flowType) {
  if (flowType === "code") {
    return sessionObject?.requests?.accessToken ?? null;
  }
  return sessionObject?.accessToken ?? null;
}

export function isDeferredCredentialDenied(sessionObject) {
  return (
    sessionObject?.status === "failed" ||
    sessionObject?.error === "credential_request_denied"
  );
}

/**
 * Advance deferred poll state for a session and return the next issuer action.
 */
export function advanceDeferredCredentialPollState(sessionObject, env = process.env) {
  if (isDeferredCredentialDenied(sessionObject)) {
    return {
      action: "denied",
      error: "credential_request_denied",
      error_description:
        sessionObject?.error_description || "Deferred credential request was denied",
    };
  }

  const attempt = Number(sessionObject?.attempt || 0) + 1;
  sessionObject.attempt = attempt;
  const readyAfter = getDeferredCredentialReadyAfterPolls(env);
  const interval =
    sessionObject?.deferredPollInterval ?? DEFERRED_CREDENTIAL_POLL_INTERVAL_SECONDS;

  if (!sessionObject.isCredentialReady && attempt < readyAfter) {
    return {
      action: "pending",
      transaction_id: sessionObject.transaction_id,
      interval,
      attempt,
    };
  }

  sessionObject.isCredentialReady = true;
  return {
    action: "ready",
    transaction_id: sessionObject.transaction_id,
    interval,
    attempt,
  };
}
