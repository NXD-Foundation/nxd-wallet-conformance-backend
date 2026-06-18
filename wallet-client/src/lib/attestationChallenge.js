/**
 * OAuth attestation challenge handling per draft-ietf-oauth-attestation-based-client-auth-07
 * sections 6.2, 8, and 8.1.
 */

import fetch from "node-fetch";

export const ATTESTATION_CHALLENGE_HEADER = "OAuth-Client-Attestation-Challenge";
export const USE_ATTESTATION_CHALLENGE_ERROR = "use_attestation_challenge";

export class AttestationChallengeError extends Error {
  constructor(message, errorCode = "attestation_challenge_error") {
    super(message);
    this.name = "AttestationChallengeError";
    this.errorCode = errorCode;
  }
}

/**
 * Case-insensitive extraction of OAuth-Client-Attestation-Challenge from response headers.
 * @param {Headers|Record<string, string>|null|undefined} headers
 * @returns {string|null}
 */
export function extractAttestationChallenge(headers) {
  if (!headers) {
    return null;
  }

  if (typeof headers.get === "function") {
    const direct = headers.get(ATTESTATION_CHALLENGE_HEADER);
    if (typeof direct === "string" && direct.length > 0) {
      return direct;
    }
    for (const [name, value] of headers.entries()) {
      if (name.toLowerCase() === ATTESTATION_CHALLENGE_HEADER.toLowerCase()) {
        return typeof value === "string" && value.length > 0 ? value : null;
      }
    }
    return null;
  }

  if (typeof headers === "object") {
    for (const [name, value] of Object.entries(headers)) {
      if (name.toLowerCase() === ATTESTATION_CHALLENGE_HEADER.toLowerCase()) {
        return typeof value === "string" && value.length > 0 ? value : null;
      }
    }
  }

  return null;
}

/**
 * Mutable challenge state for an issuance session.
 * @param {string|null} [initialChallenge]
 */
export function createAttestationChallengeState(initialChallenge = null) {
  let currentChallenge =
    typeof initialChallenge === "string" && initialChallenge.length > 0
      ? initialChallenge
      : null;

  return {
    get current() {
      return currentChallenge;
    },
    set(challenge) {
      if (typeof challenge === "string" && challenge.length > 0) {
        currentChallenge = challenge;
      }
    },
    consume() {
      return currentChallenge;
    },
    updateFromResponse(headers) {
      const next = extractAttestationChallenge(headers);
      if (next) {
        currentChallenge = next;
      }
      return next;
    },
  };
}

/**
 * POST to challenge_endpoint and return attestation_challenge.
 * @param {string} challengeEndpoint
 * @param {{ logSessionId?: string, fetchImpl?: typeof fetch }} [options]
 * @returns {Promise<string>}
 */
export async function fetchAttestationChallenge(challengeEndpoint, options = {}) {
  if (typeof challengeEndpoint !== "string" || challengeEndpoint.length === 0) {
    throw new AttestationChallengeError(
      "challenge_endpoint must be a non-empty string URL",
      "invalid_challenge_endpoint",
    );
  }

  const fetchImpl = options.fetchImpl || fetch;
  const res = await fetchImpl(challengeEndpoint, {
    method: "POST",
    headers: { Accept: "application/json" },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new AttestationChallengeError(
      `challenge_endpoint request failed with status ${res.status}: ${text}`,
      "challenge_endpoint_error",
    );
  }

  let body;
  try {
    body = await res.json();
  } catch (e) {
    throw new AttestationChallengeError(
      `challenge_endpoint returned invalid JSON: ${e?.message || String(e)}`,
      "invalid_challenge_response",
    );
  }

  const challenge = body?.attestation_challenge;
  if (typeof challenge !== "string" || challenge.length === 0) {
    throw new AttestationChallengeError(
      "challenge_endpoint response must include a non-empty attestation_challenge string",
      "missing_attestation_challenge",
    );
  }

  return challenge;
}

/**
 * Parse OAuth error body and detect use_attestation_challenge.
 * @param {string} responseText
 * @returns {{ error: string|null, errorDescription: string|null, isUseAttestationChallenge: boolean }}
 */
export function parseAttestationOAuthError(responseText) {
  let parsed = {};
  try {
    parsed = responseText ? JSON.parse(responseText) : {};
  } catch {
    parsed = {};
  }
  const error = typeof parsed.error === "string" ? parsed.error : null;
  return {
    error,
    errorDescription: typeof parsed.error_description === "string" ? parsed.error_description : null,
    isUseAttestationChallenge: error === USE_ATTESTATION_CHALLENGE_ERROR,
  };
}

/**
 * Whether a failed attestation-backed request should be retried with a fresh challenge.
 * @param {Response} response
 * @param {string} responseText
 * @returns {{ shouldRetry: boolean, challenge: string|null }}
 */
export function shouldRetryWithAttestationChallenge(response, responseText) {
  if (response?.ok) {
    return { shouldRetry: false, challenge: null };
  }
  const { isUseAttestationChallenge } = parseAttestationOAuthError(responseText);
  const challenge = extractAttestationChallenge(response?.headers);
  return {
    shouldRetry: isUseAttestationChallenge && !!challenge,
    challenge,
  };
}
