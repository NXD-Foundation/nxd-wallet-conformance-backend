/**
 * OpenID4VCI 1.0 Appendix F.1 jwt proof `iss` claim.
 *
 * - OPTIONAL for authenticated clients; if present MUST be the OAuth client_id.
 * - MUST be omitted when the access token came from pre-authorized_code
 *   through anonymous token access (no client_id / no client authentication).
 */

export const OPENID4VCI_PROOF_ISS_SPEC_REF =
  "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type";

const PRE_AUTHORIZED_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

function nonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

export function resolveTokenClientBinding({
  grantType,
  bodyClientId = null,
  attestationResult = null,
} = {}) {
  const bodyId = nonEmptyString(bodyClientId);
  const attestationSub =
    attestationResult?.ok === true ? nonEmptyString(attestationResult.attestationPayload?.sub) : null;
  const tokenClientId = bodyId || attestationSub || null;
  const anonymousAccess = grantType === PRE_AUTHORIZED_GRANT_TYPE && !tokenClientId;
  return { tokenClientId, anonymousAccess };
}

export function applyTokenClientBindingToSession(session, binding) {
  if (!session || !binding) {
    return session;
  }
  session.tokenClientId = binding.tokenClientId || null;
  session.preAuthorizedAnonymousAccess = binding.anonymousAccess === true;
  return session;
}

export function getProofIssBindingFromSession(sessionObject = null) {
  return {
    tokenClientId: nonEmptyString(sessionObject?.tokenClientId),
    anonymousAccess: sessionObject?.preAuthorizedAnonymousAccess === true,
  };
}

function proofIssError(message) {
  const error = new Error(`${message} See ${OPENID4VCI_PROOF_ISS_SPEC_REF}`);
  error.proofValidationError = true;
  error.errorCode = "invalid_proof";
  return error;
}

/**
 * Validate a credential-request proof JWT `iss` against the token-time client.
 * When the session has no recorded client binding, the claim is not compared
 * (legacy /credential tests that do not go through /token).
 */
export function assertOpenid4VciProofIssClaim({
  iss,
  tokenClientId = null,
  anonymousAccess = false,
} = {}) {
  const presentIss = nonEmptyString(iss);

  if (anonymousAccess) {
    if (presentIss) {
      throw proofIssError(
        "Proof JWT iss must be omitted for anonymous pre-authorized access to the token endpoint.",
      );
    }
    return;
  }

  if (!presentIss) {
    return;
  }

  const expectedClientId = nonEmptyString(tokenClientId);
  if (!expectedClientId) {
    return;
  }

  if (presentIss !== expectedClientId) {
    throw proofIssError(
      `Issuer claim must be the client_id of the request: ${expectedClientId}`,
    );
  }
}
