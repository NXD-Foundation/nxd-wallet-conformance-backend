import {
  registerIssuanceRefreshToken,
  revokeIssuanceRefreshToken,
  lookupIssuanceRefreshToken,
  issuanceRefreshTokenTtlSeconds,
  rotateIssuanceRefreshToken,
  storePreAuthSession,
  storeCodeFlowSession,
  getPreAuthSession,
  getCodeFlowSession,
} from "../services/cacheServiceRedis.js";
import { buildAccessToken, generateRefreshToken } from "./tokenUtils.js";
import { generateNonce } from "./cryptoUtils.js";
import jwt from "jsonwebtoken";

function bindingError(message, errorCode = "invalid_grant") {
  const error = new Error(message);
  error.errorCode = errorCode;
  return error;
}

const PRE_AUTHORIZED_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

/** Which Redis namespace and pre-auth key a token request must update. */
export function resolveTokenSessionPersistence({ grantType, preAuthorizedCode, refreshMapping }) {
  const refreshFlow = grantType === "refresh_token" ? refreshMapping?.flowType : null;
  const usePreAuth =
    grantType === PRE_AUTHORIZED_GRANT_TYPE ||
    (grantType === "refresh_token" && Boolean(refreshFlow) && refreshFlow !== "code");
  return {
    namespace: usePreAuth ? "pre-auth" : "code",
    preAuthSessionKey: usePreAuth
      ? (grantType === "refresh_token" ? refreshMapping?.sessionKey : preAuthorizedCode) || null
      : null,
  };
}

export function mapIssuanceTokenError(error) {
  if (error?.errorCode === "stale_issuance_session") {
    return { status: 400, body: { error: "invalid_grant", error_description: error.message } };
  }
  if (error?.errorCode === "invalid_client") {
    return {
      status: 401,
      body: {
        error: "invalid_client",
        error_description: error.message,
      },
    };
  }
  return null;
}

/** Bind the token to the authorized selection, not the primary item of a multi-item offer. */
export function resolveIssuanceCredentialConfigurationIds(session, authorizationDetails = null) {
  const available = [...new Set([
    ...(session?.authorizedCredentialConfigurationIds || session?.requestedCredentialConfigurationIds || []),
    ...(!session?.authorizedCredentialConfigurationIds && session?.credentialConfigurationId ? [session.credentialConfigurationId] : []),
  ])];
  const selected = [...new Set((authorizationDetails || []).map(entry => entry.credential_configuration_id).filter(Boolean))];
  if (available.length && selected.some(id => !available.includes(id))) {
    throw bindingError("Requested credential configuration is outside the issuance authorization");
  }
  return selected.length ? selected : available;
}

export async function commitRefreshTokenRotation({
  refreshTokenValue,
  newRefreshToken,
  session,
  mapping,
  boundClientId,
  rotate = rotateIssuanceRefreshToken,
}) {
  const previousBinding = session.refreshBinding;
  session.refreshBinding = {
    ...previousBinding,
    token: newRefreshToken,
    clientId: boundClientId,
    expiresAt: Date.now() + issuanceRefreshTokenTtlSeconds() * 1000,
  };
  try {
    const committed = await rotate({
      oldToken: refreshTokenValue,
      newToken: newRefreshToken,
      session,
      mapping: { ...mapping, clientId: boundClientId },
    });
    if (!committed) throw bindingError("Refresh token is expired or already rotated");
  } catch (error) {
    session.refreshBinding = previousBinding;
    throw error;
  }
}

export async function persistRefreshBindingForIssuance({
  session,
  sessionKey,
  flowType,
  refreshToken,
  dpopCnf,
  tokenClientBinding,
  commitSession = null,
  credentialConfigurationIds = resolveIssuanceCredentialConfigurationIds(session),
}) {
  const store = commitSession || (() => flowType === "code"
    ? storeCodeFlowSession(sessionKey, session)
    : storePreAuthSession(sessionKey, session));
  const dpopJkt = dpopCnf?.jkt;
  const clientId =
    tokenClientBinding?.tokenClientId ||
    session?.tokenClientId ||
    session?.walletAttestation?.clientId ||
    null;
  if (!refreshToken || !dpopJkt || !clientId || !sessionKey) {
    await store();
    return;
  }
  session.refreshBinding = { token: refreshToken, dpopJkt, clientId,
    expiresAt: Date.now() + issuanceRefreshTokenTtlSeconds() * 1000,
    credentialConfigurationIds,
  };
  const registered = await registerIssuanceRefreshToken(refreshToken, {
    sessionKey,
    flowType,
    dpopJkt,
    clientId,
  });
  if (!registered) throw bindingError("Failed to persist refresh token", "server_error");
  try {
    await store();
  } catch (error) {
    await revokeIssuanceRefreshToken(refreshToken);
    throw error;
  }
}

export async function handleRefreshTokenGrant({
  refreshTokenValue,
  dpopCnf,
  tokenClientBinding,
  serverUrl,
  signingPrivateKey,
  validatedSession = null,
}) {
  const mapping = await lookupIssuanceRefreshToken(refreshTokenValue);
  if (!mapping) {
    throw bindingError("Unknown or expired refresh token");
  }
  const session = validatedSession || (
    mapping.flowType === "code"
      ? await getCodeFlowSession(mapping.sessionKey)
      : await getPreAuthSession(mapping.sessionKey));
  if (!session?.refreshBinding || session.refreshBinding.token !== refreshTokenValue ||
      (Number.isFinite(session.refreshBinding.expiresAt) && session.refreshBinding.expiresAt <= Date.now())) {
    throw bindingError("Refresh token is invalid, expired, or already rotated");
  }
  if (!dpopCnf?.jkt) {
    throw bindingError("DPoP proof is required for refresh token grant", "invalid_dpop_proof");
  }
  if (dpopCnf.jkt !== session.refreshBinding.dpopJkt) {
    throw bindingError("Refresh token DPoP key does not match the bound session key", "invalid_dpop_proof");
  }
  const boundClientId = session.refreshBinding.clientId;
  if (!boundClientId || tokenClientBinding?.tokenClientId !== boundClientId) {
    throw bindingError("Refresh token client identity does not match the original issuance session", "invalid_client");
  }

  const generatedAccessToken = buildAccessToken(serverUrl, signingPrivateKey, dpopCnf);
  const cNonceForSession = generateNonce();
  const newRefreshToken = generateRefreshToken();

  if (mapping.flowType === "code") {
    session.requests = session.requests || {};
    session.requests.accessToken = generatedAccessToken;
  } else {
    session.accessToken = generatedAccessToken;
  }
  session.c_nonce = cNonceForSession;
  session.accessTokenExpiresAt = jwt.decode(generatedAccessToken).exp * 1000;

  await commitRefreshTokenRotation({
    refreshTokenValue,
    newRefreshToken,
    session,
    mapping,
    boundClientId,
  });

  return {
    access_token: generatedAccessToken,
    refresh_token: newRefreshToken,
    token_type: "DPoP",
    expires_in: jwt.decode(generatedAccessToken).exp - jwt.decode(generatedAccessToken).iat,
    c_nonce: cNonceForSession,
    c_nonce_expires_in: 86400,
  };
}
