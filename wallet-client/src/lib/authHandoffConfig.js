import { OPENID4VP_CS02_URI } from "./openid4vpUri.js";
import { resolveWalletProviderUrl } from "./wuaStatusList.js";

export class AuthHandoffConfigError extends Error {
  constructor(message, errorCode = "invalid_configuration") {
    super(message);
    this.name = "AuthHandoffConfigError";
    this.errorCode = errorCode;
  }
}

export function isAuthHandoffEnabled(env = process.env, body = {}) {
  if (body?.authHandoff === true) return true;
  if (body?.authHandoff === false) return false;
  const raw = String(env.WALLET_AUTH_HANDOFF || "").trim().toLowerCase();
  return raw === "true" || raw === "1";
}

function validateHttpsRedirectUri(uri) {
  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    throw new AuthHandoffConfigError(
      `OAuth redirect URI must be an absolute HTTPS URL (got ${JSON.stringify(uri)})`,
    );
  }
  if (parsed.protocol !== "https:") {
    throw new AuthHandoffConfigError(
      "OAuth redirect URI must use HTTPS for ITB auth handoff",
    );
  }
}

export function resolveOAuthRedirectUri(env = process.env) {
  const explicit = String(env.WALLET_OAUTH_REDIRECT_URI || "").trim();
  if (explicit) {
    validateHttpsRedirectUri(explicit);
    return explicit;
  }
  const provider = resolveWalletProviderUrl(env);
  if (provider) {
    const uri = `${provider.replace(/\/$/, "")}/oauth/callback`;
    validateHttpsRedirectUri(uri);
    return uri;
  }
  throw new AuthHandoffConfigError(
    "WALLET_OAUTH_REDIRECT_URI or WALLET_PROVIDER_URL (HTTPS) is required for auth handoff",
  );
}

export function resolveRedirectUriForFlow(env = process.env, authHandoff = false) {
  if (authHandoff) {
    return resolveOAuthRedirectUri(env);
  }
  return OPENID4VP_CS02_URI;
}

export function resolveAuthHandoffTtlSeconds(env = process.env, parExpiresIn = null) {
  const parsedDefault = parseInt(env.WALLET_AUTH_HANDOFF_TTL || "600", 10);
  const defaultTtl = Number.isFinite(parsedDefault) && parsedDefault > 0 ? parsedDefault : 600;
  if (parExpiresIn != null && Number.isFinite(Number(parExpiresIn)) && Number(parExpiresIn) > 0) {
    return Math.min(defaultTtl, Number(parExpiresIn));
  }
  return defaultTtl;
}

export const AUTH_HANDOFF_STATUS = "AUTHORIZATION_REQUIRED";
