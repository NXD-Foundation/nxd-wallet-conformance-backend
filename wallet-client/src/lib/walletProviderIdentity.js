/**
 * Wallet Provider identity and attestation roles (APTITUDE RFC001):
 * - WIA (Wallet Instance Attestation): PAR and Token — `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP` only
 * - WUA (Wallet Unit Attestation): Credential — `proofs.jwt` `key_attestation` or `proofs.attestation`
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import {
  ensureOrCreateEcKeyPair,
  generateDidJwkFromPrivateJwk,
  createWiaJwt,
  createWiaPopJwt,
  createWUA,
} from "./crypto.js";
import { getOrCreateWalletInstanceId } from "./cache.js";
import { validateWiaMaterialForParOrToken } from "./wiaParTokenValidation.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_PROVIDER_KEY_PATH = path.join(__dirname, "..", "..", "data", "wallet-provider-key.json");
const DEFAULT_DATA_PATH = path.join(__dirname, "..", "..", "data", "wallet-provider.json");

/**
 * When `WALLET_USE_EXTERNAL_ATTESTATION=1`, optional pre-minted JWT strings (testing / integration).
 * Env names retain OAuth-draft labels; mapped here to WIA/WUA roles.
 */
export function readExternalAttestationTokens() {
  if (process.env.WALLET_USE_EXTERNAL_ATTESTATION !== "1") return null;
  const legacyWiaHeaderJwt = process.env.WALLET_EXTERNAL_CLIENT_ASSERTION?.trim();
  const wiaHeaderJwt =
    process.env.WALLET_EXTERNAL_OAUTH_ATTESTATION?.trim() || legacyWiaHeaderJwt;
  const wiaPopJwt = process.env.WALLET_EXTERNAL_OAUTH_POP?.trim();
  const wuaJwt = process.env.WALLET_EXTERNAL_WUA?.trim();
  if (!wiaHeaderJwt && !wiaPopJwt && !wuaJwt) return null;
  return { wiaHeaderJwt, wiaPopJwt, wuaJwt };
}

export function resolveWalletProviderIdSync(walletProviderPublicJwk) {
  const env = process.env.WALLET_PROVIDER_ID?.trim();
  if (env) return env;
  const configPath = process.env.WALLET_PROVIDER_CONFIG?.trim() || DEFAULT_DATA_PATH;
  if (fs.existsSync(configPath)) {
    try {
      const j = JSON.parse(fs.readFileSync(configPath, "utf8"));
      if (j.wallet_provider_id && typeof j.wallet_provider_id === "string") return j.wallet_provider_id.trim();
    } catch {
      // ignore
    }
  }
  return generateDidJwkFromPrivateJwk(walletProviderPublicJwk);
}

export async function ensureWalletProviderKeyPair() {
  const keyPath = process.env.WALLET_PROVIDER_KEY_PATH?.trim() || DEFAULT_PROVIDER_KEY_PATH;
  return ensureOrCreateEcKeyPair(keyPath, "ES256");
}

/**
 * RFC001 §7.3 SHOULD: fresh WIA after rejection — delete persisted WP key so the next
 * `ensureWalletProviderKeyPair` mints a new pair for WIA + PoP.
 * No-op when external WIA header env vars are set (rotation would not change outbound JWTs).
 */
export async function rotateWalletProviderKeyPair() {
  const ext = readExternalAttestationTokens();
  if (ext?.wiaHeaderJwt && ext?.wiaPopJwt) {
    return false;
  }
  const keyPath = process.env.WALLET_PROVIDER_KEY_PATH?.trim() || DEFAULT_PROVIDER_KEY_PATH;
  try {
    if (fs.existsSync(keyPath)) {
      fs.unlinkSync(keyPath);
    }
  } catch (e) {
    throw new Error(`wallet provider key rotation failed: ${e?.message || e}`);
  }
  await ensureWalletProviderKeyPair();
  return true;
}

/**
 * True when the token endpoint returned 400 `invalid_client` or `invalid_dpop_proof` and the
 * description plausibly indicates an expired or time-invalid WIA or WIA PoP JWT.
 */
export function shouldRetryTokenExchangeAfterRotatingWalletProviderKey(httpStatus, errBody) {
  const ext = readExternalAttestationTokens();
  if (ext?.wiaHeaderJwt && ext?.wiaPopJwt) return false;
  if (httpStatus !== 400) return false;
  const code = errBody?.error;
  if (code !== "invalid_client" && code !== "invalid_dpop_proof") return false;
  const d = String(errBody?.error_description || "").toLowerCase();
  const hints = [
    "wia jwt has expired",
    "wallet instance attestation",
    "wia validation",
    "invalid wallet instance attestation",
    "jwt expired",
    "jwt has expired",
    "'exp'",
    "exp claim",
    "token expired",
    "nbf",
    "not yet valid",
    "ttl (",
    "exceeds maximum",
    "outside the accepted time",
    "clock",
  ];
  return hints.some((h) => d.includes(h));
}

/**
 * Self-signed WIA + PoP for a PAR or Token endpoint audience.
 * `iss` = Wallet Provider id; `sub` = wallet instance id (Redis / file).
 */
export async function buildWiaBundleForParOrToken({
  endpointAudience,
  authorizationServerIssuer,
  wiaTtlSeconds = 3600,
  challenge = null,
}) {
  const { privateJwk, publicJwk } = await ensureWalletProviderKeyPair();
  const providerId = resolveWalletProviderIdSync(publicJwk);
  const instanceId = await getOrCreateWalletInstanceId();
  const wiaJwt = await createWiaJwt({
    privateJwk,
    publicJwk,
    issuer: providerId,
    subject: instanceId,
    audience: endpointAudience,
    cnfJwk: publicJwk,
    ttlSeconds: wiaTtlSeconds,
  });
  // PoP `iss` MUST equal WIA `sub` (wallet instance id), not the Wallet Provider id.
  const wiaPopJwt = await createWiaPopJwt({
    privateJwk,
    publicJwk,
    issuer: instanceId,
    audience: authorizationServerIssuer,
    challenge,
  });
  return {
    walletProviderId: providerId,
    walletInstanceId: instanceId,
    wiaJwt,
    wiaPopJwt,
    wiaHeaders: {
      "OAuth-Client-Attestation": wiaJwt,
      "OAuth-Client-Attestation-PoP": wiaPopJwt,
    },
  };
}

/**
 * Single RFC001 path for PAR/Token client authentication: WIA header + PoP for `WIA.cnf`.
 * Validates audiences and `client_id` locally before returning headers.
 *
 * @param {string} [clientId] - OAuth `client_id` when present; MUST equal WIA `sub` when set.
 */
export async function resolveWiaForParOrToken({
  endpointAudience,
  authorizationServerIssuer,
  wiaTtlSeconds = 3600,
  clientId,
  challenge = null,
}) {
  const ext = readExternalAttestationTokens();
  let wiaJwt;
  let wiaPopJwt;
  let walletProviderId;
  let walletInstanceId;

  if (ext?.wiaHeaderJwt && ext.wiaPopJwt) {
    if (challenge != null && String(challenge).trim() !== "") {
      throw new Error(
        "attestation challenge retry is not supported with WALLET_USE_EXTERNAL_ATTESTATION; " +
          "external OAuth-Client-Attestation-PoP JWTs cannot be rebound to a new challenge",
      );
    }
    wiaJwt = ext.wiaHeaderJwt;
    wiaPopJwt = ext.wiaPopJwt;
  } else {
    const bundle = await buildWiaBundleForParOrToken({
      endpointAudience,
      authorizationServerIssuer,
      wiaTtlSeconds,
      challenge,
    });
    wiaJwt = bundle.wiaJwt;
    wiaPopJwt = bundle.wiaPopJwt;
    walletProviderId = bundle.walletProviderId;
    walletInstanceId = bundle.walletInstanceId;
  }

  const effectiveClientId =
    clientId != null && clientId !== ""
      ? clientId
      : walletInstanceId ?? (await getOrCreateWalletInstanceId());

  const validated = await validateWiaMaterialForParOrToken({
    wiaJwt,
    wiaPopJwt,
    endpointAudience,
    authorizationServerIssuer,
    clientId: effectiveClientId,
  });

  return {
    walletProviderId: walletProviderId ?? validated.walletProviderId,
    walletInstanceId: validated.walletInstanceId,
    wiaJwt,
    wiaPopJwt,
    wiaHeaders: {
      "OAuth-Client-Attestation": wiaJwt,
      "OAuth-Client-Attestation-PoP": wiaPopJwt,
    },
  };
}

/**
 * WUA for Credential binding: `proofs.jwt` `key_attestation` or `proofs.attestation`.
 * Signed by Wallet Provider key; `iss` = provider; `attested_keys` = ordered proof/holder public JWKs.
 */
export async function buildWalletUnitAttestationJwt({
  credentialEndpoint,
  proofPublicJwk,
  proofPublicJwks,
  eudiWalletInfo,
  c_nonce = null,
}) {
  const ext = readExternalAttestationTokens();
  if (ext?.wuaJwt) return ext.wuaJwt;

  const keys = proofPublicJwks ?? (proofPublicJwk ? [proofPublicJwk] : []);
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new Error("buildWalletUnitAttestationJwt: proofPublicJwk or proofPublicJwks required");
  }
  if (keys.length > 32) {
    throw new Error("buildWalletUnitAttestationJwt: at most 32 attested_keys supported");
  }

  const { privateJwk, publicJwk } = await ensureWalletProviderKeyPair();
  const providerId = resolveWalletProviderIdSync(publicJwk);
  const instanceId = await getOrCreateWalletInstanceId();
  return createWUA({
    privateJwk,
    publicJwk,
    issuer: providerId,
    subject: instanceId,
    audience: credentialEndpoint,
    attestedKeys: keys,
    eudiWalletInfo,
    alg: "ES256",
    ttlHours: 24,
    ...(typeof c_nonce === "string" && c_nonce.length > 0 ? { nonce: c_nonce } : {}),
  });
}
