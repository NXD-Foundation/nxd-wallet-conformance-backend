import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import {
  ensureOrCreateEcKeyPair,
  generateDidJwkFromPrivateJwk,
  createOAuthClientAttestationJwt,
  createOAuthClientAttestationPopJwt,
  createWUA,
} from "./crypto.js";
import { getOrCreateWalletInstanceId } from "./cache.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_PROVIDER_KEY_PATH = path.join(__dirname, "..", "..", "data", "wallet-provider-key.json");
const DEFAULT_DATA_PATH = path.join(__dirname, "..", "..", "data", "wallet-provider.json");

/**
 * When `WALLET_USE_EXTERNAL_ATTESTATION=1`, optional pre-minted JWT strings (testing / integration).
 * If all three are set, self-signing is skipped for that exchange.
 */
export function readExternalAttestationTokens() {
  if (process.env.WALLET_USE_EXTERNAL_ATTESTATION !== "1") return null;
  const clientAssertion = process.env.WALLET_EXTERNAL_CLIENT_ASSERTION?.trim();
  const oauthAtt = process.env.WALLET_EXTERNAL_OAUTH_ATTESTATION?.trim();
  const oauthPop = process.env.WALLET_EXTERNAL_OAUTH_POP?.trim();
  const wua = process.env.WALLET_EXTERNAL_WUA?.trim();
  if (!clientAssertion && !oauthAtt && !oauthPop && !wua) return null;
  return { clientAssertion, oauthAtt, oauthPop, wua };
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
 * RFC001 §7.3 SHOULD: fresh attestation after rejection — delete persisted WP key so the next
 * `ensureWalletProviderKeyPair` mints a new pair for OAuth client attestation + WIA `client_assertion`.
 * No-op when external attestation env is used (rotation would not change outbound JWTs).
 */
export async function rotateWalletProviderKeyPair() {
  const ext = readExternalAttestationTokens();
  if (ext?.clientAssertion && ext?.oauthAtt && ext?.oauthPop) {
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
 * description plausibly indicates an expired or time-invalid WIA / client attestation JWT.
 */
export function shouldRetryTokenExchangeAfterRotatingWalletProviderKey(httpStatus, errBody) {
  const ext = readExternalAttestationTokens();
  if (ext?.clientAssertion && ext?.oauthAtt && ext?.oauthPop) return false;
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
 * OAuth Client Attestation JWT + PoP for a given endpoint audience (token, PAR, etc.).
 * `iss` = Wallet Provider id; `sub` = wallet instance id (Redis / file).
 */
export async function buildWalletOAuthClientAttestationBundle({
  endpointAudience,
  authorizationServerIssuer,
  clientAssertionTtlSeconds = 3600,
}) {
  const { privateJwk, publicJwk } = await ensureWalletProviderKeyPair();
  const providerId = resolveWalletProviderIdSync(publicJwk);
  const instanceId = await getOrCreateWalletInstanceId();
  const oauthAttestationJwt = await createOAuthClientAttestationJwt({
    privateJwk,
    publicJwk,
    issuer: providerId,
    subject: instanceId,
    audience: endpointAudience,
    cnfJwk: publicJwk,
    ttlSeconds: clientAssertionTtlSeconds,
  });
  const oauthPopJwt = await createOAuthClientAttestationPopJwt({
    privateJwk,
    publicJwk,
    issuer: providerId,
    audience: authorizationServerIssuer,
  });
  return {
    walletProviderId: providerId,
    walletInstanceId: instanceId,
    oauthAttestationJwt,
    oauthPopJwt,
    clientAssertionJwt: oauthAttestationJwt,
  };
}

/**
 * Resolves `client_assertion` (jwt-bearer) + OAuth-Client-Attestation headers for token/PAR.
 * External tokens win when all three JWT env vars are set; otherwise self-signed wallet-provider material.
 */
export async function resolveAttestationForEndpoint({
  endpointAudience,
  authorizationServerIssuer,
  clientAssertionTtlSeconds = 3600,
}) {
  const ext = readExternalAttestationTokens();
  if (ext?.clientAssertion && ext.oauthAtt && ext.oauthPop) {
    return {
      clientAssertionJwt: ext.clientAssertion,
      oauthHeaders: {
        "OAuth-Client-Attestation": ext.oauthAtt,
        "OAuth-Client-Attestation-PoP": ext.oauthPop,
      },
    };
  }
  const bundle = await buildWalletOAuthClientAttestationBundle({
    endpointAudience,
    authorizationServerIssuer,
    clientAssertionTtlSeconds,
  });
  return {
    clientAssertionJwt: ext?.clientAssertion || bundle.clientAssertionJwt,
    oauthHeaders:
      ext?.oauthAtt && ext?.oauthPop
        ? {
            "OAuth-Client-Attestation": ext.oauthAtt,
            "OAuth-Client-Attestation-PoP": ext.oauthPop,
          }
        : {
            "OAuth-Client-Attestation": bundle.oauthAttestationJwt,
            "OAuth-Client-Attestation-PoP": bundle.oauthPopJwt,
          },
  };
}

/**
 * WUA for proof JWT header or `proofs.attestation`: signed by Wallet Provider key; `iss` = provider;
 * `attested_keys` = one or more proof/holder public JWKs.
 */
export async function buildWalletUnitAttestationJwt({ credentialEndpoint, proofPublicJwk, proofPublicJwks, eudiWalletInfo }) {
  const ext = readExternalAttestationTokens();
  if (ext?.wua) return ext.wua;

  const keys = proofPublicJwks ?? (proofPublicJwk ? [proofPublicJwk] : []);
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new Error("buildWalletUnitAttestationJwt: proofPublicJwk or proofPublicJwks required");
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
  });
}
