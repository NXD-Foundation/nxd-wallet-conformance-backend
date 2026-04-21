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
