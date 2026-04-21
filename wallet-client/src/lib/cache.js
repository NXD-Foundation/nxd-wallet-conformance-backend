import redis from "redis";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "node:crypto";

// Wallet-client dedicated Redis connection
// Configure via WALLET_REDIS env var (host:port) or default localhost:6379
const redisUrl = process.env.WALLET_REDIS ? process.env.WALLET_REDIS : "localhost:6379";

export const walletRedisClient = redis.createClient({ url: `redis://${redisUrl}` });

let redisConnectPromise = null;

/** Connect on first cache use so importing this module (e.g. in tests) does not hold Redis open. */
export async function ensureWalletRedisConnected() {
  if (walletRedisClient.isOpen) return;
  if (!redisConnectPromise) {
    redisConnectPromise = (async () => {
      try {
        await walletRedisClient.connect();
        console.log("Wallet client connected to Redis");
      } catch (err) {
        console.error("Wallet Redis connection error:", err);
        redisConnectPromise = null;
      }
    })();
  }
  await redisConnectPromise;
}

walletRedisClient.on("error", (err) => {
  console.error("Wallet Redis Client Error:", err);
});

walletRedisClient.on("ready", () => {
  console.log("Wallet Redis Client Ready");
});

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_INSTANCE_FILE = path.join(__dirname, "..", "..", "walletprovider", "instance-id.txt");
const WALLET_INSTANCE_REDIS_KEY = "wallet:instance_id";

/**
 * Stable wallet instance id (RFC001 `sub` for WIA-style assertions). Override with WALLET_INSTANCE_ID.
 * Prefers Redis; falls back to a local file if Redis is unavailable.
 */
export async function getOrCreateWalletInstanceId() {
  const envId = process.env.WALLET_INSTANCE_ID?.trim();
  if (envId) return envId;

  await ensureWalletRedisConnected();
  try {
    const existing = await walletRedisClient.get(WALLET_INSTANCE_REDIS_KEY);
    if (existing) return existing;
    const id = crypto.randomUUID();
    await walletRedisClient.set(WALLET_INSTANCE_REDIS_KEY, id);
    return id;
  } catch {
    return getOrCreateWalletInstanceIdFromFile();
  }
}

function getOrCreateWalletInstanceIdFromFile() {
  const filePath = process.env.WALLET_INSTANCE_ID_FILE?.trim() || DEFAULT_INSTANCE_FILE;
  try {
    if (fs.existsSync(filePath)) {
      const v = fs.readFileSync(filePath, "utf8").trim();
      if (v) return v;
    }
    const id = crypto.randomUUID();
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, id, "utf8");
    return id;
  } catch (e) {
    console.error("[wallet-instance] failed to persist instance id:", e?.message || e);
    return crypto.randomUUID();
  }
}

// Store credential and key-binding material under credential type (configurationId)
export async function storeWalletCredentialByType(configurationId, payload) {
  await ensureWalletRedisConnected();
  const key = `wallet:credentials:${configurationId}`;
  const ttlInSeconds = parseInt(process.env.WALLET_CREDENTIAL_TTL || "86400");
  await walletRedisClient.setEx(key, ttlInSeconds, JSON.stringify(payload));
}

export async function getWalletCredentialByType(configurationId) {
  await ensureWalletRedisConnected();
  const key = `wallet:credentials:${configurationId}`;
  const val = await walletRedisClient.get(key);
  return val ? JSON.parse(val) : null;
}

export async function listWalletCredentialTypes() {
  await ensureWalletRedisConnected();
  const keys = await walletRedisClient.keys("wallet:credentials:*");
  return keys.map((k) => k.replace(/^wallet:credentials:/, ""));
}

// Store logs under a specific sessionId key
export async function storeWalletLogs(sessionId, logs) {
  await ensureWalletRedisConnected();
  const key = `wallet:logs:${sessionId}`;
  const ttlInSeconds = parseInt(process.env.WALLET_LOGS_TTL || "3600"); // Default 1 hour
  
  // Clear existing list and add all logs
  await walletRedisClient.del(key);
  if (logs && logs.length > 0) {
    const logStrings = logs.map(log => JSON.stringify(log));
    await walletRedisClient.rPush(key, ...logStrings);
    await walletRedisClient.expire(key, ttlInSeconds);
  }
}

export async function getWalletLogs(sessionId) {
  await ensureWalletRedisConnected();
  const key = `wallet:logs:${sessionId}`;
  
  try {
    // Try to get as Redis list first
    const listLength = await walletRedisClient.lLen(key);
    if (listLength > 0) {
      const logEntries = await walletRedisClient.lRange(key, 0, -1);
      return logEntries.map(entry => JSON.parse(entry));
    }
    return null;
  } catch (error) {
    // If it's a WRONGTYPE error, the key contains old JSON format
    if (error.message && error.message.includes('WRONGTYPE')) {
      try {
        // Get the old JSON data
        const val = await walletRedisClient.get(key);
        if (val) {
          const oldLogs = JSON.parse(val);
          // Migrate to list format
          await walletRedisClient.del(key);
          if (oldLogs && oldLogs.length > 0) {
            const logStrings = oldLogs.map(log => JSON.stringify(log));
            await walletRedisClient.rPush(key, ...logStrings);
            const ttlInSeconds = parseInt(process.env.WALLET_LOGS_TTL || "3600");
            await walletRedisClient.expire(key, ttlInSeconds);
          }
          return oldLogs;
        }
      } catch (migrationError) {
        console.error("[cache] Failed to migrate logs:", migrationError);
        return null;
      }
    }
    console.error("[cache] Error getting logs:", error);
    return null;
  }
}

export async function appendWalletLog(sessionId, logEntry) {
  await ensureWalletRedisConnected();
  const key = `wallet:logs:${sessionId}`;
  const entryWithTimestamp = {
    ...logEntry,
    timestamp: new Date().toISOString()
  };
  
  try {
    // Use Redis list for atomic append operations
    await walletRedisClient.rPush(key, JSON.stringify(entryWithTimestamp));
    
    // Set TTL if this is the first entry
    const ttlInSeconds = parseInt(process.env.WALLET_LOGS_TTL || "3600");
    await walletRedisClient.expire(key, ttlInSeconds);
  } catch (error) {
    // If it's a WRONGTYPE error, migrate the old data first
    if (error.message && error.message.includes('WRONGTYPE')) {
      try {
        // Get the old JSON data and migrate
        const val = await walletRedisClient.get(key);
        await walletRedisClient.del(key);
        
        if (val) {
          const oldLogs = JSON.parse(val);
          if (oldLogs && oldLogs.length > 0) {
            const logStrings = oldLogs.map(log => JSON.stringify(log));
            await walletRedisClient.rPush(key, ...logStrings);
          }
        }
        
        // Now append the new entry
        await walletRedisClient.rPush(key, JSON.stringify(entryWithTimestamp));
        const ttlInSeconds = parseInt(process.env.WALLET_LOGS_TTL || "3600");
        await walletRedisClient.expire(key, ttlInSeconds);
      } catch (migrationError) {
        console.error("[cache] Failed to migrate logs during append:", migrationError);
      }
    } else {
      console.error("[cache] Error appending log:", error);
    }
  }
}

const walletPresentationSessionKey = (sessionId) =>
  `wallet:presentation_session:${sessionId}`;

/**
 * RFC002 / OpenID4VP presentation context for wallet session correlation (P1-W-11).
 * @param {Record<string, unknown>} payload - Verified (or best-effort decoded) authorization request JWT payload
 * @param {string | null | undefined} deepLinkClientId - `client_id` from the openid4vp deep link
 */
export function buildWalletPresentationSessionRecord(payload, deepLinkClientId) {
  if (!payload || typeof payload !== "object") return null;
  let responseMode = payload.response_mode || "direct_post";
  const responseUri = payload.response_uri;
  if (responseUri && /direct_post\.jwt/i.test(String(responseUri))) {
    responseMode = "direct_post.jwt";
  }
  const cid =
    typeof payload.client_id === "string" && payload.client_id.length
      ? payload.client_id
      : deepLinkClientId ?? null;
  return {
    client_id: cid,
    response_uri: typeof responseUri === "string" ? responseUri : null,
    response_mode: responseMode,
    nonce: payload.nonce ?? null,
    state: payload.state ?? null,
    dcql_query: payload.dcql_query ?? null,
    transaction_data: payload.transaction_data ?? null,
    updatedAt: new Date().toISOString(),
  };
}

export async function storeWalletPresentationSession(
  sessionId,
  payload,
  deepLinkClientId,
) {
  if (!sessionId) return;
  const record = buildWalletPresentationSessionRecord(payload, deepLinkClientId);
  if (!record) return;
  await ensureWalletRedisConnected();
  const ttl = parseInt(process.env.WALLET_PRESENTATION_SESSION_TTL || "3600", 10);
  try {
    await walletRedisClient.setEx(
      walletPresentationSessionKey(sessionId),
      ttl,
      JSON.stringify(record),
    );
  } catch (e) {
    console.error("[cache] storeWalletPresentationSession:", e?.message || e);
  }
}

export async function getWalletPresentationSession(sessionId) {
  if (!sessionId) return null;
  await ensureWalletRedisConnected();
  try {
    const v = await walletRedisClient.get(walletPresentationSessionKey(sessionId));
    return v ? JSON.parse(v) : null;
  } catch (e) {
    console.error("[cache] getWalletPresentationSession:", e?.message || e);
    return null;
  }
}
