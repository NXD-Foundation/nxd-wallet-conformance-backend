import "./logger.js";
import redis from "redis";
import { registerLogSinks } from "./logger.js";

// Wallet-client dedicated Redis connection
// Configure via WALLET_REDIS env var (host:port) or default localhost:6379
const redisUrl = process.env.WALLET_REDIS ? process.env.WALLET_REDIS : "localhost:6379";

export const walletRedisClient = redis.createClient({ url: `redis://${redisUrl}` });

(async () => {
  try {
    await walletRedisClient.connect();
    console.log("Wallet client connected to Redis");
  } catch (err) {
    console.error("Wallet Redis connection error:", err);
  }
})();

walletRedisClient.on("error", (err) => {
  console.error("Wallet Redis Client Error:", err);
});

walletRedisClient.on("ready", () => {
  console.log("Wallet Redis Client Ready");
});

// Store credential and key-binding material under credential type (configurationId)
export async function storeWalletCredentialByType(configurationId, payload) {
  const key = `wallet:credentials:${configurationId}`;
  const ttlInSeconds = parseInt(process.env.WALLET_CREDENTIAL_TTL || "86400");
  await walletRedisClient.setEx(key, ttlInSeconds, JSON.stringify(payload));
}

export async function getWalletCredentialByType(configurationId) {
  const key = `wallet:credentials:${configurationId}`;
  const val = await walletRedisClient.get(key);
  return val ? JSON.parse(val) : null;
}

export async function listWalletCredentialTypes() {
  const keys = await walletRedisClient.keys("wallet:credentials:*");
  return keys.map((k) => k.replace(/^wallet:credentials:/, ""));
}

// Store logs under a specific sessionId key
export async function storeWalletLogs(sessionId, logs) {
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
  return getLogsByKey(`wallet:logs:${sessionId}`);
}

export async function appendWalletLog(sessionId, logEntry) {
  return appendLogByKey(`wallet:logs:${sessionId}`, logEntry);
}

export async function getGlobalLogs() {
  return getLogsByKey("wallet:logs:global");
}

export async function appendGlobalLog(logEntry) {
  return appendLogByKey("wallet:logs:global", logEntry);
}

async function getLogsByKey(key) {
  try {
    const listLength = await walletRedisClient.lLen(key);
    if (listLength > 0) {
      const logEntries = await walletRedisClient.lRange(key, 0, -1);
      return logEntries.map((entry) => JSON.parse(entry));
    }
    return null;
  } catch (error) {
    if (error.message && error.message.includes("WRONGTYPE")) {
      try {
        const val = await walletRedisClient.get(key);
        if (val) {
          const oldLogs = JSON.parse(val);
          await walletRedisClient.del(key);
          if (oldLogs && oldLogs.length > 0) {
            const logStrings = oldLogs.map((log) => JSON.stringify(log));
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

async function appendLogByKey(key, logEntry) {
  const entryWithTimestamp = {
    ...logEntry,
    timestamp: logEntry?.timestamp || new Date().toISOString()
  };

  try {
    await walletRedisClient.rPush(key, JSON.stringify(entryWithTimestamp));
    const ttlInSeconds = parseInt(process.env.WALLET_LOGS_TTL || "3600");
    await walletRedisClient.expire(key, ttlInSeconds);
  } catch (error) {
    if (error.message && error.message.includes("WRONGTYPE")) {
      try {
        const val = await walletRedisClient.get(key);
        await walletRedisClient.del(key);

        if (val) {
          const oldLogs = JSON.parse(val);
          if (oldLogs && oldLogs.length > 0) {
            const logStrings = oldLogs.map((log) => JSON.stringify(log));
            await walletRedisClient.rPush(key, ...logStrings);
          }
        }

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

registerLogSinks({
  appendSessionLog: appendWalletLog,
  appendGlobalLog,
});

function statusListNextKey(kind, listId) {
  return `wallet:statuslist:${kind}:${listId}:next`;
}

function statusListEntriesKey(kind, listId) {
  return `wallet:statuslist:${kind}:${listId}:entries`;
}

export function createRedisStatusListStorage() {
  return {
    async allocate(kind, listId, metadata) {
      const next = await walletRedisClient.incr(statusListNextKey(kind, listId));
      const idx = next - 1;
      await walletRedisClient.hSet(
        statusListEntriesKey(kind, listId),
        String(idx),
        JSON.stringify({ status: 0, ...metadata }),
      );
      return idx;
    },
    async allocatedCount(kind, listId) {
      const raw = await walletRedisClient.get(statusListNextKey(kind, listId));
      return raw ? Number(raw) : 0;
    },
    async getEntry(kind, listId, idx) {
      const raw = await walletRedisClient.hGet(statusListEntriesKey(kind, listId), String(idx));
      return raw ? JSON.parse(raw) : null;
    },
    async putEntry(kind, listId, idx, entry) {
      await walletRedisClient.hSet(
        statusListEntriesKey(kind, listId),
        String(idx),
        JSON.stringify(entry),
      );
    },
    async listEntries(kind, listId) {
      const all = await walletRedisClient.hGetAll(statusListEntriesKey(kind, listId));
      return Object.entries(all).map(([idx, raw]) => [Number(idx), JSON.parse(raw)]);
    },
  };
}

