import redis from "redis";
import { selectCs02VerifierEncryptionJwk } from "../utils/cs02TrustPolicy.js";
import { getSessionLogContext } from "../utils/sessionLogContext.js";
import { withCanonicalSessionContext } from "../utils/sessionContext.js";

//
const VCI_CODE_FLOW_TIMEOUT = process.env.VCI_CODE_FLOW_TIMEOUT || 180;
const VCI_PRE_AUTH_TIMEOUT = process.env.VCI_PRE_AUTH_TIMEOUT || 180;
const ISSUANCE_REFRESH_TOKEN_TTL_SECONDS = Number(process.env.ISSUANCE_REFRESH_TOKEN_TTL_SECONDS) || 86400 * 30;
const ISSUANCE_REFRESH_SESSION_TTL_SECONDS =
  Math.max(Number(process.env.ISSUANCE_REFRESH_SESSION_TTL_SECONDS) || 0, ISSUANCE_REFRESH_TOKEN_TTL_SECONDS);
const VP_TIMEOUT = process.env.VP_TIMEOUT || 180;
const redis_url = process.env.REDIS ? process.env.REDIS : "localhost:6379";
// Create a Redis client
export const client = redis.createClient({
  url: `redis://${redis_url}`,
});

// Connect to Redis
(async () => {
  try {
    await client.connect();
    console.log("Connected to Redis");
  } catch (err) {
    console.error("Error connecting to Redis:", err);
    if (process.env.ALLOW_NO_REDIS === 'true' || process.env.NODE_ENV === 'test') {
      console.warn('Redis connection failed; continuing without Redis for tests.');
    } else {
      process.exit(1);
    }
  }
})();

// Add event listeners for Redis connection status
client.on('error', (err) => {
  console.error('Redis Client Error:', err);
});

client.on('connect', () => {
  console.log('Redis Client Connected');
});

client.on('ready', () => {
  console.log('Redis Client Ready');
});

client.on('end', () => {
  console.log('Redis Client Connection Ended');
});

/*
pre-auth-sessions : {
  key: "12321-12312-12312" //session
  value :{
    result: {} //json,
    persona: "",
    accessToken: 
  }
}
*/



// Function to store a pre-auth session in Redis
export async function storePreAuthSession(sessionKey, sessionValue, options = {}) {
  try {
    // Check if Redis client is connected
    if (!client.isReady) {
      if (sessionValue?.refreshBinding) throw new Error("Redis is unavailable for refresh session storage");
      console.log("Redis not ready, skipping storePreAuthSession");
      return;
    }
    
    const key = `pre-auth-sessions:${sessionKey}`;
    const ttlInSeconds = resolveIssuanceSessionTtl(sessionValue, options, VCI_PRE_AUTH_TIMEOUT);
    sessionValue.preAuthorizedCodeExpiresAt ??= Date.now() + Number(VCI_PRE_AUTH_TIMEOUT) * 1000;
    await saveIssuanceSession(key, sessionKey, sessionValue, "pre-auth", ttlInSeconds);
  } catch (err) {
    console.error("Error storing session:", err);
    throw err; // Re-throw the error so calling code knows about the failure
  }
}
// Function to retrieve a pre-auth session from Redis
export async function getPreAuthSession(sessionKey) {
  try {
    // Check if Redis client is connected
    if (!client.isReady) {
      console.log("Redis not ready, skipping getPreAuthSession");
      return null;
    }
    
    const key = `pre-auth-sessions:${sessionKey}`;
    const result = await client.get(key);
    if (result) {
      return JSON.parse(result);
    } else {
      return null;
    }
  } catch (err) {
    console.error("Error retrieving session:", err);
    throw err; // Re-throw the error so calling code knows about the failure
  }
}

/** Reserve a BWIA digest for one issuance session; the same session may retry. */
export async function reserveBusinessWalletAttestation(digest, sessionId, ttlSeconds) {
  if (!client.isReady || !digest || !sessionId || !Number.isInteger(ttlSeconds) || ttlSeconds <= 0) return false;
  const key = `issuance:bwia-use:${digest}`;
  const result = await client.set(key, String(sessionId), { NX: true, EX: ttlSeconds });
  if (result === "OK") return true;
  return (await client.get(key)) === String(sessionId);
}

export async function storeBusinessWalletDpopNonce(nonce, endpoint, jkt, sessionId = null) {
  if (!client.isReady || !nonce || !endpoint || !jkt) return false;
  const key = `issuance:bwia-dpop-nonce:${nonce}`;
  return (await client.set(key, JSON.stringify({ endpoint, jkt, sessionId }), { NX: true, EX: 300 })) === "OK";
}

export async function consumeBusinessWalletDpopNonce(nonce, endpoint, jkt, sessionId = null) {
  if (!client.isReady || !nonce || !endpoint || !jkt) return false;
  const key = `issuance:bwia-dpop-nonce:${nonce}`;
  const script = "local v=redis.call('GET',KEYS[1]); if not v then return 0 end; local d=cjson.decode(v); if d.endpoint ~= ARGV[1] or d.jkt ~= ARGV[2] or (d.sessionId and d.sessionId ~= ARGV[3]) then return 0 end; redis.call('DEL',KEYS[1]); return 1";
  return Number(await client.eval(script, { keys: [key], arguments: [endpoint, jkt, sessionId || ""] })) === 1;
}

export async function registerIssuanceRefreshToken(refreshToken, record) {
  if (!client.isReady || !refreshToken || !record?.sessionKey) return false;
  const key = `issuance:refresh-token:${refreshToken}`;
  return (await client.setEx(key, ISSUANCE_REFRESH_TOKEN_TTL_SECONDS, JSON.stringify(record))) === "OK";
}

export async function lookupIssuanceRefreshToken(refreshToken) {
  if (!client.isReady || !refreshToken) return null;
  const raw = await client.get(`issuance:refresh-token:${refreshToken}`);
  return raw ? JSON.parse(raw) : null;
}

export async function revokeIssuanceRefreshToken(refreshToken) {
  if (!client.isReady || !refreshToken) return;
  await client.del(`issuance:refresh-token:${refreshToken}`);
}

export function issuanceRefreshTokenTtlSeconds() {
  return ISSUANCE_REFRESH_TOKEN_TTL_SECONDS;
}

export function issuanceRefreshSessionTtlSeconds() {
  return ISSUANCE_REFRESH_SESSION_TTL_SECONDS;
}

export function resolveIssuanceSessionTtl(session, options = {}, initialTtl = VCI_CODE_FLOW_TIMEOUT) {
  if (session?.refreshBinding) {
    const expiresAt = session.refreshBinding.expiresAt;
    return Number.isFinite(expiresAt)
      ? Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000))
      : ISSUANCE_REFRESH_SESSION_TTL_SECONDS;
  }
  return Number(options.ttlSeconds ?? initialTtl);
}

/** Reject whole-session snapshots read before rotation, including snapshots with no binding yet. */
async function saveIssuanceSession(key, sessionKey, session, flow, ttlSeconds) {
  const value = JSON.stringify(withCanonicalSessionContext(sessionKey, session, "issuance", flow));
  const script = `
    local raw = redis.call('GET', KEYS[1])
    if raw then
      local current = cjson.decode(raw)
      local next = cjson.decode(ARGV[1])
      if type(current.refreshBinding) == 'table' and
         (type(next.refreshBinding) ~= 'table' or current.refreshBinding.token ~= next.refreshBinding.token) then
        return 0
      end
    end
    -- Keep JSON verbatim so empty arrays retain their shape.
    redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
    return 1`;
  const saved = await client.eval(script, { keys: [key], arguments: [value, String(ttlSeconds)] });
  if (Number(saved) !== 1) {
    const error = new Error("Issuance session changed during token rotation; reload before saving");
    error.errorCode = "stale_issuance_session";
    throw error;
  }
}

/** Compare and rotate in one Redis operation. No worker can redeem the old token twice. */
export async function rotateIssuanceRefreshToken({ oldToken, newToken, mapping, session, nonceExpiresIn = 86400 }) {
  if (!client.isReady) throw new Error("Redis is unavailable for refresh token rotation");
  const flow = mapping.flowType === "code" ? "code" : "pre-auth";
  const storedSession = withCanonicalSessionContext(mapping.sessionKey, session, "issuance", flow);
  const script = `
    local raw = redis.call('GET', KEYS[1])
    local oldMapping = redis.call('GET', KEYS[2])
    if not raw or not oldMapping then return 0 end
    local current = cjson.decode(raw)
    if not current.refreshBinding or current.refreshBinding.token ~= ARGV[1] then return 0 end
    local next = cjson.decode(ARGV[3])
    if current.refreshBinding.dpopJkt ~= next.refreshBinding.dpopJkt or
       current.refreshBinding.clientId ~= next.refreshBinding.clientId then return 0 end
    redis.call('SET', KEYS[3], ARGV[4], 'EX', ARGV[5])
    redis.call('SET', KEYS[1], ARGV[3], 'EX', ARGV[6])
    redis.call('SET', KEYS[4], '1', 'EX', ARGV[7])
    redis.call('DEL', KEYS[2])
    return 1`;
  return Number(await client.eval(script, {
    keys: [`${flow === "code" ? "code-flow" : "pre-auth"}-sessions:${mapping.sessionKey}`,
      `issuance:refresh-token:${oldToken}`, `issuance:refresh-token:${newToken}`, `nonces:${session.c_nonce}`],
    arguments: [oldToken, newToken, JSON.stringify(storedSession), JSON.stringify(mapping),
      String(ISSUANCE_REFRESH_TOKEN_TTL_SECONDS), String(resolveIssuanceSessionTtl(session)), String(nonceExpiresIn)],
  })) === 1;
}

/** Validate transaction codes, count failures, and consume the initial grant atomically. */
export async function redeemPreAuthorizedTokenSession(sessionKey, session, txCode) {
  if (!client.isReady) throw new Error("Redis is unavailable for pre-authorized code redemption");
  const nextSession = { ...session, preAuthorizedCodeConsumed: true };
  const script = `
    local raw = redis.call('GET', KEYS[1])
    if not raw then return 'invalid_grant' end
    local current = cjson.decode(raw)
    if current.preAuthorizedCodeConsumed or current.preAuthorizedCodeInvalidated or
       tonumber(redis.call('GET', KEYS[2]) or '0') >= tonumber(ARGV[4]) or
       (current.preAuthorizedCodeExpiresAt and current.preAuthorizedCodeExpiresAt <= tonumber(ARGV[3])) or
       current.status == 'pending_external' then return 'invalid_grant' end
    local supplied = ARGV[2] ~= ''
    if current.txCodeRequired and not supplied then return 'invalid_request' end
    if not current.txCodeRequired and supplied then return 'invalid_request' end
    if current.txCodeRequired and ARGV[2] ~= tostring(current.expectedTxCode) then
      redis.call('INCR', KEYS[2])
      redis.call('PEXPIRE', KEYS[2], math.max(1, redis.call('PTTL', KEYS[1])))
      return 'invalid_grant'
    end
    -- Preserve the supplied JSON verbatim: Lua cjson would turn empty arrays into objects.
    redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[5])
    redis.call('DEL', KEYS[2])
    return 'ok'`;
  const code = await client.eval(script, {
    keys: [`pre-auth-sessions:${sessionKey}`, `issuance:pre-auth-tx-attempts:${sessionKey}`],
    arguments: [JSON.stringify(withCanonicalSessionContext(sessionKey, nextSession, "issuance", "pre-auth")),
      txCode == null ? "" : String(txCode), String(Date.now()),
      String(Math.max(1, Number(process.env.PRE_AUTH_TX_CODE_MAX_ATTEMPTS) || 5)),
      String(resolveIssuanceSessionTtl(session, {}, VCI_PRE_AUTH_TIMEOUT))],
  });
  if (code !== "ok") {
    const error = new Error(code === "invalid_request"
      ? "tx_code was provided but not expected, or expected but not provided"
      : "Pre-authorized code is expired, used, invalidated, not ready, or the Transaction Code is wrong");
    error.errorCode = code;
    throw error;
  }
}

// Function to get session key from an access token
export async function getSessionKeyFromAccessToken(accessToken) {
  try {
    const keys = await client.keys("pre-auth-sessions:*"); // Get all session keys
    for (const key of keys) {
      const session = await client.get(key);
      if (session) {
        const parsedSession = JSON.parse(session);
        if (parsedSession.accessToken === accessToken) {
          console.log(`Found session key for access token: ${accessToken}`);
          return key.replace("pre-auth-sessions:", ""); // Return the session key without the prefix
        }
      }
    }
    console.log("No session found for access token:", accessToken);
    return null;
  } catch (err) {
    console.error("Error retrieving session key for access token:", err);
  }
}

export async function storeCodeFlowSession(sessionKey, sessionValue, options = {}) {
  try {
    if (!client.isReady) {
      if (sessionValue?.refreshBinding) throw new Error("Redis is unavailable for refresh session storage");
      console.log("Redis not ready, skipping storeCodeFlowSession");
      return;
    }
    const key = `code-flow-sessions:${sessionKey}`;
    const ttlInSeconds = resolveIssuanceSessionTtl(sessionValue, options, VCI_CODE_FLOW_TIMEOUT);
    await saveIssuanceSession(key, sessionKey, sessionValue, "code", ttlInSeconds);
    console.log(`Session stored under key: ${key}`);
  } catch (err) {
    console.error("Error storing session:", err);
    throw err;
  }
}

function dcApiProgressKeys(sessionKey, flowType) {
  const flow = flowType === "code" ? "code" : "pre-auth";
  const root = `dc-api-progress:${flow}:${sessionKey}`;
  return { session: `${flow === "code" ? "code-flow-sessions" : "pre-auth-sessions"}:${sessionKey}`, issued: `${root}:issued`, notifications: `${root}:notifications`, metadata: `${root}:metadata` };
}

/** Atomically update progress keys without reserializing the caller's session or claims. */
export async function updateDcApiIssuanceProgress(sessionKey, flowType, update, redisClient = client) {
  const keys = dcApiProgressKeys(sessionKey, flowType);
  const script = `
    if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
    local mode = ARGV[1]
    if mode == 'issued' then
      redis.call('SADD', KEYS[2], ARGV[2])
      redis.call('HSET', KEYS[3], ARGV[3], ARGV[4])
      if redis.call('HGET', KEYS[4], 'status') ~= 'failed' then redis.call('HSET', KEYS[4], 'status', 'success') end
    elseif mode == 'notification' then
      local raw = redis.call('HGET', KEYS[3], ARGV[2])
      if not raw then return -1 end
      local entry = cjson.decode(raw)
      entry.event = ARGV[3]
      entry.event_description = ARGV[4] ~= '' and ARGV[4] or cjson.null
      redis.call('HSET', KEYS[3], ARGV[2], cjson.encode(entry))
      if ARGV[3] == 'credential_failure' or ARGV[3] == 'credential_deleted' then
        redis.call('HSET', KEYS[4], 'status', 'failed')
      elseif redis.call('HGET', KEYS[4], 'status') ~= 'failed' then
        redis.call('HSET', KEYS[4], 'status', 'success')
      end
    else
      return -2
    end
    local ttl = redis.call('PTTL', KEYS[1])
    if ttl >= 0 then
      for index = 2, 4 do redis.call('PEXPIRE', KEYS[index], math.max(ttl, 1)) end
    end
    return 1
  `;
  const args = update.mode === "issued"
    ? ["issued", update.credentialConfigurationId, update.notificationId, JSON.stringify({ credentialConfigurationId: update.credentialConfigurationId, event: "issued" })]
    : ["notification", update.notificationId, update.event, update.eventDescription || ""];
  return Number(await redisClient.eval(script, { keys: [keys.session, keys.issued, keys.notifications, keys.metadata], arguments: args }));
}

export async function getDcApiIssuanceProgress(sessionKey, flowType, redisClient = client) {
  if (!redisClient.isReady && redisClient === client) return { issuedCredentialConfigurationIds: [], notifications: {}, status: null };
  const keys = dcApiProgressKeys(sessionKey, flowType);
  const [issued, notifications, metadata] = await Promise.all([
    redisClient.sMembers(keys.issued),
    redisClient.hGetAll(keys.notifications),
    redisClient.hGetAll(keys.metadata),
  ]);
  return {
    issuedCredentialConfigurationIds: issued || [],
    notifications: Object.fromEntries(Object.entries(notifications || {}).map(([id, value]) => [id, JSON.parse(value)])),
    status: metadata?.status || null,
  };
}

// Function to retrieve a code-flow session from Redis
export async function getCodeFlowSession(sessionKey) {
  try {
    if (!client.isReady) {
      console.log("Redis not ready, skipping getCodeFlowSession");
      return null;
    }
    const key = `code-flow-sessions:${sessionKey}`;
    const result = await client.get(key);
    if (result) {
      // console.log("Session retrieved:", JSON.parse(result));
      return JSON.parse(result);
    } else {
      console.log("Session not found for key:", key);
      return null;
    }
  } catch (err) {
    console.error("Error retrieving session:", err);
  }
}

// Function to get session key from an access token
export async function getSessionKeyAuthCode(code) {
  try {
    const keys = await client.keys("code-flow-sessions:*"); // Get all session keys
    for (const key of keys) {
      const session = await client.get(key);
      if (session) {
        const parsedSession = JSON.parse(session);
        if (
          parsedSession.requests &&
          parsedSession.requests.sessionId == code
        ) {
          console.log(`Found session key for authorization code: ${code}`);
          return key.replace("code-flow-sessions:", ""); // Return the session key without the prefix
        }
      }
    }
    console.log("No session found for auth code:", code);
    return null;
  } catch (err) {
    console.error("Error retrieving session key for access token:", err);
  }
}

// Function to get session key from an access token
export async function getSessionAccessToken(token) {
  try {
    const keys = await client.keys("code-flow-sessions:*"); // Get all session keys
    for (const key of keys) {
      const session = await client.get(key);
      if (session) {
        const parsedSession = JSON.parse(session);
        if (
          parsedSession.requests &&
          parsedSession.requests.accessToken == token
        ) {
          console.log(`Found session key for access token: ${token}`);
          return key.replace("code-flow-sessions:", ""); // Return the session key without the prefix
        }
      }
    }
    console.log("No session found for auth code:", token);
    return null;
  } catch (err) {
    console.error("Error retrieving session key for access token:", err);
  }
}

const DEFERRED_SESSION_PREFIXES = [
  { prefix: "code-flow-sessions:", flowType: "code" },
  { prefix: "pre-auth-sessions:", flowType: "pre-auth" },
];

export async function findDeferredSessionByTransactionId(transaction_id) {
  try {
    if (!client.isReady) {
      console.log("Redis not ready, skipping findDeferredSessionByTransactionId");
      return null;
    }

    for (const { prefix, flowType } of DEFERRED_SESSION_PREFIXES) {
      const keys = await client.keys(`${prefix}*`);
      for (const key of keys) {
        const session = await client.get(key);
        if (!session) {
          continue;
        }
        const parsedSession = JSON.parse(session);
        if (
          parsedSession.transaction_id &&
          parsedSession.transaction_id == transaction_id
        ) {
          console.log(
            `Found ${flowType} session key for transaction_id: ${transaction_id}`,
          );
          return {
            sessionKey: key.replace(prefix, ""),
            flowType,
          };
        }
      }
    }

    console.log("No session found for transaction_id:", transaction_id);
    return null;
  } catch (err) {
    console.error("Error retrieving deferred session for transaction_id:", err);
    return null;
  }
}

export async function getDeferredSessionTransactionId(transaction_id) {
  const lookup = await findDeferredSessionByTransactionId(transaction_id);
  return lookup?.sessionKey ?? null;
}

export function withVPSessionLifecycle(sessionValue, now = Math.floor(Date.now() / 1000), ttlInSeconds = Number(VP_TIMEOUT) || 180) {
  if (!sessionValue || typeof sessionValue !== "object") return sessionValue;
  const selectedEncryptionKey =
    sessionValue.encryption_key ||
    (sessionValue.response_mode === "direct_post.jwt"
      ? selectCs02VerifierEncryptionJwk(sessionValue.client_metadata)
      : null);
  return {
    ...sessionValue,
    created_at: sessionValue.created_at ?? now,
    expires_at: sessionValue.expires_at ?? now + ttlInSeconds,
    ...(selectedEncryptionKey ? { encryption_key: selectedEncryptionKey } : {}),
  };
}

const memoryVpSessions = new Map();

function canUseMemoryVpFallback() {
  return process.env.ALLOW_NO_REDIS === "true" || process.env.NODE_ENV === "test";
}

export async function storeVPSession(sessionKey, sessionValue) {
  const ttlInSeconds = Number(VP_TIMEOUT) || 180;
  const value = withVPSessionLifecycle(
    withCanonicalSessionContext(sessionKey, sessionValue, "verification"),
    Math.floor(Date.now() / 1000),
    ttlInSeconds,
  );

  if (!client.isReady) {
    if (canUseMemoryVpFallback()) {
      memoryVpSessions.set(sessionKey, {
        value,
        expiresAtMs: Date.now() + ttlInSeconds * 1000,
      });
      return;
    }
    console.log("Redis not ready, skipping storeVPSession");
    return;
  }

  try {
    const key = `vp-sessions:${sessionKey}`;
    await client.setEx(key, ttlInSeconds, JSON.stringify(value)); // Set with expiration
    console.log(`VP Session stored under key: ${key}`);
  } catch (err) {
    console.error("Error storing session:", err);
  }
}

export async function getVPSession(sessionKey) {
  if (!client.isReady && canUseMemoryVpFallback()) {
    const entry = memoryVpSessions.get(sessionKey);
    if (!entry) return null;
    const nowUnix = Math.floor(Date.now() / 1000);
    if (entry.expiresAtMs <= Date.now() || (entry.value?.expires_at != null && Number(entry.value.expires_at) <= nowUnix)) {
      memoryVpSessions.delete(sessionKey);
      return null;
    }
    return entry.value;
  }

  try {
    const key = `vp-sessions:${sessionKey}`;
    const result = await client.get(key);
    if (result) {
      const session = JSON.parse(result);
      if (session?.expires_at != null && Number(session.expires_at) <= Math.floor(Date.now() / 1000)) {
        await client.del(key);
        return null;
      }
      return session;
    } else {
      console.log("Session not found for key:", key);
      return null;
    }
  } catch (err) {
    console.error("Error retrieving session:", err);
  }
}

export async function consumeVPSessionKeyBindingJti(sessionKey, jti, ttlInSeconds = Number(VP_TIMEOUT) || 180) {
  if (!sessionKey || typeof jti !== "string" || jti.length === 0 || !client.isReady) return false;
  try {
    const result = await client.set(
      `vp-kb-jti:${sessionKey}:${jti}`,
      "1",
      { NX: true, EX: ttlInSeconds },
    );
    return result === "OK";
  } catch (error) {
    console.error("Error consuming VP key-binding jti:", error);
    return false;
  }
}

// Function to store a nonce in Redis cache
export async function storeNonce(nonce, ttlInSeconds = 300) {
  try {
    if (!client.isReady) {
      console.log("Redis not ready, skipping storeNonce");
      return;
    }
    const key = `nonces:${nonce}`;
    await client.setEx(key, ttlInSeconds, "1"); // Store with expiration, value doesn't matter for nonce
    console.log(`Nonce stored under key: ${key} with TTL: ${ttlInSeconds}s`);
  } catch (err) {
    console.error("Error storing nonce:", err);
  }
}

// Function to check if a nonce exists in Redis cache
export async function checkNonce(nonce) {
  try {
    if (!client.isReady) {
      console.log("Redis not ready, skipping checkNonce");
      return false;
    }
    const key = `nonces:${nonce}`;
    const result = await client.exists(key);
    const exists = result === 1;
    console.log(`Nonce ${nonce} ${exists ? 'found' : 'not found'} in cache`);
    return exists;
  } catch (err) {
    console.error("Error checking nonce:", err);
    return false;
  }
}

// Function to delete a nonce from Redis cache
export async function deleteNonce(nonce) {
  try {
    const key = `nonces:${nonce}`;
    const result = await client.del(key);
    const deleted = result === 1;
    console.log(`Nonce ${nonce} ${deleted ? 'deleted' : 'not found for deletion'} from cache`);
    return deleted;
  } catch (err) {
    console.error("Error deleting nonce:", err);
    return false;
  }
}

// Function to atomically check and set last poll time for slow_down detection
// Returns true if poll is allowed (enough time has passed), false if polled too recently
export async function checkAndSetPollTime(preAuthorizedCode, minPollIntervalSeconds = 5) {
  try {
    if (!client.isReady) {
      console.error("Redis client is not ready");
      throw new Error("Redis client is not ready");
    }
    
    const key = `poll-times:${preAuthorizedCode}`;
    const now = Date.now();
    
    // Try to set the key only if it doesn't exist (NX flag)
    // Set expiration to the minimum poll interval
    const result = await client.set(key, now.toString(), {
      EX: minPollIntervalSeconds,
      NX: true // Only set if key doesn't exist
    });
    
    // If result is OK, the key was set successfully (poll allowed)
    // If result is null, the key already exists (polled too recently)
    return result === 'OK';
  } catch (err) {
    console.error("Error checking/setting poll time:", err);
    // On error, allow the poll to proceed (fail open)
    return true;
  }
}

// Function to clear poll tracking for a session
export async function clearPollTime(preAuthorizedCode) {
  try {
    if (!client.isReady) {
      return;
    }
    
    const key = `poll-times:${preAuthorizedCode}`;
    await client.del(key);
  } catch (err) {
    console.error("Error clearing poll time:", err);
  }
}

export function getPreCodeSessions() {
  return {
    sessions: sessions,
    results: issuanceResults,
    personas: personas,
    accessTokens: accesTokens,
  };
}

export function getAuthCodeSessions() {
  return {
    walletSessions: walletCodeSessions,
    sessions: issuerCodeSessions,
    requests: codeFlowRequests,
    results: codeFlowRequestsResults,
  };
}

export const PAR_TTL_SECONDS = 90;

export async function storePushedAuthorizationRequest(requestUri, request, redisClient = client) {
  if (!redisClient.isReady) throw new Error("Redis unavailable for PAR storage");
  await redisClient.setEx(`par-requests:${requestUri}`, PAR_TTL_SECONDS, JSON.stringify(request));
}

export async function getPushedAuthorizationRequest(requestUri, redisClient = client) {
  if (!redisClient.isReady) throw new Error("Redis unavailable for PAR lookup");
  const raw = await redisClient.get(`par-requests:${requestUri}`);
  return raw ? JSON.parse(raw) : null;
}

export function getSessionsAuthorizationDetail() {
  return sessionsAuthorizationDetail;
}

export function getAuthCodeAuthorizationDetail() {
  return authCodeAuthorizationDetail;
}

// ============================================================================
// SESSION-BASED LOGGING FUNCTIONS
// ============================================================================

// Function to store logs for a specific session
export async function storeSessionLog(sessionId, logLevel, message, metadata = {}) {
  try {
    // Check if Redis client is connected
    if (!client.isReady) {
      console.log("Redis not ready, skipping storeSessionLog");
      return;
    }
    
    const key = `session-logs:${sessionId}`;
    const timestamp = new Date().toISOString();
    
    const logEntry = {
      timestamp,
      level: logLevel,
      message,
      metadata
    };
    
    // Get existing logs or initialize empty array
    const existingLogs = await client.get(key);
    let logs = existingLogs ? JSON.parse(existingLogs) : [];
    
    // Add new log entry
    logs.push(logEntry);
    
    // Keep only the last 100 log entries to prevent memory issues
    if (logs.length > 100) {
      logs = logs.slice(-100);
    }
    
    const ttlInSeconds = 1800; // 30 minutes
    await client.setEx(key, ttlInSeconds, JSON.stringify(logs));
  } catch (err) {
    console.error("Error storing session log:", err);
  }
}

// Function to retrieve all logs for a specific session
export async function getSessionLogs(sessionId) {
  try {
    // Check if Redis client is connected
    if (!client.isReady) {
      console.error("Redis client is not ready");
      throw new Error("Redis client is not ready");
    }
    
    const key = `session-logs:${sessionId}`;
    const result = await client.get(key);
    
    if (result) {
      return JSON.parse(result);
    } else {
      return [];
    }
  } catch (err) {
    console.error("Error retrieving session logs:", err);
    return [];
  }
}

// Function to clear logs for a specific session
export async function clearSessionLogs(sessionId) {
  try {
    // Check if Redis client is connected
    if (!client.isReady) {
      console.error("Redis client is not ready");
      throw new Error("Redis client is not ready");
    }
    
    const key = `session-logs:${sessionId}`;
    const result = await client.del(key);
    return result === 1;
  } catch (err) {
    console.error("Error clearing session logs:", err);
    return false;
  }
}

// Convenience functions for different log levels
export async function logInfo(sessionId, message, metadata = {}) {
  console.log(`Logging info for session ${sessionId}: ${message}, metadata: ${JSON.stringify(metadata)}`);
  return await storeSessionLog(sessionId, 'info', message, metadata);
}

export async function logWarn(sessionId, message, metadata = {}) {
  console.log(`Logging warn for session ${sessionId}: ${message}, metadata: ${JSON.stringify(metadata)}`);
  return await storeSessionLog(sessionId, 'warn', message, metadata);
}

export async function logError(sessionId, message, metadata = {}) {
  console.log(`Logging error for session ${sessionId}: ${message}, metadata: ${JSON.stringify(metadata)}`);
  return await storeSessionLog(sessionId, 'error', message, metadata);
}

export async function logDebug(sessionId, message, metadata = {}) {
  console.log(`Logging debug for session ${sessionId}: ${message}, metadata: ${JSON.stringify(metadata)}`);
  return await storeSessionLog(sessionId, 'debug', message, metadata);
}


//TODO evaluate this approach might be better
// ============================================================================
// CONSOLE LOG INTERCEPTION (OPTIONAL)
// ============================================================================
//
// To enable global console interception for all console.log/warn/error calls:
// 
// import { enableConsoleInterception } from './services/cacheServiceRedis.js';
// enableConsoleInterception();
//
// This will automatically capture all console logs when a session context is set.
// The session context is automatically managed by the x509Routes middleware.
//

// Store original console methods
const originalConsole = {
  log: console.log,
  warn: console.warn,
  error: console.error,
  info: console.info,
  debug: console.debug
};

// Function to enable console log interception
export function enableConsoleInterception() {
  console.log = (...args) => {
    originalConsole.log(...args);
    const currentSessionId = getSessionLogContext()?.sessionId;
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'info', message).catch(err => 
        originalConsole.error('Failed to store console.log:', err)
      );
    }
  };

  console.warn = (...args) => {
    originalConsole.warn(...args);
    const currentSessionId = getSessionLogContext()?.sessionId;
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'warn', message).catch(err => 
        originalConsole.error('Failed to store console.warn:', err)
      );
    }
  };

  console.error = (...args) => {
    originalConsole.error(...args);
    const currentSessionId = getSessionLogContext()?.sessionId;
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'error', message).catch(err => 
        originalConsole.error('Failed to store console.error:', err)
      );
    }
  };

  console.info = (...args) => {
    originalConsole.info(...args);
    const currentSessionId = getSessionLogContext()?.sessionId;
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'info', message).catch(err => 
        originalConsole.error('Failed to store console.info:', err)
      );
    }
  };

  console.debug = (...args) => {
    originalConsole.debug(...args);
    const currentSessionId = getSessionLogContext()?.sessionId;
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'debug', message).catch(err => 
        originalConsole.error('Failed to store console.debug:', err)
      );
    }
  };
}

// Function to disable console log interception
export function disableConsoleInterception() {
  console.log = originalConsole.log;
  console.warn = originalConsole.warn;
  console.error = originalConsole.error;
  console.info = originalConsole.info;
  console.debug = originalConsole.debug;
}
