import redis from "redis";

//
const VCI_CODE_FLOW_TIMEOUT = process.env.VCI_CODE_FLOW_TIMEOUT || 180;
const VCI_PRE_AUTH_TIMEOUT = process.env.VCI_PRE_AUTH_TIMEOUT || 180;
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
export async function storePreAuthSession(sessionKey, sessionValue) {
  try {
    // Check if Redis client is connected
    if (!client.isReady) {
      console.log("Redis not ready, skipping storePreAuthSession");
      return;
    }
    
    const key = `pre-auth-sessions:${sessionKey}`;
    const ttlInSeconds = VCI_PRE_AUTH_TIMEOUT; // env, default: 3 minutes
    await client.setEx(key, ttlInSeconds, JSON.stringify(sessionValue)); // Set with expiration
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

// Function to get session key from an access token
export async function getSessionKeyFromAccessToken(accessToken) {
  try {
    const keys = await client.keys("pre-auth-sessions:*"); // Get all session keys
    for (const key of keys) {
      const session = await client.get(key);
      if (session) {
        const parsedSession = JSON.parse(session);
        if (
          parsedSession.accessToken === accessToken ||
          Object.hasOwn(parsedSession.tokenAuthorizations || {}, accessToken)
        ) {
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

export async function storeCodeFlowSession(sessionKey, sessionValue) {
  try {
    if (!client.isReady) {
      console.log("Redis not ready, skipping storeCodeFlowSession");
      return;
    }
    const key = `code-flow-sessions:${sessionKey}`;
    const ttlInSeconds = VCI_CODE_FLOW_TIMEOUT; // env, default: 3 minutes
    await client.setEx(key, ttlInSeconds, JSON.stringify(sessionValue)); // Set with expiration
    console.log(`Session stored under key: ${key}`);
  } catch (err) {
    console.error("Error storing session:", err);
  }
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

/**
 * Resolve deferred issuance session by `transaction_id` (code flow or pre-auth store).
 * @returns {Promise<{ sessionKey: string, flowType: 'code'|'pre-auth' } | null>}
 */
export async function resolveDeferredIssuanceContext(transaction_id) {
  try {
    if (!client.isReady) {
      console.log("Redis not ready, skipping resolveDeferredIssuanceContext");
      return null;
    }
    const scan = async (prefix, flowType) => {
      const keys = await client.keys(`${prefix}*`);
      for (const key of keys) {
        const session = await client.get(key);
        if (session) {
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
      return null;
    };
    const fromCode = await scan("code-flow-sessions:", "code");
    if (fromCode) return fromCode;
    return await scan("pre-auth-sessions:", "pre-auth");
  } catch (err) {
    console.error("Error in resolveDeferredIssuanceContext:", err);
  }
  return null;
}

export async function getDeferredSessionTransactionId(transaction_id) {
  const ctx = await resolveDeferredIssuanceContext(transaction_id);
  return ctx ? ctx.sessionKey : null;
}

export async function storeVPSession(sessionKey, sessionValue) {
  try {
    const key = `vp-sessions:${sessionKey}`;
    const ttlInSeconds = VP_TIMEOUT; // env, default: 3 minutes
    await client.setEx(key, ttlInSeconds, JSON.stringify(sessionValue)); // Set with expiration
    console.log(`VP Session stored under key: ${key}`);
  } catch (err) {
    console.error("Error storing session:", err);
  }
}

export async function getVPSession(sessionKey) {
  try {
    const key = `vp-sessions:${sessionKey}`;
    const result = await client.get(key);
    if (result) {
      // console.log("VP Session retrieved:", JSON.parse(result));
      return JSON.parse(result);
    } else {
      console.log("Session not found for key:", key);
      return null;
    }
  } catch (err) {
    console.error("Error retrieving session:", err);
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

export function getPushedAuthorizationRequests() {
  return pushedAuthorizationRequests;
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
    const normalizedMetadata = normalizeLogMetadata(metadata);
    
    const logEntry = {
      timestamp,
      level: logLevel,
      message,
      event: extractExplicitLogField(normalizedMetadata, "event"),
      phase: extractExplicitLogField(normalizedMetadata, "phase"),
      kind: extractExplicitLogField(normalizedMetadata, "kind"),
      compliance: extractExplicitLogField(normalizedMetadata, "compliance"),
      artifacts: extractExplicitLogField(normalizedMetadata, "artifacts"),
      metadata: normalizedMetadata
    };
    enrichLogEntry(logEntry);
    
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

function extractExplicitLogField(metadata, field) {
  if (!metadata || typeof metadata !== "object") return undefined;
  if (!(field in metadata)) return undefined;
  const value = metadata[field];
  delete metadata[field];
  return value;
}

function normalizeLogMetadata(metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return {};
  }
  return sanitizeLogValue(metadata);
}

function sanitizeLogValue(value, keyPath = "") {
  if (value == null) return value;
  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item) => sanitizeLogValue(item, keyPath));
  }
  if (typeof value === "object") {
    const out = {};
    for (const [key, child] of Object.entries(value)) {
      out[key] = sanitizeLogValue(child, key);
    }
    return out;
  }
  if (typeof value !== "string") return value;

  const lowerKey = String(keyPath).toLowerCase();
  if (
    lowerKey.includes("token") ||
    lowerKey.includes("proof") ||
    lowerKey.includes("jwt") ||
    lowerKey.includes("assertion") ||
    lowerKey.includes("qr")
  ) {
    return summarizeSecretString(value);
  }

  if (value.length > 400) {
    return {
      preview: `${value.slice(0, 180)}...${value.slice(-40)}`,
      length: value.length,
    };
  }

  return value;
}

function summarizeSecretString(value) {
  if (typeof value !== "string") return value;
  return {
    present: true,
    length: value.length,
    preview: value.length <= 24 ? value : `${value.slice(0, 12)}...${value.slice(-8)}`,
  };
}

function enrichLogEntry(entry) {
  const inferred = inferLogAttributes(entry.message, entry.metadata);
  if (!entry.event && inferred.event) entry.event = inferred.event;
  if (!entry.phase && inferred.phase) entry.phase = inferred.phase;
  if (!entry.kind && inferred.kind) entry.kind = inferred.kind;
  if (!entry.compliance && inferred.compliance) entry.compliance = inferred.compliance;
}

function inferLogAttributes(message = "", metadata = {}) {
  const text = String(message);
  const lower = text.toLowerCase();
  const out = {};

  if (text.includes("[HTTP]")) out.kind = "http";
  else if (text.includes("[WARN]") || text.includes("[ERROR]")) out.kind = "compliance";
  else out.kind = "protocol";

  if (text.includes("[VCI]") || lower.includes("qr code") || lower.includes("/vci/offer")) out.phase = "offer";
  else if (text.includes("[PAR]") || lower.includes("/par")) out.phase = "par";
  else if (text.includes("[AUTHORIZATION]") || lower.includes("/authorize")) out.phase = "authorize";
  else if (text.includes("[TOKEN]") || lower.includes("/token")) out.phase = "token";
  else if (lower.includes("/nonce")) out.phase = "nonce";
  else if (text.includes("[CREDENTIAL]") || lower.includes("/credential")) out.phase = "credential";
  else if (lower.includes("vp request") || lower.includes("openid4vp")) out.phase = "vp";
  else if (lower.includes("/logs")) out.phase = "internal";

  if (text.includes("[HTTP] [REQUEST]")) out.event = "http.request";
  else if (text.includes("[HTTP] [RESPONSE]")) out.event = "http.response";
  else if (text.includes("[ISSUER] [VCI] [START]")) out.event = "offer.created";
  else if (lower.includes("qr code generated successfully")) out.event = "offer.qr.generated";
  else if (text.includes("[ISSUER] [PAR] [START]")) out.event = "par.received";
  else if (text.includes("[ISSUER] [PAR] [COMPLETE]")) out.event = "par.accepted";
  else if (text.includes("[ISSUER] [AUTHORIZATION] [START]")) out.event = "authorize.received";
  else if (text.includes("[ISSUER] [AUTHORIZATION] [COMPLETE]")) out.event = "authorize.completed";
  else if (text.includes("[TOKEN] [START]")) out.event = "token.received";
  else if (lower.includes("pkce verification successful")) out.event = "token.pkce_verified";
  else if (lower.includes("wia validated")) out.event = "token.wia.validated";
  else if (lower.includes("wua validated")) out.event = "credential.wua.validated";
  else if (lower.includes("proof jwt signature and claims validated successfully")) out.event = "credential.proof.validated";
  else if (text.includes("[CREDENTIAL] [COMPLETE]")) out.event = "credential.completed";
  else if (lower.includes("retrieving session logs")) out.event = "logs.retrieved";

  if (out.event === "token.pkce_verified") {
    out.compliance = {
      status: "pass",
      specs: [
        { name: "RFC7636", section: "4.6" },
        { name: "RFC001", section: "7.3" },
      ],
    };
  } else if (lower.includes("missing wia")) {
    out.compliance = {
      status: entryLevelToCompliance(text),
      specs: [
        { name: "ETSI TS 119 472-3", section: "4.5.1" },
        { name: "OpenID4VCI 1.0", section: "Appendix E" },
      ],
    };
  } else if (lower.includes("proof validation successful")) {
    out.compliance = {
      status: "pass",
      specs: [
        { name: "OpenID4VCI 1.0", section: "8.2" },
      ],
    };
  }

  return out;
}

function entryLevelToCompliance(message = "") {
  if (message.includes("[ERROR]")) return "fail";
  if (message.includes("[WARN]")) return "warn";
  return "pass";
}

export function summarizeSessionLogs(logs = []) {
  const phases = {};
  const warnings = [];
  const errors = [];

  for (const log of logs) {
    const phase = log.phase || "internal";
    if (!phases[phase]) phases[phase] = "pass";
    if (log.level === "error") phases[phase] = "fail";
    else if (log.level === "warn" && phases[phase] !== "fail") phases[phase] = "pass_with_warning";

    if (log.level === "warn") warnings.push(log.message);
    if (log.level === "error") errors.push(log.message);
  }

  const first = logs[0]?.timestamp || null;
  const last = logs[logs.length - 1]?.timestamp || null;
  const finalStatus = errors.length > 0 ? "failed" : warnings.length > 0 ? "success_with_warnings" : "success";
  const firstOffer = logs.find((log) => log.event === "offer.created");

  return {
    status: finalStatus,
    flow: firstOffer?.metadata?.flow || null,
    credential_type: firstOffer?.metadata?.credentialType || null,
    started_at: first,
    finished_at: last,
    phases,
    warnings: warnings.slice(0, 10),
    errors: errors.slice(0, 10),
  };
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

// Session context storage for console interception
let currentSessionId = null;

// Function to set session context for console interception
export function setSessionContext(sessionId) {
  currentSessionId = sessionId;
}

// Function to clear session context
export function clearSessionContext() {
  currentSessionId = null;
}

// Function to enable console log interception
export function enableConsoleInterception() {
  console.log = (...args) => {
    originalConsole.log(...args);
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'info', message).catch(err => 
        originalConsole.error('Failed to store console.log:', err)
      );
    }
  };

  console.warn = (...args) => {
    originalConsole.warn(...args);
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'warn', message).catch(err => 
        originalConsole.error('Failed to store console.warn:', err)
      );
    }
  };

  console.error = (...args) => {
    originalConsole.error(...args);
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'error', message).catch(err => 
        originalConsole.error('Failed to store console.error:', err)
      );
    }
  };

  console.info = (...args) => {
    originalConsole.info(...args);
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'info', message).catch(err => 
        originalConsole.error('Failed to store console.info:', err)
      );
    }
  };

  console.debug = (...args) => {
    originalConsole.debug(...args);
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
